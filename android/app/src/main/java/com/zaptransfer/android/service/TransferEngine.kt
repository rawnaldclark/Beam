package com.zaptransfer.android.service

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.util.Log
import com.zaptransfer.android.crypto.HashAccumulator
import com.zaptransfer.android.crypto.KeyManager
import com.zaptransfer.android.crypto.SessionCipher
import com.zaptransfer.android.data.db.dao.ChunkProgressDao
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.data.db.entity.ChunkProgressEntity
import com.zaptransfer.android.data.db.entity.TransferHistoryEntity
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "TransferEngine"

// ── Wire-format constants ──────────────────────────────────────────────────────

/** JSON type tag sent by the initiating device to propose a file transfer. */
private const val MSG_TRANSFER_REQUEST = "transfer_request"

/** JSON type tag sent by the receiver to accept an incoming transfer. */
private const val MSG_TRANSFER_ACCEPT = "transfer_accept"

/** JSON type tag sent by the receiver to decline an incoming transfer. */
private const val MSG_TRANSFER_DECLINE = "transfer_decline"

/** JSON type tag for a single encrypted text (clipboard) payload. */
private const val MSG_CLIPBOARD = "clipboard"

/** JSON type tag acknowledging receipt of one chunk (includes RTT measurement support). */
private const val MSG_CHUNK_ACK = "chunk_ack"

/** Subdirectory inside the app's cache directory used for in-progress receive buffers. */
private const val TEMP_DIR = "transfer_tmp"

/**
 * How many chunks must be ACK'd between mandatory checkpoint writes.
 * Lower values increase durability at the cost of more Room writes.
 */
private const val CHECKPOINT_CHUNK_INTERVAL = 64

/**
 * Maximum time in milliseconds between checkpoint writes, regardless of chunk count.
 * Ensures progress is saved even for very large chunk sizes.
 */
private const val CHECKPOINT_TIME_INTERVAL_MS = 10_000L

/**
 * Progress snapshot for a single transfer, published to the UI via [StateFlow].
 *
 * @param transferId        UUID v4 of the transfer session.
 * @param direction         "send" or "receive".
 * @param fileName          Original file name from the metadata envelope.
 * @param totalBytes        Total file size in bytes (from metadata).
 * @param transferredBytes  Number of bytes confirmed sent or written to temp file.
 * @param speedBytesPerSec  Instantaneous transfer speed; 0 until first measurement.
 * @param state             Current [TransferState] name (e.g., "TRANSFERRING").
 */
data class TransferProgress(
    val transferId: String,
    val direction: String,
    val fileName: String,
    val totalBytes: Long,
    val transferredBytes: Long,
    val speedBytesPerSec: Long,
    val state: String,
)

/**
 * Internal session context for a single in-flight transfer.
 *
 * Held in [TransferEngine.activeSessions] keyed by [transferId]. Destroyed when
 * the transfer reaches a terminal state.
 */
private data class TransferSession(
    val transferId: String,
    val direction: String,     // "send" or "receive"
    val targetDeviceId: String,
    val fileName: String,
    val totalBytes: Long,
    val chunkKey: ByteArray,
    val stateMachine: TransferStateMachine = TransferStateMachine(),
    val flowController: FlowController = FlowController(isDirectPath = false),
    val chunkSizer: ChunkSizer = ChunkSizer(),
    val hashAccumulator: HashAccumulator = HashAccumulator(),
    var transferredBytes: Long = 0L,
    var lastSpeedSampleTime: Long = System.currentTimeMillis(),
    var lastSpeedSampleBytes: Long = 0L,
    var speedBytesPerSec: Long = 0L,
    var expectedSha256: String? = null,  // set by receiver from metadata envelope
    var tempFile: File? = null,          // receive buffer; null for send sessions
    var tempOutputStream: OutputStream? = null,
    var sendJob: Job? = null,            // coroutine driving the chunk send loop
    var nextChunkIndex: Long = 0L,
    var chunkSentAt: MutableMap<Long, Long> = ConcurrentHashMap(), // index → nanoTime
    // Chunk progress persistence tracking
    var chunksAckedSinceCheckpoint: Int = 0,
    var lastCheckpointTime: Long = System.currentTimeMillis(),
)

/**
 * Central transfer orchestrator for the Beam application.
 *
 * ## Responsibilities
 *  1. **Send path**: open file URI, compute SHA-256, establish session crypto,
 *     send the metadata envelope, then stream encrypted chunks through the
 *     relay with AIMD flow control and adaptive chunk sizing.
 *  2. **Receive path**: handle the incoming metadata envelope, auto-accept paired
 *     devices, decrypt and buffer chunks, verify the final hash, and persist to
 *     a permanent file.
 *  3. **Clipboard send**: single encrypted JSON message (no chunking).
 *  4. **Progress reporting**: expose a [StateFlow] of [TransferProgress] snapshots
 *     keyed by transfer ID so the UI and foreground service can subscribe.
 *
 * ## Architecture notes
 * - [TransferStateMachine] enforces valid state transitions per session.
 * - [FlowController] applies AIMD congestion control to the chunk send loop.
 * - [ChunkSizer] adapts chunk size based on ACK RTT measurements.
 * - [HashAccumulator] handles out-of-order chunk arrival during hash computation.
 * - All crypto (encryption, decryption, key derivation) delegates to [SessionCipher].
 *
 * ## Session key derivation
 * For this relay-only implementation the session key is derived from a single
 * X25519 ECDH output (simplified Triple-DH). Full Triple-DH (with ephemeral key
 * pairs exchanged during the handshake) will be added when WebRTC is introduced
 * in Phase J. The KDF chain remains identical; only the DH inputs change.
 *
 * ## Thread safety
 * All public methods launch coroutines on [scope] (IO dispatcher). The [activeSessions]
 * map is [ConcurrentHashMap] for safe concurrent reads. State machine mutations and
 * flow-controller calls within a session's send loop are serialized by the coroutine
 * that owns that session.
 *
 * @param context         Application context for file system access.
 * @param keyManager      Provides this device's key pairs for ECDH and signing.
 * @param sessionCipher   Symmetric crypto: key derivation, chunk encrypt/decrypt.
 * @param deviceRepo      Looks up peer public keys for session key derivation.
 * @param transferHistoryDao Persists completed/failed transfers to Room.
 * @param signalingClient Active relay WebSocket for send/receive of all messages.
 */
@Singleton
class TransferEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val keyManager: KeyManager,
    private val sessionCipher: SessionCipher,
    private val deviceRepo: DeviceRepository,
    private val transferHistoryDao: TransferHistoryDao,
    private val chunkProgressDao: ChunkProgressDao,
    private val signalingClient: SignalingClient,
) {

    /** Coroutine scope backed by a SupervisorJob so one failed session doesn't cancel others. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Live transfer sessions keyed by their UUID string transfer ID. */
    private val activeSessions = ConcurrentHashMap<String, TransferSession>()

    /** Content resolver for opening URIs returned by the system file picker. */
    private val contentResolver: ContentResolver = context.contentResolver

    // ── Progress flow ──────────────────────────────────────────────────────────

    private val _progress = MutableStateFlow<Map<String, TransferProgress>>(emptyMap())

    /**
     * Live progress for all active transfers, keyed by transfer ID.
     *
     * Emits a new snapshot on every meaningful state change. Entries are removed
     * when the transfer reaches a terminal state and the history record is written.
     * UI consumers should display this alongside [TransferHistoryDao.getRecent] for
     * a combined active + history view.
     */
    val progress: StateFlow<Map<String, TransferProgress>> = _progress.asStateFlow()

    // ── Relay message listener ─────────────────────────────────────────────────

    init {
        // Register a permanent listener for the lifetime of this Singleton.
        // The listener is removed only if the process dies, which also destroys this object.
        signalingClient.addListener(object : SignalingListener {
            override fun onMessage(message: RelayMessage) {
                when (message) {
                    is RelayMessage.Text -> handleTextMessage(message.json)
                    is RelayMessage.Binary -> handleBinaryChunk(message.data)
                }
            }
        })
    }

    // ── Public API: send ───────────────────────────────────────────────────────

    /**
     * Initiates a file transfer to [targetDeviceId].
     *
     * Steps:
     *  1. Open [fileUri] via the [ContentResolver] and compute its SHA-256.
     *  2. Look up the peer's X25519 public key from the paired-device record.
     *  3. Derive the session key via X25519 ECDH + HKDF.
     *  4. Encrypt the metadata JSON with the metadata sub-key.
     *  5. Send `{type:"transfer_request", ...metadata}` to the relay.
     *  6. Transition the state machine to [TransferState.REQUESTING].
     *  7. (ACK receipt will trigger the chunk send loop via [handleChunkAck].)
     *
     * Errors during any step are caught, logged, and reflected as a [TransferState.FAILED]
     * transition in the session's state machine. The caller does not need to handle
     * exceptions from this method.
     *
     * @param targetDeviceId 22-char relay device ID of the receiving peer.
     * @param fileUri        Content URI from the system file picker.
     * @param fileName       Original file name (used in the metadata envelope).
     * @param mimeType       MIME type string (e.g., "image/png"); may be empty.
     * @param fileSize       Exact byte count of the file.
     */
    fun sendFile(
        targetDeviceId: String,
        fileUri: Uri,
        fileName: String,
        mimeType: String,
        fileSize: Long,
    ) {
        scope.launch {
            val transferId = UUID.randomUUID().toString()
            Log.i(TAG, "sendFile: transferId=$transferId target=$targetDeviceId file=$fileName size=$fileSize")

            try {
                // Step 1: compute SHA-256 of the plaintext file
                val sha256Hex = computeFileSha256(fileUri)

                // Step 2 + 3: look up peer key and derive session/chunk keys
                val peer = deviceRepo.getDevice(targetDeviceId)
                    ?: error("Peer $targetDeviceId not found in paired devices")
                val ourKeys = keyManager.getOrCreateKeys()
                val dhOutput = keyManager.deriveSharedSecret(ourKeys.x25519Sk, peer.x25519PublicKey)
                // Simplified single-DH for relay-only phase; all three dh inputs are the same
                // DH output so the salt is what provides domain separation for now.
                val salt = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                val sessionKey = sessionCipher.deriveSessionKey(dhOutput, dhOutput, dhOutput, salt)
                val chunkKey = sessionCipher.deriveChunkKey(sessionKey)
                val metadataKey = sessionCipher.deriveMetadataKey(sessionKey)

                // Step 4: encrypt metadata
                val metadataJson = JSONObject().apply {
                    put("transferId", transferId)
                    put("fileName", fileName)
                    put("mimeType", mimeType)
                    put("fileSize", fileSize)
                    put("sha256", sha256Hex)
                    put("salt", android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP))
                }.toString()
                val encryptedMetadata = sessionCipher.encryptMetadata(metadataJson, metadataKey)

                // Step 5: create session context
                val session = TransferSession(
                    transferId = transferId,
                    direction = "send",
                    targetDeviceId = targetDeviceId,
                    fileName = fileName,
                    totalBytes = fileSize,
                    chunkKey = chunkKey,
                )
                activeSessions[transferId] = session

                // Step 6: send request message to relay
                val requestMsg = JSONObject().apply {
                    put("type", MSG_TRANSFER_REQUEST)
                    put("transferId", transferId)
                    put("targetDeviceId", targetDeviceId)
                    put("metadataEnvelope",
                        android.util.Base64.encodeToString(encryptedMetadata, android.util.Base64.NO_WRAP))
                }
                signalingClient.send(requestMsg)

                // Step 7: transition state machine
                session.stateMachine.transition(TransferState.REQUESTING)
                publishProgress(session)

                // Persist a "pending" history record so it appears immediately in history
                transferHistoryDao.insert(
                    TransferHistoryEntity(
                        transferId = transferId,
                        deviceId = targetDeviceId,
                        direction = "SENT",
                        fileName = fileName,
                        fileSizeBytes = fileSize,
                        mimeType = mimeType.ifBlank { null },
                        status = "PENDING",
                        sha256Hash = sha256Hex,
                        localUri = fileUri.toString(),
                        startedAt = System.currentTimeMillis(),
                    )
                )

                Log.i(TAG, "Transfer request sent: $transferId")

                // The chunk loop starts when the receiver sends transfer_accept (see handleTextMessage)
                // and we receive a chunk_ack for the implicit "chunk -1" (accept ACK).
                // For simplicity in this relay phase: start streaming immediately after REQUESTING.
                startChunkSendLoop(session, fileUri)

            } catch (e: Exception) {
                Log.e(TAG, "sendFile failed: transferId=$transferId ${e.message}", e)
                activeSessions[transferId]?.let { session ->
                    failSession(session, e.message ?: "Unknown error")
                }
            }
        }
    }

    /**
     * Sends a clipboard text payload to [targetDeviceId].
     *
     * The text is JSON-encoded, encrypted with XChaCha20-Poly1305 using a fresh
     * session key, and relayed as a single `{type:"clipboard"}` message. There is
     * no chunking, no flow control, and no integrity hash — clipboard items are
     * small enough to fit in a single relay frame.
     *
     * @param targetDeviceId 22-char relay device ID of the target.
     * @param text           UTF-8 clipboard text to transmit.
     */
    fun sendClipboard(targetDeviceId: String, text: String) {
        scope.launch {
            try {
                val peer = deviceRepo.getDevice(targetDeviceId)
                    ?: error("Peer $targetDeviceId not found")
                val ourKeys = keyManager.getOrCreateKeys()
                val dhOutput = keyManager.deriveSharedSecret(ourKeys.x25519Sk, peer.x25519PublicKey)
                val salt = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                val sessionKey = sessionCipher.deriveSessionKey(dhOutput, dhOutput, dhOutput, salt)
                val metadataKey = sessionCipher.deriveMetadataKey(sessionKey)

                val payload = JSONObject().apply {
                    put("text", text)
                    put("salt", android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP))
                }.toString()
                val encrypted = sessionCipher.encryptMetadata(payload, metadataKey)

                val msg = JSONObject().apply {
                    put("type", MSG_CLIPBOARD)
                    put("targetDeviceId", targetDeviceId)
                    put("payload",
                        android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP))
                }
                signalingClient.send(msg)
                Log.i(TAG, "Clipboard sent to $targetDeviceId (${text.length} chars)")
            } catch (e: Exception) {
                Log.e(TAG, "sendClipboard failed: ${e.message}", e)
            }
        }
    }

    // ── Public API: incoming message handlers ──────────────────────────────────

    /**
     * Handles an incoming transfer request from a remote peer.
     *
     * Auto-accepts if the sender is a known paired device. Creates the receive
     * session, transitions to [TransferState.AWAITING_ACCEPT], then immediately
     * to [TransferState.TRANSFERRING], and sends an accept ACK to the relay.
     *
     * @param json Parsed JSON of the `transfer_request` relay message.
     */
    fun handleIncomingRequest(json: JSONObject) {
        scope.launch {
            val transferId = json.getString("transferId")
            val senderDeviceId = json.optString("fromDeviceId", "unknown")
            Log.i(TAG, "Incoming transfer request: $transferId from $senderDeviceId")

            try {
                // Verify the sender is a paired device — reject unknown sources
                val peer = deviceRepo.getDevice(senderDeviceId)
                if (peer == null) {
                    Log.w(TAG, "Rejected transfer from unknown device $senderDeviceId")
                    return@launch
                }

                // Derive session keys (matching the sender's derivation)
                val ourKeys = keyManager.getOrCreateKeys()
                val dhOutput = keyManager.deriveSharedSecret(ourKeys.x25519Sk, peer.x25519PublicKey)

                // Decrypt metadata envelope
                val envelopeB64 = json.getString("metadataEnvelope")
                val envelope = android.util.Base64.decode(envelopeB64, android.util.Base64.NO_WRAP)

                // We need the salt from the metadata to reconstruct the session key.
                // For the relay phase: we decrypt the metadata first using a preliminary key
                // derived without a salt to extract the salt, then re-derive properly.
                // In practice the sender embeds the salt in the (encrypted) metadata — the
                // receiver must use a pre-agreed "null-salt" key to unwrap the outer layer.
                // Simplified approach: use zero salt for relay-only phase; Phase J introduces
                // proper ephemeral key exchange that negotiates the salt over the wire.
                val zeroSalt = ByteArray(32)
                val sessionKey = sessionCipher.deriveSessionKey(dhOutput, dhOutput, dhOutput, zeroSalt)
                val metadataKey = sessionCipher.deriveMetadataKey(sessionKey)
                val metadataJson = sessionCipher.decryptMetadata(envelope, metadataKey)
                val metadata = JSONObject(metadataJson)

                val fileName = metadata.getString("fileName")
                val mimeType = metadata.optString("mimeType")
                val fileSize = metadata.getLong("fileSize")
                val sha256Hex = metadata.getString("sha256")
                val chunkKey = sessionCipher.deriveChunkKey(sessionKey)

                // Create the temp file for buffering received chunks
                val tempDir = File(context.cacheDir, TEMP_DIR).also { it.mkdirs() }
                val tempFile = File(tempDir, "recv_$transferId.tmp")

                val session = TransferSession(
                    transferId = transferId,
                    direction = "receive",
                    targetDeviceId = senderDeviceId,
                    fileName = fileName,
                    totalBytes = fileSize,
                    chunkKey = chunkKey,
                    expectedSha256 = sha256Hex,
                    tempFile = tempFile,
                    tempOutputStream = tempFile.outputStream(),
                )
                activeSessions[transferId] = session

                // Auto-accept: transition directly to TRANSFERRING
                session.stateMachine.transition(TransferState.AWAITING_ACCEPT)
                session.stateMachine.transition(TransferState.TRANSFERRING)
                publishProgress(session)

                // Persist initial history record
                transferHistoryDao.insert(
                    TransferHistoryEntity(
                        transferId = transferId,
                        deviceId = senderDeviceId,
                        direction = "RECEIVED",
                        fileName = fileName,
                        fileSizeBytes = fileSize,
                        mimeType = mimeType.ifBlank { null },
                        status = "PENDING",
                        sha256Hash = null,
                        localUri = null,
                        startedAt = System.currentTimeMillis(),
                    )
                )

                // Send accept to the sender so it starts streaming chunks
                val acceptMsg = JSONObject().apply {
                    put("type", MSG_TRANSFER_ACCEPT)
                    put("transferId", transferId)
                    put("targetDeviceId", senderDeviceId)
                }
                signalingClient.send(acceptMsg)

                Log.i(TAG, "Transfer $transferId accepted; awaiting chunks from $senderDeviceId")
            } catch (e: Exception) {
                Log.e(TAG, "handleIncomingRequest failed: $transferId ${e.message}", e)
            }
        }
    }

    /**
     * Handles an incoming encrypted binary chunk.
     *
     * Wire format of the binary frame (big-endian):
     * ```
     * [4 bytes: transferId length]
     * [N bytes: transferId UTF-8]
     * [8 bytes: chunk index (int64)]
     * [remaining bytes: XChaCha20-Poly1305 ciphertext]
     * ```
     *
     * Steps:
     *  1. Parse the header to extract transfer ID and chunk index.
     *  2. Look up the active receive session.
     *  3. Decrypt and unpad the chunk payload.
     *  4. Feed decrypted bytes to [HashAccumulator].
     *  5. Append bytes to the temp file output stream.
     *  6. Send a [MSG_CHUNK_ACK] JSON message back to the sender.
     *  7. Update progress.
     *  8. If this was the last chunk: transition to [TransferState.VERIFYING] and finalize.
     *
     * @param data Raw binary WebSocket frame bytes.
     */
    fun handleChunk(data: ByteArray) {
        scope.launch {
            try {
                // Parse header
                if (data.size < 12) {
                    Log.w(TAG, "Chunk frame too short: ${data.size} bytes")
                    return@launch
                }
                val idLen = ((data[0].toInt() and 0xFF) shl 24) or
                    ((data[1].toInt() and 0xFF) shl 16) or
                    ((data[2].toInt() and 0xFF) shl 8) or
                    (data[3].toInt() and 0xFF)

                if (idLen <= 0 || idLen > 64 || data.size < 4 + idLen + 8) {
                    Log.w(TAG, "Invalid chunk header: idLen=$idLen dataSize=${data.size}")
                    return@launch
                }

                val transferId = String(data, 4, idLen, Charsets.UTF_8)
                var idx = 4 + idLen
                var chunkIndex = 0L
                for (i in 0 until 8) {
                    chunkIndex = (chunkIndex shl 8) or (data[idx++].toLong() and 0xFF)
                }
                val ciphertext = data.copyOfRange(idx, data.size)

                val session = activeSessions[transferId] ?: run {
                    Log.w(TAG, "No active receive session for transferId=$transferId")
                    return@launch
                }

                // Build AAD matching the sender: transferId bytes + chunkIndex bytes
                val aad = buildChunkAad(transferId, chunkIndex)

                // Decrypt and unpad
                val plaintext = sessionCipher.decryptChunk(
                    ciphertext = ciphertext,
                    chunkKey = session.chunkKey,
                    chunkIndex = chunkIndex,
                    aad = aad,
                )

                // Feed to hash accumulator (handles out-of-order arrival)
                session.hashAccumulator.feedChunk(chunkIndex, plaintext)

                // Append to temp file (sequential writes — chunks arrive in order for relay)
                session.tempOutputStream?.write(plaintext)

                // Update progress counters
                session.transferredBytes += plaintext.size
                updateSpeed(session)
                publishProgress(session)

                // Send ACK to unblock the sender's flow controller
                val ackMsg = JSONObject().apply {
                    put("type", MSG_CHUNK_ACK)
                    put("transferId", transferId)
                    put("chunkIndex", chunkIndex)
                    put("targetDeviceId", session.targetDeviceId)
                }
                signalingClient.send(ackMsg)

                // ── Checkpoint persistence ─────────────────────────────────────
                // Write a resume checkpoint every CHECKPOINT_CHUNK_INTERVAL chunks
                // or every CHECKPOINT_TIME_INTERVAL_MS, whichever comes first.
                // totalChunks is approximated from totalBytes / current chunk size.
                session.chunksAckedSinceCheckpoint++
                val now = System.currentTimeMillis()
                val timeSinceLastCheckpoint = now - session.lastCheckpointTime
                if (session.chunksAckedSinceCheckpoint >= CHECKPOINT_CHUNK_INTERVAL ||
                    timeSinceLastCheckpoint >= CHECKPOINT_TIME_INTERVAL_MS
                ) {
                    val approxTotalChunks = if (session.chunkSizer.currentChunkSize > 0) {
                        ((session.totalBytes + session.chunkSizer.currentChunkSize - 1) /
                            session.chunkSizer.currentChunkSize).toInt()
                    } else 1
                    saveChunkProgress(session, chunkIndex, approxTotalChunks)
                }

                // Check if transfer is complete
                if (session.transferredBytes >= session.totalBytes) {
                    finalizeReceive(session)
                }
            } catch (e: Exception) {
                Log.e(TAG, "handleChunk failed: ${e.message}", e)
            }
        }
    }

    /**
     * Handles a chunk ACK from the receiving peer.
     *
     * Updates the [FlowController] and [ChunkSizer] for the corresponding send session,
     * allowing the send loop to proceed past its [FlowController.acquire] suspension point.
     *
     * @param json Parsed JSON of the `chunk_ack` relay message.
     */
    fun handleChunkAck(json: JSONObject) {
        val transferId = json.optString("transferId") ?: return
        val chunkIndex = json.optLong("chunkIndex", -1L)
        if (chunkIndex < 0) return

        val session = activeSessions[transferId] ?: return
        if (session.direction != "send") return

        // Measure RTT for the chunk sizer
        val sentAt = session.chunkSentAt.remove(chunkIndex)
        if (sentAt != null) {
            val rttMs = (System.nanoTime() - sentAt) / 1_000_000L
            session.chunkSizer.onAckReceived(rttMs)
        }

        // Unblock the flow controller
        session.flowController.onAck()
        Log.v(TAG, "ACK received: transferId=$transferId chunkIndex=$chunkIndex")
    }

    // ── Chunk send loop ────────────────────────────────────────────────────────

    /**
     * Drives the chunk send loop for a file transfer.
     *
     * Opens the file URI and reads chunks sequentially, throttled by [FlowController.acquire].
     * Each chunk is padded and encrypted, then framed into the binary wire format and
     * sent via [SignalingClient.sendBinary].
     *
     * The loop runs until all bytes are sent or the session's [Job] is cancelled.
     *
     * @param session Active send [TransferSession].
     * @param fileUri The content URI to read from.
     */
    private fun startChunkSendLoop(session: TransferSession, fileUri: Uri) {
        session.sendJob = scope.launch {
            try {
                session.stateMachine.transition(TransferState.TRANSFERRING)
                publishProgress(session)

                withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(fileUri)?.use { inputStream ->
                        var chunkIndex = 0L
                        val buffer = ByteArray(session.chunkSizer.currentChunkSize)

                        var bytesRead: Int
                        while (inputStream.read(buffer, 0, session.chunkSizer.currentChunkSize)
                                .also { bytesRead = it } != -1
                        ) {
                            // Wait for a flow-control window slot
                            session.flowController.acquire()

                            val chunk = buffer.copyOf(bytesRead)
                            val aad = buildChunkAad(session.transferId, chunkIndex)
                            val ciphertext = sessionCipher.encryptChunk(
                                plaintext = chunk,
                                chunkKey = session.chunkKey,
                                chunkIndex = chunkIndex,
                                aad = aad,
                            )

                            // Build binary frame
                            val frame = buildChunkFrame(session.transferId, chunkIndex, ciphertext)

                            // Record send timestamp for RTT measurement
                            session.chunkSentAt[chunkIndex] = System.nanoTime()

                            signalingClient.sendBinary(frame)

                            session.transferredBytes += bytesRead
                            session.nextChunkIndex = chunkIndex + 1
                            updateSpeed(session)
                            publishProgress(session)

                            chunkIndex++
                        }
                    } ?: error("Could not open input stream for $fileUri")
                }

                // All chunks sent — wait for final ACK before declaring verifying
                // (For relay-only: transition immediately; Phase J will await the final ACK)
                session.stateMachine.transition(TransferState.VERIFYING)
                session.stateMachine.transition(TransferState.COMPLETE)
                publishProgress(session)

                // Update history record to COMPLETED
                transferHistoryDao.updateCompletion(
                    transferId = session.transferId,
                    status = "COMPLETED",
                    sha256Hash = session.expectedSha256,
                    localUri = fileUri.toString(),
                    completedAt = System.currentTimeMillis(),
                )

                Log.i(TAG, "File send complete: ${session.transferId}")
                cleanupSession(session)

            } catch (e: Exception) {
                Log.e(TAG, "Chunk send loop failed: ${session.transferId} ${e.message}", e)
                failSession(session, e.message ?: "Send loop error")
            }
        }
    }

    // ── Receive finalization ───────────────────────────────────────────────────

    /**
     * Finalizes a completed receive session.
     *
     * Steps:
     *  1. Flush and close the temp file output stream.
     *  2. Finalize [HashAccumulator] and compare with [TransferSession.expectedSha256].
     *  3. On match: move temp file to the Downloads folder and update history.
     *  4. On mismatch: delete temp file, mark session FAILED.
     *
     * @param session The completed receive [TransferSession].
     */
    private suspend fun finalizeReceive(session: TransferSession) {
        try {
            session.stateMachine.transition(TransferState.VERIFYING)
            publishProgress(session)

            // Close the write stream before reading the final hash
            session.tempOutputStream?.flush()
            session.tempOutputStream?.close()
            session.tempOutputStream = null

            // Finalize hash and compare
            val hashBytes = session.hashAccumulator.finalize()
            val actualHex = hashBytes.joinToString("") { "%02x".format(it) }
            val expectedHex = session.expectedSha256

            if (expectedHex != null && actualHex != expectedHex) {
                Log.e(
                    TAG,
                    "Hash mismatch for ${session.transferId}: " +
                        "expected=$expectedHex actual=$actualHex"
                )
                session.tempFile?.delete()
                failSession(session, "Integrity check failed: SHA-256 mismatch")
                return
            }

            // Move temp file to a permanent location in the app's files directory
            val destDir = File(context.getExternalFilesDir(null), "Beam").also { it.mkdirs() }
            val destFile = uniqueFile(destDir, session.fileName)
            session.tempFile?.renameTo(destFile)

            session.stateMachine.transition(TransferState.COMPLETE)
            publishProgress(session)

            transferHistoryDao.updateCompletion(
                transferId = session.transferId,
                status = "COMPLETED",
                sha256Hash = actualHex,
                localUri = Uri.fromFile(destFile).toString(),
                completedAt = System.currentTimeMillis(),
            )

            Log.i(TAG, "Receive complete and verified: ${session.transferId} → ${destFile.path}")
            clearCheckpoint(session.transferId)
            cleanupSession(session)

        } catch (e: Exception) {
            Log.e(TAG, "finalizeReceive failed: ${session.transferId} ${e.message}", e)
            failSession(session, e.message ?: "Finalization error")
        }
    }

    // ── Text message dispatch ──────────────────────────────────────────────────

    /**
     * Routes incoming JSON relay messages to the appropriate handler.
     *
     * Called on OkHttp's reader thread — dispatches all heavy work into [scope].
     *
     * @param json Parsed relay text frame.
     */
    private fun handleTextMessage(json: JSONObject) {
        when (val type = json.optString("type")) {
            MSG_TRANSFER_REQUEST -> handleIncomingRequest(json)
            MSG_TRANSFER_ACCEPT -> {
                // The receiver accepted; the send loop is already running — no extra action needed
                val transferId = json.optString("transferId")
                Log.i(TAG, "Transfer accepted by receiver: $transferId")
            }
            MSG_TRANSFER_DECLINE -> {
                val transferId = json.optString("transferId")
                activeSessions[transferId]?.let { session ->
                    scope.launch {
                        try {
                            session.stateMachine.transition(TransferState.DECLINED)
                        } catch (e: IllegalStateException) {
                            session.stateMachine.forceReset()
                        }
                        publishProgress(session)
                        transferHistoryDao.updateCompletion(
                            transferId = transferId,
                            status = "CANCELLED",
                            sha256Hash = null,
                            localUri = null,
                            completedAt = System.currentTimeMillis(),
                        )
                        cleanupSession(session)
                    }
                }
            }
            MSG_CHUNK_ACK -> handleChunkAck(json)
            else -> Log.v(TAG, "TransferEngine ignoring message type: $type")
        }
    }

    /**
     * Routes incoming binary frames.
     *
     * Binary frames from the relay are always encrypted chunk payloads addressed
     * to an active receive session.
     *
     * @param data Raw binary WebSocket bytes.
     */
    private fun handleBinaryChunk(data: ByteArray) {
        handleChunk(data)
    }

    // ── Session lifecycle helpers ──────────────────────────────────────────────

    /**
     * Marks the session as [TransferState.FAILED], updates history, and cleans up.
     *
     * Safe to call from any coroutine context. Uses [TransferStateMachine.forceReset]
     * if a normal transition to FAILED is illegal from the current state.
     *
     * @param session The session to fail.
     * @param reason  Developer-facing error description (not shown to users).
     */
    private suspend fun failSession(session: TransferSession, reason: String) {
        try {
            session.stateMachine.transition(TransferState.FAILED)
        } catch (e: IllegalStateException) {
            session.stateMachine.forceReset()
        }
        publishProgress(session)

        session.sendJob?.cancel()
        session.tempOutputStream?.close()
        session.tempFile?.delete()

        transferHistoryDao.updateCompletion(
            transferId = session.transferId,
            status = "FAILED",
            sha256Hash = null,
            localUri = null,
            completedAt = System.currentTimeMillis(),
        )
        Log.e(TAG, "Transfer ${session.transferId} FAILED: $reason")
        cleanupSession(session)
    }

    /**
     * Removes the session from [activeSessions] and the progress map after a short
     * delay so the UI can render the terminal state before the entry disappears.
     *
     * @param session The session to remove.
     */
    private fun cleanupSession(session: TransferSession) {
        scope.launch {
            delay(2_000)
            activeSessions.remove(session.transferId)
            _progress.update { it - session.transferId }
        }
    }

    // ── Progress helpers ───────────────────────────────────────────────────────

    /**
     * Publishes a fresh [TransferProgress] snapshot for [session] to [_progress].
     */
    private fun publishProgress(session: TransferSession) {
        val snapshot = TransferProgress(
            transferId = session.transferId,
            direction = session.direction,
            fileName = session.fileName,
            totalBytes = session.totalBytes,
            transferredBytes = session.transferredBytes,
            speedBytesPerSec = session.speedBytesPerSec,
            state = session.stateMachine.current.name,
        )
        _progress.update { current -> current + (session.transferId to snapshot) }
    }

    /**
     * Updates [TransferSession.speedBytesPerSec] using a 1-second exponential moving average.
     *
     * Samples are taken every time this method is called; if less than 500 ms has passed
     * since the last sample the speed is not recalculated to avoid noisy micro-measurements.
     *
     * @param session The session whose speed to update.
     */
    private fun updateSpeed(session: TransferSession) {
        val now = System.currentTimeMillis()
        val elapsed = now - session.lastSpeedSampleTime
        if (elapsed < 500L) return  // wait for a meaningful sample window

        val bytesDelta = session.transferredBytes - session.lastSpeedSampleBytes
        if (bytesDelta <= 0L || elapsed <= 0L) return

        val instantSpeed = bytesDelta * 1_000L / elapsed  // bytes per second
        // Exponential moving average (α = 0.3) to smooth out bursts
        session.speedBytesPerSec = ((session.speedBytesPerSec * 7L + instantSpeed * 3L) / 10L)
        session.lastSpeedSampleTime = now
        session.lastSpeedSampleBytes = session.transferredBytes
    }

    // ── File utility helpers ───────────────────────────────────────────────────

    /**
     * Computes the SHA-256 hex digest of the file at [fileUri] by streaming it
     * through [MessageDigest] in 64 KB chunks.
     *
     * This does NOT use [HashAccumulator] because the file is read sequentially
     * from a content URI — there is no out-of-order arrival concern.
     *
     * @param fileUri The content URI to hash.
     * @return Lowercase hex SHA-256 string (64 characters).
     * @throws IllegalStateException if the URI cannot be opened.
     */
    private suspend fun computeFileSha256(fileUri: Uri): String = withContext(Dispatchers.IO) {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(65_536)  // 64 KB read buffer
        contentResolver.openInputStream(fileUri)?.use { stream ->
            var read: Int
            while (stream.read(buffer).also { read = it } != -1) {
                md.update(buffer, 0, read)
            }
        } ?: error("Cannot open input stream for SHA-256 computation: $fileUri")
        md.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Returns a [File] in [dir] with a unique name derived from [baseName].
     *
     * If [baseName] already exists, appends "(N)" before the extension until
     * a non-colliding name is found.
     *
     * @param dir      Target directory (assumed to exist).
     * @param baseName Preferred file name.
     * @return A [File] object whose path does not currently exist on disk.
     */
    private fun uniqueFile(dir: File, baseName: String): File {
        var candidate = File(dir, baseName)
        if (!candidate.exists()) return candidate

        val dotIndex = baseName.lastIndexOf('.')
        val nameWithoutExt = if (dotIndex >= 0) baseName.substring(0, dotIndex) else baseName
        val ext = if (dotIndex >= 0) baseName.substring(dotIndex) else ""

        var counter = 1
        while (candidate.exists()) {
            candidate = File(dir, "$nameWithoutExt ($counter)$ext")
            counter++
        }
        return candidate
    }

    // ── Binary frame builders ──────────────────────────────────────────────────

    /**
     * Constructs the chunk AAD (Additional Authenticated Data) for encryption.
     *
     * AAD format: `transferId_bytes || chunkIndex_BE64`.
     * Including both fields in the AAD prevents an attacker from replaying a valid
     * chunk from one transfer into another, or reordering chunks within a transfer.
     *
     * @param transferId UUID v4 string of the transfer.
     * @param chunkIndex Zero-based chunk index.
     * @return AAD byte array.
     */
    private fun buildChunkAad(transferId: String, chunkIndex: Long): ByteArray {
        val idBytes = transferId.toByteArray(Charsets.UTF_8)
        val indexBytes = ByteArray(8).also { buf ->
            var idx = chunkIndex
            for (i in 7 downTo 0) {
                buf[i] = (idx and 0xFF).toByte()
                idx = idx ushr 8
            }
        }
        return idBytes + indexBytes
    }

    /**
     * Builds the binary wire frame for a chunk.
     *
     * Frame layout:
     * ```
     * [4 bytes: transferId UTF-8 length, big-endian uint32]
     * [N bytes: transferId UTF-8]
     * [8 bytes: chunkIndex, big-endian int64]
     * [M bytes: XChaCha20-Poly1305 ciphertext]
     * ```
     *
     * @param transferId UUID string.
     * @param chunkIndex Zero-based chunk index.
     * @param ciphertext Encrypted + tagged chunk bytes.
     * @return The complete binary frame ready to pass to [SignalingClient.sendBinary].
     */
    private fun buildChunkFrame(
        transferId: String,
        chunkIndex: Long,
        ciphertext: ByteArray,
    ): ByteArray {
        val idBytes = transferId.toByteArray(Charsets.UTF_8)
        val idLen = idBytes.size

        val frame = ByteArray(4 + idLen + 8 + ciphertext.size)
        var offset = 0

        // 4-byte transferId length
        frame[offset++] = (idLen ushr 24 and 0xFF).toByte()
        frame[offset++] = (idLen ushr 16 and 0xFF).toByte()
        frame[offset++] = (idLen ushr 8 and 0xFF).toByte()
        frame[offset++] = (idLen and 0xFF).toByte()

        // transferId bytes
        idBytes.copyInto(frame, destinationOffset = offset)
        offset += idLen

        // 8-byte chunk index (big-endian)
        var idx = chunkIndex
        for (i in offset + 7 downTo offset) {
            frame[i] = (idx and 0xFF).toByte()
            idx = idx ushr 8
        }
        offset += 8

        // Ciphertext
        ciphertext.copyInto(frame, destinationOffset = offset)

        return frame
    }

    // ── Public API: cancel + checkpoint ───────────────────────────────────────

    /**
     * Cancels an in-progress transfer by its transfer ID.
     *
     * Cancels the send coroutine (if any), transitions the state machine to FAILED,
     * updates the history record to CANCELLED, cleans up the temp file, and removes
     * the chunk-progress checkpoint from Room.
     *
     * Safe to call from any thread — all mutations are dispatched onto [scope].
     *
     * @param transferId UUID of the transfer to cancel.
     */
    fun cancelTransfer(transferId: String) {
        scope.launch {
            val session = activeSessions[transferId] ?: run {
                Log.w(TAG, "cancelTransfer: no session found for $transferId")
                return@launch
            }
            Log.i(TAG, "Cancelling transfer $transferId")
            session.sendJob?.cancel()
            session.tempOutputStream?.runCatching { close() }
            session.tempFile?.delete()

            try {
                session.stateMachine.transition(TransferState.FAILED)
            } catch (e: IllegalStateException) {
                session.stateMachine.forceReset()
            }
            publishProgress(session)

            transferHistoryDao.updateCompletion(
                transferId = transferId,
                status = "CANCELLED",
                sha256Hash = null,
                localUri = null,
                completedAt = System.currentTimeMillis(),
            )

            // Remove the resume checkpoint from Room
            chunkProgressDao.delete(transferId)
            cleanupSession(session)
        }
    }

    /**
     * Persists a chunk-progress checkpoint to Room for the given receive session.
     *
     * Called every [CHECKPOINT_CHUNK_INTERVAL] chunks OR every [CHECKPOINT_TIME_INTERVAL_MS],
     * whichever threshold is reached first. The caller (handleChunk) is responsible for
     * checking the thresholds — this function always writes unconditionally.
     *
     * @param session       The active receive session to checkpoint.
     * @param chunkIndex    The index of the most recently ACK'd chunk.
     * @param totalChunks   Total expected chunk count declared by the sender in metadata.
     */
    private suspend fun saveChunkProgress(
        session: TransferSession,
        chunkIndex: Long,
        totalChunks: Int,
    ) {
        val entity = ChunkProgressEntity(
            transferId = session.transferId,
            totalChunks = totalChunks,
            lastAckedChunk = chunkIndex.toInt(),
            tempFilePath = session.tempFile?.absolutePath ?: "",
            sha256State = null,  // incremental state serialisation not yet supported
            updatedAt = System.currentTimeMillis(),
        )
        // Use insert with REPLACE conflict strategy for the first checkpoint;
        // subsequent writes use updateProgress for lower overhead.
        val existing = chunkProgressDao.getByTransferId(session.transferId)
        if (existing == null) {
            chunkProgressDao.insert(entity)
        } else {
            chunkProgressDao.updateProgress(
                transferId = session.transferId,
                lastAckedChunk = chunkIndex.toInt(),
                sha256State = null,
                updatedAt = entity.updatedAt,
            )
        }
        session.chunksAckedSinceCheckpoint = 0
        session.lastCheckpointTime = entity.updatedAt
        Log.v(TAG, "Checkpoint saved: transferId=${session.transferId} lastAckedChunk=$chunkIndex")
    }

    /**
     * Deletes the chunk-progress checkpoint for [transferId] from Room.
     *
     * Must be called when a transfer reaches a terminal state (COMPLETE, FAILED, CANCELLED)
     * so that the startup recovery scan does not attempt to resume it.
     *
     * @param transferId UUID of the completed or failed transfer.
     */
    suspend fun clearCheckpoint(transferId: String) {
        chunkProgressDao.delete(transferId)
        Log.d(TAG, "Checkpoint cleared: transferId=$transferId")
    }

    /**
     * Cancels all active transfer sessions and releases coroutine scope resources.
     *
     * Should be called when the owning [TransferForegroundService] is destroyed.
     * Any in-flight coroutines are cancelled; history records for those sessions
     * are NOT updated to FAILED here — the service's [onDestroy] is responsible
     * for that cleanup if needed.
     */
    fun shutdown() {
        activeSessions.values.forEach { session ->
            session.sendJob?.cancel()
            session.tempOutputStream?.runCatching { close() }
        }
        activeSessions.clear()
        scope.cancel()
        Log.i(TAG, "TransferEngine shut down")
    }
}
