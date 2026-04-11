package com.zaptransfer.android.ui.devicehub

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.util.Log
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.crypto.BeamCryptoContext
import com.zaptransfer.android.crypto.BeamSessionRegistry
import com.zaptransfer.android.data.db.dao.ClipboardDao
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.data.db.entity.ClipboardEntryEntity
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.db.entity.TransferHistoryEntity
import com.zaptransfer.android.data.preferences.UserPreferences
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import org.json.JSONObject
import javax.inject.Inject

private const val TAG = "DeviceHubVM"

/**
 * ViewModel for the Device Hub screen.
 *
 * Combines two reactive sources:
 *  1. Persistent paired device list from [DeviceRepository.observePairedDevices].
 *  2. Ephemeral online presence set from [DeviceRepository.onlineDevices].
 *
 * The [uiState] flow emits a new [DeviceHubUiState] whenever either source
 * changes — the UI never polls. [recentTransfers] is driven directly by the
 * Room DAO flow and updates as transfers complete in the background service.
 *
 * On init, if paired devices exist, connects to the relay and registers
 * rendezvous IDs so clipboard-transfer messages can be received.
 *
 * The 5-second [SharingStarted.WhileSubscribed] timeout keeps the upstream flows
 * alive during brief recompositions (e.g., navigation transitions), preventing
 * unnecessary re-queries on immediate return.
 *
 * @param deviceRepo         Mediates access to [PairedDeviceEntity] records and online presence.
 * @param transferHistoryDao Provides the recent-transfers flow for the history section.
 * @param signalingClient    Singleton relay client for sending/receiving clipboard messages.
 * @param appContext         Application context for clipboard and toast access.
 */
@HiltViewModel
class DeviceHubViewModel @Inject constructor(
    private val deviceRepo: DeviceRepository,
    private val transferHistoryDao: TransferHistoryDao,
    private val clipboardDao: ClipboardDao,
    private val signalingClient: SignalingClient,
    private val userPreferences: UserPreferences,
    private val beamCrypto: BeamCryptoContext,
    @ApplicationContext private val appContext: Context,
) : ViewModel() {

    /**
     * Pending sender-side waiters for transfer-accept messages, keyed by
     * the lowercase hex transferId. Populated by sendClipboardEncrypted()
     * and completed by the relay listener when the peer accepts or rejects.
     */
    private val pendingAccepts =
        java.util.concurrent.ConcurrentHashMap<String, CompletableDeferred<BeamSessionRegistry.Session>>()

    /** Shared flow for one-shot UI events (e.g., toast messages). */
    private val _toastEvents = MutableSharedFlow<String>(extraBufferCapacity = 5)
    val toastEvents: SharedFlow<String> = _toastEvents.asSharedFlow()

    /**
     * Pending file that was received but not yet saved (when auto-save is OFF).
     * The UI can observe this to show a "Save" prompt for the received file.
     */
    private val _pendingFileSave = MutableStateFlow<PendingFileSave?>(null)
    val pendingFileSave: StateFlow<PendingFileSave?> = _pendingFileSave.asStateFlow()

    /**
     * Listener that dispatches incoming relay messages. The legacy plaintext
     * clipboard-transfer / file-offer / file-complete handlers were removed
     * in Task 9 — every transfer now goes through the Beam E2E path.
     */
    private val relayListener = object : SignalingListener {
        override fun onMessage(message: RelayMessage) {
            when (message) {
                is RelayMessage.Binary -> {
                    val bytes = message.data
                    if (!isBeamFrame(bytes)) {
                        Log.w(TAG, "dropped non-Beam binary frame (${bytes.size} bytes)")
                        _toastEvents.tryEmit("Received transfer could not be decrypted.")
                        return
                    }
                    viewModelScope.launch { handleIncomingBeamFrame(bytes) }
                }
                is RelayMessage.Text -> {
                    val json = message.json
                    when (json.optString("type")) {
                        "transfer-init"   -> viewModelScope.launch { handleTransferInit(json) }
                        "transfer-accept" -> viewModelScope.launch { handleTransferAccept(json) }
                        "transfer-reject" -> {
                            Log.w(TAG, "transfer-reject: ${json.optString("errorCode")}")
                            viewModelScope.launch { handleTransferReject(json) }
                        }
                        "file-complete" -> {
                            // Advisory only — completion is driven by chunksReceived
                            // == totalChunks inside handleIncomingBeamFileFrame.
                        }
                        "peer-online" -> {
                            val peerId = json.optString("deviceId", "")
                            if (peerId.isNotEmpty()) {
                                deviceRepo.handlePresence(peerId, true)
                            }
                        }
                        "peer-offline" -> {
                            val peerId = json.optString("deviceId", "")
                            if (peerId.isNotEmpty()) {
                                deviceRepo.handlePresence(peerId, false)
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Persist, copy, and notify about an incoming clipboard payload that
     * arrived via the Beam E2E encrypted path. Single authoritative
     * delivery UX shared by every receive code path.
     */
    private suspend fun deliverIncomingClipboard(content: String, fromDeviceId: String) {
        Log.d(TAG, "Clipboard delivered from $fromDeviceId, length=${content.length}")
        val prefs = userPreferences.preferencesFlow.first()
        val autoCopy = prefs.autoCopyClipboard

        if (autoCopy) {
            val clipboardManager = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboardManager.setPrimaryClip(ClipData.newPlainText("Beam Clipboard", content))
        }

        try {
            clipboardDao.insert(
                ClipboardEntryEntity(
                    deviceId = fromDeviceId,
                    content = content,
                    isUrl = android.util.Patterns.WEB_URL.matcher(content).find(),
                    receivedAt = System.currentTimeMillis(),
                )
            )
            while (clipboardDao.getCount() > 20) {
                clipboardDao.deleteOldest()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to persist clipboard entry: ${e.message}")
        }

        val preview = if (content.length > 60) content.take(57) + "..." else content
        if (autoCopy) {
            _toastEvents.tryEmit("Clipboard received and copied: $preview")
        } else {
            _toastEvents.tryEmit("Clipboard received \u2014 tap to copy: $preview")
        }
    }

    init {
        // Connect to relay if paired devices exist, so we can receive clipboard messages.
        viewModelScope.launch {
            val devices = deviceRepo.observePairedDevices().first()
            if (devices.isNotEmpty()) {
                try {
                    signalingClient.addListener(relayListener)
                    // Always call connect() — it is re-entrant and will cycle
                    // any stale WebSocket left over from a cached process.
                    // The previous "skip if already Connected" guard caused
                    // the app to trust a half-dead socket when reopened from
                    // a backgrounded state, requiring a force-stop to recover.
                    signalingClient.connect()
                    // Wait for connection to be established, then register rendezvous.
                    signalingClient.connectionState.first { it is ConnectionState.Connected }
                    val rendezvousIds = devices.map { it.deviceId }
                    signalingClient.registerRendezvous(rendezvousIds)
                    Log.d(TAG, "Relay connected, registered rendezvous: $rendezvousIds")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to connect to relay: ${e.message}")
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        signalingClient.removeListener(relayListener)
    }

    /**
     * Primary UI state: the list of paired devices enriched with live online status.
     *
     * Loading defaults to true until the first Room emission. After that it is always
     * false — the list may be empty but is never in an indeterminate state.
     */
    val uiState: StateFlow<DeviceHubUiState> = combine(
        deviceRepo.observePairedDevices(),
        deviceRepo.onlineDevices,
    ) { devices, online ->
        DeviceHubUiState(
            devices = devices.map { entity ->
                PairedDeviceUi(
                    entity = entity,
                    isOnline = online.contains(entity.deviceId),
                )
            },
            isLoading = false,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = DeviceHubUiState(),
    )

    /**
     * Reads the Android system clipboard and sends its text content to the
     * specified paired Chrome device via the relay WebSocket.
     *
     * @param targetDeviceId The Chrome device's ID to send the clipboard to.
     */
    fun sendClipboard(targetDeviceId: String) {
        val clipboardManager = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboardManager.primaryClip
        val text = clip?.getItemAt(0)?.text?.toString()

        if (text.isNullOrBlank()) {
            _toastEvents.tryEmit("Clipboard is empty")
            return
        }

        viewModelScope.launch {
            try {
                sendClipboardEncrypted(targetDeviceId, text)
                val preview = if (text.length > 40) text.take(37) + "..." else text
                _toastEvents.tryEmit("Clipboard sent (encrypted): $preview")
            } catch (e: BeamSessionRegistry.HandshakeException) {
                Log.e(TAG, "Encrypted clipboard send failed: ${e.code}", e)
                _toastEvents.tryEmit("Send failed — ${BeamSessionRegistry.ErrorMessages.forCode(e.code)}")
            } catch (e: Exception) {
                Log.e(TAG, "Encrypted clipboard send failed", e)
                _toastEvents.tryEmit("Send failed — ${BeamSessionRegistry.ErrorMessages.forCode(BeamSessionRegistry.ErrorCodes.INTERNAL)}")
            }
        }
    }

    // -------------------------------------------------------------------------
    // Beam E2E encryption — handshake + frame handling
    // -------------------------------------------------------------------------

    /**
     * Run the Beam Triple-DH handshake with [targetDeviceId] and send [text]
     * as an encrypted clipboard payload over the binary channel.
     */
    private suspend fun sendClipboardEncrypted(targetDeviceId: String, text: String) {
        val peerStaticPk = beamCrypto.peerStaticPk(targetDeviceId)
            ?: throw BeamSessionRegistry.HandshakeException(
                BeamSessionRegistry.ErrorCodes.INTERNAL,
                "no static key for peer $targetDeviceId",
            )
        val rendezvousId = targetDeviceId // Chrome's deviceId is the rendezvous

        val init = beamCrypto.registry.startInit(
            peerId = targetDeviceId,
            peerStaticPk = peerStaticPk,
            kind = BeamSessionRegistry.Kind.CLIPBOARD,
        )
        // Wire encoding: 16 raw bytes → base64url. MUST match Chrome exactly
        // so the relay pairs relay-bind strings and the peer looks up the
        // session by the same key.
        val transferIdWire = base64UrlFromBytes(init.wireMessage.transferId)
        val waiter = CompletableDeferred<BeamSessionRegistry.Session>()
        pendingAccepts[transferIdWire] = waiter

        signalingClient.send(JSONObject().apply {
            put("type", "transfer-init")
            put("v", init.wireMessage.v)
            put("targetDeviceId", targetDeviceId)
            put("rendezvousId", rendezvousId)
            put("transferId", transferIdWire)
            put("kind", init.wireMessage.kind.wire)
            put("ephPkA", base64UrlFromBytes(init.wireMessage.ephPkA))
            put("salt", base64UrlFromBytes(init.wireMessage.salt))
        })
        signalingClient.send(JSONObject().apply {
            put("type", "relay-bind")
            put("transferId", transferIdWire)
            put("targetDeviceId", targetDeviceId)
            put("rendezvousId", rendezvousId)
        })

        val session = try {
            withTimeout(10_000) { waiter.await() }
        } catch (e: TimeoutCancellationException) {
            pendingAccepts.remove(transferIdWire)
            signalingClient.send(JSONObject().apply {
                put("type", "transfer-reject")
                put("targetDeviceId", targetDeviceId)
                put("rendezvousId", rendezvousId)
                put("transferId", transferIdWire)
                put("errorCode", BeamSessionRegistry.ErrorCodes.TIMEOUT)
            })
            signalingClient.send(JSONObject().apply {
                put("type", "relay-release")
                put("transferId", transferIdWire)
            })
            beamCrypto.registry.destroy(init.session.transferId, BeamSessionRegistry.ErrorCodes.TIMEOUT)
            throw BeamSessionRegistry.HandshakeException(
                BeamSessionRegistry.ErrorCodes.TIMEOUT,
                "handshake timed out waiting for transfer-accept",
            )
        }

        try {
            val plaintext = text.toByteArray(Charsets.UTF_8)
            val chunkKey = session.chunkKey
                ?: throw IllegalStateException("chunkKey null after handshake")
            val transcript = session.transcript
                ?: throw IllegalStateException("transcript null after handshake")
            val ciphertext = beamCrypto.cipher.encryptClipboard(plaintext, chunkKey, transcript)
            val frame = encodeBeamFrame(session.transferId, 0, ciphertext)
            signalingClient.sendBinary(frame)
        } finally {
            signalingClient.send(JSONObject().apply {
                put("type", "relay-release")
                put("transferId", transferIdWire)
            })
            beamCrypto.registry.destroy(session.transferId)
        }
    }

    /**
     * Handle an incoming transfer-init message from the peer. Derives session
     * keys, responds with transfer-accept + relay-bind, and parks the session
     * in ACTIVE state awaiting the encrypted binary frame.
     */
    private suspend fun handleTransferInit(json: JSONObject) {
        val fromDeviceId = json.optString("fromDeviceId", json.optString("deviceId", ""))
        val rendezvousId = json.optString("rendezvousId", fromDeviceId)
        val transferIdWire = json.optString("transferId", "")
        val peerStaticPk = beamCrypto.peerStaticPk(fromDeviceId)
        if (peerStaticPk == null) {
            Log.w(TAG, "transfer-init: no peerStaticPk for $fromDeviceId — rejecting")
            sendTransferReject(fromDeviceId, rendezvousId, transferIdWire, BeamSessionRegistry.ErrorCodes.INTERNAL)
            return
        }
        val kindStr = json.optString("kind", "")
        val kind = BeamSessionRegistry.Kind.fromWire(kindStr) ?: run {
            sendTransferReject(fromDeviceId, rendezvousId, transferIdWire, BeamSessionRegistry.ErrorCodes.INTERNAL)
            return
        }
        val wire = try {
            BeamSessionRegistry.TransferInitMessage(
                v = json.optInt("v", 0),
                transferId = base64UrlToBytes(transferIdWire),
                kind = kind,
                ephPkA = base64UrlToBytes(json.optString("ephPkA", "")),
                salt = base64UrlToBytes(json.optString("salt", "")),
            )
        } catch (e: Exception) {
            Log.e(TAG, "transfer-init wire decode error", e)
            sendTransferReject(fromDeviceId, rendezvousId, transferIdWire, BeamSessionRegistry.ErrorCodes.INTERNAL)
            return
        }
        try {
            val accept = beamCrypto.registry.onInit(fromDeviceId, peerStaticPk, wire)
            val replyIdWire = base64UrlFromBytes(accept.wireMessage.transferId)
            signalingClient.send(JSONObject().apply {
                put("type", "transfer-accept")
                put("v", accept.wireMessage.v)
                put("targetDeviceId", fromDeviceId)
                put("rendezvousId", rendezvousId)
                put("transferId", replyIdWire)
                put("ephPkB", base64UrlFromBytes(accept.wireMessage.ephPkB))
            })
            signalingClient.send(JSONObject().apply {
                put("type", "relay-bind")
                put("transferId", replyIdWire)
                put("targetDeviceId", fromDeviceId)
                put("rendezvousId", rendezvousId)
            })
        } catch (e: BeamSessionRegistry.HandshakeException) {
            Log.w(TAG, "transfer-init rejected: ${e.code}")
            sendTransferReject(fromDeviceId, rendezvousId, transferIdWire, e.code)
        } catch (e: Exception) {
            Log.e(TAG, "transfer-init handling error", e)
            sendTransferReject(fromDeviceId, rendezvousId, transferIdWire, BeamSessionRegistry.ErrorCodes.INTERNAL)
        }
    }

    /**
     * Handle an incoming transfer-accept: finish sender-side Triple-DH and
     * resolve the pending sendClipboardEncrypted waiter.
     */
    private fun handleTransferAccept(json: JSONObject) {
        val fromDeviceId = json.optString("fromDeviceId", json.optString("deviceId", ""))
        val transferIdWire = json.optString("transferId", "")
        try {
            val wire = BeamSessionRegistry.TransferAcceptMessage(
                v = json.optInt("v", 0),
                transferId = base64UrlToBytes(transferIdWire),
                ephPkB = base64UrlToBytes(json.optString("ephPkB", "")),
            )
            val session = beamCrypto.registry.onAccept(fromDeviceId, wire)
            pendingAccepts.remove(transferIdWire)?.complete(session)
        } catch (e: Exception) {
            Log.e(TAG, "transfer-accept handling error", e)
            pendingAccepts.remove(transferIdWire)?.completeExceptionally(e)
        }
    }

    /**
     * Handle an incoming transfer-reject.
     */
    private fun handleTransferReject(json: JSONObject) {
        val transferIdWire = json.optString("transferId", "")
        val code = json.optString("errorCode", BeamSessionRegistry.ErrorCodes.INTERNAL)
        val err = BeamSessionRegistry.HandshakeException(code, "peer rejected transfer: $code")
        pendingAccepts.remove(transferIdWire)?.completeExceptionally(err)
        try {
            beamCrypto.registry.destroy(base64UrlToBytes(transferIdWire), code)
        } catch (_: Exception) { /* ignore */ }
    }

    /**
     * Decrypt and deliver an incoming Beam binary frame. Routes by the
     * active session's kind.
     */
    private suspend fun handleIncomingBeamFrame(bytes: ByteArray) {
        val frame = decodeBeamFrame(bytes) ?: return
        val session = beamCrypto.registry.getByTransferId(frame.transferId) ?: run {
            Log.w(TAG, "Beam frame for unknown session ${bytesToHex(frame.transferId)}")
            return
        }
        if (session.state != BeamSessionRegistry.State.ACTIVE) {
            Log.w(TAG, "Beam frame for inactive session (state=${session.state})")
            return
        }
        beamCrypto.registry.touch(session)

        when (session.kind) {
            BeamSessionRegistry.Kind.CLIPBOARD -> {
                try {
                    val chunkKey = session.chunkKey ?: return
                    val transcript = session.transcript ?: return
                    val plaintext = beamCrypto.cipher.decryptClipboard(frame.ciphertext, chunkKey, transcript)
                    val content = String(plaintext, Charsets.UTF_8)
                    deliverIncomingClipboard(content, session.peerId)
                } catch (e: Exception) {
                    Log.e(TAG, "clipboard decrypt failed", e)
                } finally {
                    beamCrypto.registry.destroy(session.transferId)
                }
            }
            BeamSessionRegistry.Kind.FILE -> handleIncomingBeamFileFrame(session, frame.index, frame.ciphertext)
        }
    }

    /**
     * Per-session accumulation state for an incoming encrypted file.
     * Keyed by transferId hex in [pendingBeamFiles].
     */
    private data class IncomingBeamFile(
        val fileName: String,
        val fileSize: Int,
        val mimeType: String,
        val totalChunks: Int,
        val chunks: MutableList<ByteArray> = mutableListOf(),
    )

    private val pendingBeamFiles =
        java.util.concurrent.ConcurrentHashMap<String, IncomingBeamFile>()

    private suspend fun handleIncomingBeamFileFrame(
        session: BeamSessionRegistry.Session,
        index: Int,
        ciphertext: ByteArray,
    ) {
        val transcript = session.transcript ?: return
        val metaKey = session.metaKey ?: return
        val chunkKey = session.chunkKey ?: return
        val idHex = bytesToHex(session.transferId)

        try {
            if (index == 0) {
                // Encrypted metadata envelope.
                val metaBytes = beamCrypto.cipher.decryptFileMetadata(ciphertext, metaKey, transcript)
                val metaJson = JSONObject(String(metaBytes, Charsets.UTF_8))
                val fileName = metaJson.optString("fileName", "file")
                val fileSize = metaJson.optInt("fileSize", 0)
                val mimeType = metaJson.optString("mime", "application/octet-stream")
                val totalChunks = metaJson.optInt("totalChunks", 0)
                if (totalChunks <= 0) {
                    Log.e(TAG, "file metadata has invalid totalChunks: $totalChunks")
                    beamCrypto.registry.destroy(session.transferId, BeamSessionRegistry.ErrorCodes.DECRYPT_FAIL)
                    return
                }
                session.totalChunks = totalChunks
                pendingBeamFiles[idHex] = IncomingBeamFile(
                    fileName = fileName,
                    fileSize = fileSize,
                    mimeType = mimeType,
                    totalChunks = totalChunks,
                )
                return
            }

            val state = pendingBeamFiles[idHex]
            if (state == null) {
                Log.e(TAG, "file chunk arrived before metadata envelope")
                beamCrypto.registry.destroy(session.transferId, BeamSessionRegistry.ErrorCodes.DECRYPT_FAIL)
                return
            }
            if (index > state.totalChunks) {
                Log.e(TAG, "file chunk index $index exceeds totalChunks ${state.totalChunks}")
                pendingBeamFiles.remove(idHex)
                beamCrypto.registry.destroy(session.transferId, BeamSessionRegistry.ErrorCodes.DECRYPT_FAIL)
                return
            }

            val plain = beamCrypto.cipher.decryptFileChunk(
                ciphertext = ciphertext,
                chunkKey = chunkKey,
                index = index,
                totalChunks = state.totalChunks,
                transcript = transcript,
            )
            state.chunks.add(plain)

            if (state.chunks.size == state.totalChunks) {
                // All chunks received — assemble and hand off to legacy delivery UX.
                val totalLen = state.chunks.sumOf { it.size }
                val combined = ByteArray(totalLen)
                var off = 0
                for (c in state.chunks) {
                    c.copyInto(combined, off)
                    off += c.size
                }
                if (totalLen != state.fileSize) {
                    Log.e(TAG, "file size mismatch: expected ${state.fileSize}, got $totalLen")
                    pendingBeamFiles.remove(idHex)
                    beamCrypto.registry.destroy(session.transferId, BeamSessionRegistry.ErrorCodes.DECRYPT_FAIL)
                    return
                }
                pendingBeamFiles.remove(idHex)
                val ft = FileTransferState(
                    transferId = idHex,
                    fileName = state.fileName,
                    fileSize = state.fileSize,
                    mimeType = state.mimeType,
                    fromDeviceId = session.peerId,
                ).also { it.chunks.add(combined); it.bytesReceived = totalLen }
                handleReceivedFileComplete(ft)
                beamCrypto.registry.destroy(session.transferId)
            }
        } catch (e: Exception) {
            Log.e(TAG, "file frame decrypt failed at index $index", e)
            pendingBeamFiles.remove(idHex)
            beamCrypto.registry.destroy(session.transferId, BeamSessionRegistry.ErrorCodes.DECRYPT_FAIL)
        }
    }

    private fun sendTransferReject(
        targetDeviceId: String,
        rendezvousId: String,
        transferIdHex: String,
        errorCode: String,
    ) {
        signalingClient.send(JSONObject().apply {
            put("type", "transfer-reject")
            put("targetDeviceId", targetDeviceId)
            put("rendezvousId", rendezvousId)
            put("transferId", transferIdHex)
            put("errorCode", errorCode)
        })
    }

    // -- Beam frame codec -----------------------------------------------------

    private val BEAM_MAGIC = byteArrayOf(0x42, 0x45, 0x41, 0x4d) // "BEAM"

    private fun isBeamFrame(bytes: ByteArray): Boolean =
        bytes.size >= 24 &&
            bytes[0] == BEAM_MAGIC[0] &&
            bytes[1] == BEAM_MAGIC[1] &&
            bytes[2] == BEAM_MAGIC[2] &&
            bytes[3] == BEAM_MAGIC[3]

    private fun encodeBeamFrame(transferId: ByteArray, index: Int, ciphertext: ByteArray): ByteArray {
        require(transferId.size == 16) { "transferId must be 16 bytes" }
        val out = ByteArray(24 + ciphertext.size)
        System.arraycopy(BEAM_MAGIC, 0, out, 0, 4)
        System.arraycopy(transferId, 0, out, 4, 16)
        out[20] = ((index ushr 24) and 0xff).toByte()
        out[21] = ((index ushr 16) and 0xff).toByte()
        out[22] = ((index ushr 8) and 0xff).toByte()
        out[23] = (index and 0xff).toByte()
        System.arraycopy(ciphertext, 0, out, 24, ciphertext.size)
        return out
    }

    private data class BeamFrame(val transferId: ByteArray, val index: Int, val ciphertext: ByteArray)

    private fun decodeBeamFrame(bytes: ByteArray): BeamFrame? {
        if (!isBeamFrame(bytes)) return null
        val transferId = bytes.copyOfRange(4, 20)
        val index =
            ((bytes[20].toInt() and 0xff) shl 24) or
                ((bytes[21].toInt() and 0xff) shl 16) or
                ((bytes[22].toInt() and 0xff) shl 8) or
                (bytes[23].toInt() and 0xff)
        val ciphertext = bytes.copyOfRange(24, bytes.size)
        return BeamFrame(transferId, index, ciphertext)
    }

    private fun bytesToHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    /**
     * Encode raw bytes as unpadded base64url. This is the canonical on-the-wire
     * encoding for every transferId and ephemeral-public-key field in the Beam
     * E2E handshake, matching the Chrome extension byte-for-byte.
     */
    private fun base64UrlFromBytes(b: ByteArray): String {
        return android.util.Base64.encodeToString(
            b,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
        )
    }

    private fun base64UrlToBytes(s: String): ByteArray {
        return android.util.Base64.decode(
            s,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
        )
    }

    /**
     * The 10 most recent clipboard entries, ordered newest-first.
     * Drives the "Received Clipboard" section on the Device Hub screen.
     */
    val recentClipboard: StateFlow<List<ClipboardEntryEntity>> =
        clipboardDao.getRecent(10)
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(5_000),
                initialValue = emptyList(),
            )

    /**
     * Copies the given text to the Android system clipboard.
     * Used by the "Copy" button on received clipboard items.
     *
     * @param text The text content to place on the clipboard.
     */
    fun copyToClipboard(text: String) {
        val clipboardManager = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboardManager.setPrimaryClip(ClipData.newPlainText("Beam Clipboard", text))
        _toastEvents.tryEmit("Copied to clipboard")
    }

    /**
     * The 20 most recent transfers across all devices, ordered newest-first.
     *
     * Emits a new list whenever any [TransferHistoryEntity] row changes — the
     * TransferForegroundService writes rows as transfers complete.
     */
    val recentTransfers: StateFlow<List<TransferHistoryEntity>> =
        transferHistoryDao.getRecent(20)
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(5_000),
                initialValue = emptyList(),
            )

    /**
     * Sends a file to a paired Chrome device via the relay binary channel.
     *
     * Flow:
     *  1. Read the file bytes from the content URI.
     *  2. Send a file-offer JSON message with metadata.
     *  3. Send relay-bind to establish the binary session.
     *  4. Wait for bind to propagate, then stream 200KB binary chunks.
     *  5. Send file-complete to signal the end of the transfer.
     *
     * @param targetDeviceId The Chrome device's ID to send the file to.
     * @param uri            Content URI of the file selected by the user.
     */
    fun sendFile(targetDeviceId: String, uri: Uri) {
        viewModelScope.launch {
            try {
                val contentResolver = appContext.contentResolver
                val fileName = contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    cursor.moveToFirst()
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex >= 0) cursor.getString(nameIndex) else null
                } ?: "file"

                val inputStream = contentResolver.openInputStream(uri) ?: run {
                    _toastEvents.tryEmit("Could not open file")
                    return@launch
                }
                val bytes = inputStream.use { it.readBytes() }
                val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"

                Log.d(TAG, "Sending encrypted file: $fileName (${bytes.size} bytes) to $targetDeviceId")
                sendFileEncrypted(targetDeviceId, fileName, mimeType, bytes)
                _toastEvents.tryEmit("Sent $fileName (encrypted)")
            } catch (e: BeamSessionRegistry.HandshakeException) {
                Log.e(TAG, "Encrypted file send failed: ${e.code}", e)
                _toastEvents.tryEmit("File send failed — ${BeamSessionRegistry.ErrorMessages.forCode(e.code)}")
            } catch (e: Exception) {
                Log.e(TAG, "sendFile failed: ${e.message}", e)
                _toastEvents.tryEmit("File send failed — ${BeamSessionRegistry.ErrorMessages.forCode(BeamSessionRegistry.ErrorCodes.INTERNAL)}")
            }
        }
    }

    /**
     * Run the Beam handshake and stream an encrypted file to the peer.
     * Mirrors [sendClipboardEncrypted] but emits an encrypted metadata
     * envelope followed by N encrypted chunks.
     */
    private suspend fun sendFileEncrypted(
        targetDeviceId: String,
        fileName: String,
        mimeType: String,
        fileBytes: ByteArray,
    ) {
        val peerStaticPk = beamCrypto.peerStaticPk(targetDeviceId)
            ?: throw BeamSessionRegistry.HandshakeException(
                BeamSessionRegistry.ErrorCodes.INTERNAL,
                "no static key for peer $targetDeviceId",
            )
        val rendezvousId = targetDeviceId

        val chunkSize = 200 * 1024
        val totalChunks = maxOf(1, (fileBytes.size + chunkSize - 1) / chunkSize)

        val init = beamCrypto.registry.startInit(
            peerId = targetDeviceId,
            peerStaticPk = peerStaticPk,
            kind = BeamSessionRegistry.Kind.FILE,
        )
        val transferIdWire = base64UrlFromBytes(init.wireMessage.transferId)
        val waiter = CompletableDeferred<BeamSessionRegistry.Session>()
        pendingAccepts[transferIdWire] = waiter

        signalingClient.send(JSONObject().apply {
            put("type", "transfer-init")
            put("v", init.wireMessage.v)
            put("targetDeviceId", targetDeviceId)
            put("rendezvousId", rendezvousId)
            put("transferId", transferIdWire)
            put("kind", init.wireMessage.kind.wire)
            put("ephPkA", base64UrlFromBytes(init.wireMessage.ephPkA))
            put("salt", base64UrlFromBytes(init.wireMessage.salt))
        })
        signalingClient.send(JSONObject().apply {
            put("type", "relay-bind")
            put("transferId", transferIdWire)
            put("targetDeviceId", targetDeviceId)
            put("rendezvousId", rendezvousId)
        })

        val session = try {
            withTimeout(15_000) { waiter.await() }
        } catch (e: TimeoutCancellationException) {
            pendingAccepts.remove(transferIdWire)
            signalingClient.send(JSONObject().apply {
                put("type", "transfer-reject")
                put("targetDeviceId", targetDeviceId)
                put("rendezvousId", rendezvousId)
                put("transferId", transferIdWire)
                put("errorCode", BeamSessionRegistry.ErrorCodes.TIMEOUT)
            })
            signalingClient.send(JSONObject().apply {
                put("type", "relay-release")
                put("transferId", transferIdWire)
            })
            beamCrypto.registry.destroy(init.session.transferId, BeamSessionRegistry.ErrorCodes.TIMEOUT)
            throw BeamSessionRegistry.HandshakeException(
                BeamSessionRegistry.ErrorCodes.TIMEOUT,
                "handshake timed out waiting for transfer-accept (file)",
            )
        }

        try {
            val chunkKey = session.chunkKey ?: throw IllegalStateException("chunkKey null after handshake")
            val metaKey = session.metaKey ?: throw IllegalStateException("metaKey null after handshake")
            val transcript = session.transcript ?: throw IllegalStateException("transcript null after handshake")
            session.totalChunks = totalChunks

            // 1. Encrypted metadata envelope at index 0.
            val metaJson = JSONObject().apply {
                put("fileName", fileName)
                put("fileSize", fileBytes.size)
                put("mime", mimeType)
                put("totalChunks", totalChunks)
            }.toString()
            val metaCt = beamCrypto.cipher.encryptFileMetadata(
                metaJson.toByteArray(Charsets.UTF_8),
                metaKey,
                transcript,
            )
            signalingClient.sendBinary(encodeBeamFrame(session.transferId, 0, metaCt))

            // 2. Encrypted chunks at indices 1..N.
            var offset = 0
            var chunkIndex = 1
            while (offset < fileBytes.size) {
                val end = minOf(offset + chunkSize, fileBytes.size)
                val chunkPlain = fileBytes.copyOfRange(offset, end)
                val chunkCt = beamCrypto.cipher.encryptFileChunk(
                    plaintext = chunkPlain,
                    chunkKey = chunkKey,
                    index = chunkIndex,
                    totalChunks = totalChunks,
                    transcript = transcript,
                )
                signalingClient.sendBinary(encodeBeamFrame(session.transferId, chunkIndex, chunkCt))
                offset = end
                chunkIndex += 1
                if (offset < fileBytes.size) delay(20)
            }

            // 3. file-complete signal.
            signalingClient.send(JSONObject().apply {
                put("type", "file-complete")
                put("targetDeviceId", targetDeviceId)
                put("rendezvousId", rendezvousId)
                put("transferId", transferIdWire)
            })
        } finally {
            signalingClient.send(JSONObject().apply {
                put("type", "relay-release")
                put("transferId", transferIdWire)
            })
            beamCrypto.registry.destroy(session.transferId)
        }
    }

    /**
     * Routes a completed file transfer based on the auto-save setting.
     *
     * - Auto-save ON:  immediately saves to Downloads and toasts "Saved [filename]".
     * - Auto-save OFF: holds the assembled bytes in [_pendingFileSave] so the UI
     *                  can prompt the user, and toasts "File received: [filename] -- open app to save".
     */
    private fun handleReceivedFileComplete(ft: FileTransferState) {
        viewModelScope.launch {
            val prefs = userPreferences.preferencesFlow.first()
            if (prefs.autoSaveFiles) {
                saveReceivedFile(ft)
            } else {
                // Assemble chunks into a single byte array for deferred save.
                val combined = ByteArray(ft.chunks.sumOf { it.size })
                var offset = 0
                for (chunk in ft.chunks) {
                    chunk.copyInto(combined, offset)
                    offset += chunk.size
                }
                _pendingFileSave.value = PendingFileSave(
                    fileName = ft.fileName,
                    mimeType = ft.mimeType,
                    data = combined,
                    fromDeviceId = ft.fromDeviceId,
                )
                _toastEvents.tryEmit("File received: ${ft.fileName} \u2014 open app to save")
            }
        }
    }

    /**
     * Saves the currently pending file (held in [_pendingFileSave]) to Downloads.
     * Called by the UI when the user taps "Save" on the pending file prompt.
     */
    fun savePendingFile() {
        val pending = _pendingFileSave.value ?: return
        viewModelScope.launch {
            try {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, pending.fileName)
                    put(MediaStore.Downloads.MIME_TYPE, pending.mimeType)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        put(MediaStore.Downloads.IS_PENDING, 1)
                    }
                }
                val uri = appContext.contentResolver.insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI, values
                ) ?: throw Exception("Failed to create file entry in MediaStore")

                appContext.contentResolver.openOutputStream(uri)?.use { it.write(pending.data) }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    values.clear()
                    values.put(MediaStore.Downloads.IS_PENDING, 0)
                    appContext.contentResolver.update(uri, values, null, null)
                }

                Log.d(TAG, "Pending file saved to Downloads: ${pending.fileName}")
                _toastEvents.tryEmit("Saved ${pending.fileName} to Downloads")
                _pendingFileSave.value = null
            } catch (e: Exception) {
                Log.e(TAG, "savePendingFile failed: ${e.message}", e)
                _toastEvents.tryEmit("Failed to save file: ${e.message}")
            }
        }
    }

    /**
     * Dismisses the pending file save prompt without saving.
     */
    fun dismissPendingFile() {
        _pendingFileSave.value = null
    }

    /**
     * Assembles received file chunks and saves the resulting file to the
     * Downloads directory via MediaStore.
     *
     * Uses the MediaStore IS_PENDING pattern to ensure the file is only visible
     * to other apps after the write is complete (avoids partial-file access).
     *
     * @param ft The completed file transfer state containing all received chunks.
     */
    private fun saveReceivedFile(ft: FileTransferState) {
        viewModelScope.launch {
            try {
                // Assemble all chunks into a single byte array.
                val combined = ByteArray(ft.chunks.sumOf { it.size })
                var offset = 0
                for (chunk in ft.chunks) {
                    chunk.copyInto(combined, offset)
                    offset += chunk.size
                }

                // Write to Downloads via MediaStore.
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, ft.fileName)
                    put(MediaStore.Downloads.MIME_TYPE, ft.mimeType)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        put(MediaStore.Downloads.IS_PENDING, 1)
                    }
                }
                val uri = appContext.contentResolver.insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI, values
                ) ?: throw Exception("Failed to create file entry in MediaStore")

                appContext.contentResolver.openOutputStream(uri)?.use { it.write(combined) }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    values.clear()
                    values.put(MediaStore.Downloads.IS_PENDING, 0)
                    appContext.contentResolver.update(uri, values, null, null)
                }

                Log.d(TAG, "File saved to Downloads: ${ft.fileName}")
                _toastEvents.tryEmit("Saved ${ft.fileName} to Downloads")
            } catch (e: Exception) {
                Log.e(TAG, "saveReceivedFile failed: ${e.message}", e)
                _toastEvents.tryEmit("Failed to save file: ${e.message}")
            }
        }
    }
}

// ── UI models ──────────────────────────────────────────────────────────────────

/**
 * Top-level UI state for the Device Hub screen.
 *
 * @param devices   List of paired devices, each annotated with live online status.
 * @param isLoading True only during the very first Room emission; false thereafter.
 */
data class DeviceHubUiState(
    val devices: List<PairedDeviceUi> = emptyList(),
    val isLoading: Boolean = true,
)

/**
 * A [PairedDeviceEntity] enriched with the current online presence status.
 *
 * Presence is ephemeral — it resets to false on process restart and is
 * re-populated by relay presence events. The UI should treat [isOnline] as
 * best-effort and never gate critical operations on it.
 *
 * @param entity   The persistent device record from Room.
 * @param isOnline True if the device has reported online presence since last app start.
 */
data class PairedDeviceUi(
    val entity: PairedDeviceEntity,
    val isOnline: Boolean,
)

/**
 * Mutable accumulator for an in-progress incoming file transfer.
 *
 * Populated when a file-offer message arrives; chunks are appended as binary
 * frames are received; consumed by [DeviceHubViewModel.saveReceivedFile] when
 * the file-complete message arrives.
 *
 * @param transferId   Unique identifier for this transfer (generated by the sender).
 * @param fileName     Original file name from the sender.
 * @param fileSize     Expected total size in bytes.
 * @param mimeType     MIME type of the file.
 * @param fromDeviceId Device ID of the sender.
 * @param chunks       Accumulated binary chunks in receive order.
 * @param bytesReceived Running total of bytes received so far.
 */
data class FileTransferState(
    val transferId: String,
    val fileName: String,
    val fileSize: Int,
    val mimeType: String,
    val fromDeviceId: String,
    val chunks: MutableList<ByteArray> = mutableListOf(),
    var bytesReceived: Int = 0,
)

/**
 * Holds a fully received file that has not yet been saved to disk.
 * Used when auto-save is OFF — the UI shows a save prompt with this data.
 *
 * @param fileName     Original file name from the sender.
 * @param mimeType     MIME type of the file.
 * @param data         Complete file contents as a byte array.
 * @param fromDeviceId Device ID of the sender.
 */
data class PendingFileSave(
    val fileName: String,
    val mimeType: String,
    val data: ByteArray,
    val fromDeviceId: String,
)
