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
import com.zaptransfer.android.crypto.BeamV2Transport
import com.zaptransfer.android.crypto.BeamV2Wiring
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
import androidx.annotation.VisibleForTesting
import org.json.JSONObject
import javax.inject.Inject

/**
 * Maximum declared size for an incoming Beam file transfer.
 *
 * Matches the server's SESSION_LIMIT (500 MB) so no legitimate transfer is
 * blocked client-side, while preventing a malicious paired peer from
 * declaring a multi-GB transfer to force an unbounded ByteArray allocation
 * on assembly.
 */
internal const val MAX_FILE_SIZE_BYTES: Long = 500L * 1024 * 1024

/**
 * Maximum declared chunk count for an incoming Beam file transfer.
 *
 * Sized for the 500 MB SESSION_LIMIT against the ~175 KB effective wire
 * chunk size (ciphertext + AEAD overhead).
 */
internal const val MAX_CHUNKS: Int = 3000

/** Maximum filename length accepted in a Beam file metadata envelope. */
internal const val MAX_FILENAME_LENGTH: Int = 255

/**
 * Validate a decrypted Beam file metadata envelope.
 *
 * Returns null if the metadata is acceptable, or a short human-readable
 * error description suitable for logging if it must be rejected. Rejection
 * means the caller MUST destroy the session with DECRYPT_FAIL and MUST NOT
 * store any state for this transfer — otherwise a malicious paired peer
 * can cause unbounded memory allocation on assembly.
 *
 * Caps are sized to match the server's existing SESSION_LIMIT so no
 * legitimate transfer is blocked client-side.
 *
 * @param fileName    Proposed file name from the decrypted envelope.
 * @param fileSize    Proposed total byte size (read as Long to avoid
 *                    silent Int overflow on attacker-supplied values
 *                    above 2^31).
 * @param mimeType    Proposed MIME type (defaulted non-null upstream).
 * @param totalChunks Proposed chunk count.
 * @return null if valid, otherwise a non-null error description.
 */
@VisibleForTesting
@Suppress("UNUSED_PARAMETER")
internal fun validateFileMetadata(
    fileName: String,
    fileSize: Long,
    mimeType: String,
    totalChunks: Int,
): String? {
    if (fileSize <= 0L || fileSize > MAX_FILE_SIZE_BYTES) {
        return "invalid fileSize=$fileSize"
    }
    if (totalChunks <= 0 || totalChunks > MAX_CHUNKS) {
        return "invalid totalChunks=$totalChunks"
    }
    if (fileName.isBlank() || fileName.length > MAX_FILENAME_LENGTH) {
        return "invalid fileName length=${fileName.length}"
    }
    // mimeType has a non-null default from optString upstream; no further
    // check needed here. Parameter retained so the signature matches the
    // fields read from the metadata envelope in one place.
    return null
}

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
    private val beamV2Wiring: BeamV2Wiring,
    @ApplicationContext private val appContext: Context,
) : ViewModel() {

    init {
        // Register the in-app delivery surface with the v2 wiring. This is
        // the single place transport-decoded clipboards/files reach the UI.
        beamV2Wiring.setDelivery(object : BeamV2Wiring.Delivery {
            override suspend fun onClipboardReceived(content: String, fromDeviceId: String) {
                deliverIncomingClipboard(content, fromDeviceId)
            }
            override suspend fun onFileReceived(args: BeamV2Transport.FileDelivery) {
                deliverIncomingFileV2(args)
            }
            override fun onReceiveError(transferIdHex: String, code: String) {
                Log.w(TAG, "Beam v2 receive error: $code (id=$transferIdHex)")
                _toastEvents.tryEmit("Receive failed — $code")
            }
        })
    }

    /**
     * Delivery callback for v2 file transfers. Saves to public Downloads
     * via MediaStore — required since Android 10 (scoped storage). Direct
     * `java.io.File` writes to `Environment.DIRECTORY_DOWNLOADS` fail
     * with `EACCES` on every modern device.
     */
    private suspend fun deliverIncomingFileV2(args: BeamV2Transport.FileDelivery) {
        try {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, args.fileName)
                put(MediaStore.Downloads.MIME_TYPE, args.mimeType)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
            }
            val uri = appContext.contentResolver.insert(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI, values,
            ) ?: throw Exception("Failed to create MediaStore entry")

            appContext.contentResolver.openOutputStream(uri)?.use { it.write(args.bytes) }
                ?: throw Exception("Failed to open output stream for $uri")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                appContext.contentResolver.update(uri, values, null, null)
            }

            _toastEvents.tryEmit("Saved ${args.fileName} to Downloads")
            Log.i(TAG, "Beam v2 file saved: ${args.fileName} (${args.fileSize} bytes)")
        } catch (e: Exception) {
            Log.e(TAG, "deliverIncomingFileV2 failed: ${e.message}", e)
            _toastEvents.tryEmit("File save failed: ${e.message}")
        }
    }

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
    /**
     * Listener for relay text messages this ViewModel still cares about
     * (presence updates). Binary frames and Beam v2 JSON are handled by
     * [BeamV2Wiring]'s dedicated listener; everything else is dropped.
     */
    private val relayListener = object : SignalingListener {
        override fun onMessage(message: RelayMessage) {
            if (message !is RelayMessage.Text) return
            when (message.json.optString("type")) {
                "peer-online" -> {
                    val peerId = message.json.optString("deviceId", "")
                    if (peerId.isNotEmpty()) deviceRepo.handlePresence(peerId, true)
                }
                "peer-offline" -> {
                    val peerId = message.json.optString("deviceId", "")
                    if (peerId.isNotEmpty()) deviceRepo.handlePresence(peerId, false)
                }
                else -> { /* ignored — handled elsewhere */ }
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

    /**
     * Re-register rendezvous with the relay to trigger a fresh presence
     * exchange. Called from the screen composable on every Activity resume
     * (via LifecycleResumeEffect) — not just on ViewModel init.
     *
     * This is the "refresh on focus" pattern: instead of trusting that
     * the persistent push chain (WS heartbeat → server presence → UI
     * update) delivered accurate state while the app was backgrounded,
     * we actively poke the server for fresh peer-online events every time
     * the user looks at the screen. Cheap (one JSON message) and makes
     * presence self-healing regardless of what happened during idle.
     */
    fun refreshPresence() {
        viewModelScope.launch {
            try {
                val devices = deviceRepo.observePairedDevices().first()
                if (devices.isNotEmpty()) {
                    // Ensure WS is alive — connect() is re-entrant and cycles
                    // a dead socket if needed.
                    signalingClient.connect()
                    // Re-register to trigger server peer-online re-emission.
                    val rendezvousIds = devices.map { it.deviceId }
                    signalingClient.registerRendezvous(rendezvousIds)
                    Log.d(TAG, "refreshPresence: re-registered rendezvous $rendezvousIds")
                }
            } catch (e: Exception) {
                Log.w(TAG, "refreshPresence failed: ${e.message}")
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
            } catch (e: com.zaptransfer.android.crypto.BeamV2Exception) {
                Log.e(TAG, "Encrypted clipboard send failed: ${e.code}", e)
                _toastEvents.tryEmit("Send failed — ${e.code}")
            } catch (e: Exception) {
                Log.e(TAG, "Encrypted clipboard send failed", e)
                _toastEvents.tryEmit("Send failed")
            }
        }
    }

    // -------------------------------------------------------------------------
    // Beam E2E encryption — handshake + frame handling
    // -------------------------------------------------------------------------

    /**
     * Send `text` as an encrypted clipboard payload via the Beam v2 transport.
     * One stateless AEAD frame; receiver decrypts on arrival, no handshake.
     */
    private suspend fun sendClipboardEncrypted(targetDeviceId: String, text: String) {
        beamV2Wiring.transport.sendClipboard(targetDeviceId, text)
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
            } catch (e: com.zaptransfer.android.crypto.BeamV2Exception) {
                Log.e(TAG, "Encrypted file send failed: ${e.code}", e)
                _toastEvents.tryEmit("File send failed — ${e.code}")
            } catch (e: Exception) {
                Log.e(TAG, "sendFile failed: ${e.message}", e)
                _toastEvents.tryEmit("File send failed")
            }
        }
    }

    /**
     * Send a file via Beam v2 transport: meta frame + chunk frames, all
     * stateless AEAD under K_AB. Receiver assembles via the transport's
     * inbox and emits via [BeamV2Wiring.Delivery.onFileReceived].
     */
    private suspend fun sendFileEncrypted(
        targetDeviceId: String,
        fileName: String,
        mimeType: String,
        fileBytes: ByteArray,
    ) {
        beamV2Wiring.transport.sendFile(
            targetDeviceId = targetDeviceId,
            fileName       = fileName,
            fileSize       = fileBytes.size.toLong(),
            mimeType       = mimeType.ifBlank { "application/octet-stream" },
            bytes          = fileBytes,
        )
    }

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
