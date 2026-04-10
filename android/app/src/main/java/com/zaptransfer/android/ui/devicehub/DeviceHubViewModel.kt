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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
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
    @ApplicationContext private val appContext: Context,
) : ViewModel() {

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
     * State for an in-progress incoming file transfer.
     * Populated when a file-offer is received; consumed on file-complete.
     */
    private var pendingFileTransfer: FileTransferState? = null

    /**
     * Listener that handles incoming relay messages:
     *   - clipboard-transfer: copies content to Android clipboard.
     *   - file-offer: auto-accepts and prepares to receive binary chunks.
     *   - file-complete: assembles chunks and saves to Downloads.
     *   - Binary frames: appends chunk data to the pending transfer.
     */
    private val relayListener = object : SignalingListener {
        override fun onMessage(message: RelayMessage) {
            when (message) {
                is RelayMessage.Binary -> {
                    // Binary frame — a file data chunk from the sender.
                    val ft = pendingFileTransfer ?: return
                    ft.chunks.add(message.data)
                    ft.bytesReceived += message.data.size
                    Log.d(TAG, "File chunk: ${message.data.size} bytes, total: ${ft.bytesReceived}/${ft.fileSize}")
                    // Auto-assemble when all bytes received
                    if (ft.bytesReceived >= ft.fileSize) {
                        Log.d(TAG, "All bytes received, handling file")
                        handleReceivedFileComplete(ft)
                        pendingFileTransfer = null
                    }
                }
                is RelayMessage.Text -> {
                    val json = message.json
                    when (json.optString("type")) {
                        "clipboard-transfer" -> handleClipboardTransfer(json)
                        "file-offer" -> handleFileOffer(json)
                        "file-accept" -> {
                            Log.d(TAG, "File accepted by remote, transferId: ${json.optString("transferId")}")
                        }
                        "file-complete" -> handleFileComplete(json)
                        "peer-online" -> {
                            val peerId = json.optString("deviceId", "")
                            if (peerId.isNotEmpty()) {
                                Log.d(TAG, "Peer online: $peerId")
                                deviceRepo.handlePresence(peerId, true)
                            }
                        }
                        "peer-offline" -> {
                            val peerId = json.optString("deviceId", "")
                            if (peerId.isNotEmpty()) {
                                Log.d(TAG, "Peer offline: $peerId")
                                deviceRepo.handlePresence(peerId, false)
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Handle an incoming clipboard-transfer message.
     *
     * Behaviour depends on the auto-copy clipboard setting:
     *   - ON:  copies to system clipboard + toast "Clipboard received and copied"
     *   - OFF: stores in Room only + toast "Clipboard received -- tap to copy"
     *
     * In both cases the content is persisted to Room for the history section.
     */
    private fun handleClipboardTransfer(json: JSONObject) {
        val content = json.optString("content", "")
        val from = json.optString("fromDeviceId", json.optString("deviceId", ""))
        Log.d(TAG, "Clipboard received from $from, length=${content.length}")

        viewModelScope.launch {
            // Read the current auto-copy setting from DataStore.
            val prefs = userPreferences.preferencesFlow.first()
            val autoCopy = prefs.autoCopyClipboard

            if (autoCopy) {
                // Copy to Android system clipboard
                val clipboardManager = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboardManager.setPrimaryClip(ClipData.newPlainText("Beam Clipboard", content))
            }

            // Always persist to Room for the "Received Clipboard" history section
            try {
                clipboardDao.insert(
                    ClipboardEntryEntity(
                        deviceId = from,
                        content = content,
                        isUrl = android.util.Patterns.WEB_URL.matcher(content).find(),
                        receivedAt = System.currentTimeMillis(),
                    )
                )
                // Trim to 20 entries max
                while (clipboardDao.getCount() > 20) {
                    clipboardDao.deleteOldest()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to persist clipboard entry: ${e.message}")
            }

            // Notify the UI with an appropriate message
            val preview = if (content.length > 60) content.take(57) + "..." else content
            if (autoCopy) {
                _toastEvents.tryEmit("Clipboard received and copied: $preview")
            } else {
                _toastEvents.tryEmit("Clipboard received \u2014 tap to copy: $preview")
            }
        }
    }

    /**
     * Handle an incoming file-offer message.
     * Auto-accepts the transfer by sending file-accept and relay-bind,
     * then prepares state to accumulate binary chunks.
     */
    private fun handleFileOffer(json: JSONObject) {
        val transferId = json.getString("transferId")
        val fileName = json.getString("fileName")
        val fileSize = json.getInt("fileSize")
        val mimeType = json.optString("mimeType", "application/octet-stream")
        val fromId = json.optString("fromDeviceId", json.optString("deviceId", ""))
        val rendezvousId = json.optString("rendezvousId", fromId)

        Log.d(TAG, "File offer from $fromId: $fileName ($fileSize bytes)")

        pendingFileTransfer = FileTransferState(
            transferId = transferId,
            fileName = fileName,
            fileSize = fileSize,
            mimeType = mimeType,
            fromDeviceId = fromId,
        )

        // Auto-accept: send file-accept + relay-bind
        signalingClient.send(JSONObject().apply {
            put("type", "file-accept")
            put("targetDeviceId", fromId)
            put("rendezvousId", rendezvousId)
            put("transferId", transferId)
        })
        signalingClient.send(JSONObject().apply {
            put("type", "relay-bind")
            put("transferId", transferId)
            put("targetDeviceId", fromId)
            put("rendezvousId", rendezvousId)
        })

        _toastEvents.tryEmit("Receiving $fileName...")
    }

    /**
     * Handle a file-complete message.
     * Assembles accumulated chunks and saves the file to Downloads.
     */
    private fun handleFileComplete(json: JSONObject) {
        val transferId = json.optString("transferId", "")
        val ft = pendingFileTransfer
        if (ft == null || ft.transferId != transferId) return

        Log.d(TAG, "File complete: ${ft.fileName}, ${ft.bytesReceived} bytes received")
        handleReceivedFileComplete(ft)
        pendingFileTransfer = null
    }

    init {
        // Connect to relay if paired devices exist, so we can receive clipboard messages.
        viewModelScope.launch {
            val devices = deviceRepo.observePairedDevices().first()
            if (devices.isNotEmpty()) {
                try {
                    signalingClient.addListener(relayListener)
                    // Only connect if not already connected.
                    if (signalingClient.connectionState.value !is ConnectionState.Connected &&
                        signalingClient.connectionState.value !is ConnectionState.Connecting
                    ) {
                        signalingClient.connect()
                    }
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

        // The rendezvous ID is Chrome's deviceId — the same one used during pairing.
        // Both sides registered this ID, so the relay can route between them.
        val msg = JSONObject().apply {
            put("type", "clipboard-transfer")
            put("targetDeviceId", targetDeviceId)
            put("rendezvousId", targetDeviceId) // Chrome's deviceId is the rendezvous
            put("content", text)
        }

        val sent = signalingClient.send(msg)
        if (sent) {
            val preview = if (text.length > 40) text.take(37) + "..." else text
            _toastEvents.tryEmit("Clipboard sent: $preview")
        } else {
            _toastEvents.tryEmit("Failed to send: relay not connected")
        }
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

                // Resolve the display name from the content provider.
                val fileName = contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    cursor.moveToFirst()
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex >= 0) cursor.getString(nameIndex) else null
                } ?: "file"

                // Read the entire file into memory.
                val inputStream = contentResolver.openInputStream(uri) ?: run {
                    _toastEvents.tryEmit("Could not open file")
                    return@launch
                }
                val bytes = inputStream.readBytes()
                inputStream.close()

                val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"
                val transferId = "tf-${System.currentTimeMillis()}-${(0..999999).random()}"

                // The rendezvous ID is Chrome's deviceId (used during pairing).
                val rendezvousId = targetDeviceId

                Log.d(TAG, "Sending file: $fileName (${bytes.size} bytes) to $targetDeviceId")

                // 1. Send file-offer metadata.
                signalingClient.send(JSONObject().apply {
                    put("type", "file-offer")
                    put("targetDeviceId", targetDeviceId)
                    put("rendezvousId", rendezvousId)
                    put("fileName", fileName)
                    put("fileSize", bytes.size)
                    put("mimeType", mimeType)
                    put("transferId", transferId)
                })

                // 2. Send relay-bind.
                signalingClient.send(JSONObject().apply {
                    put("type", "relay-bind")
                    put("transferId", transferId)
                    put("targetDeviceId", targetDeviceId)
                    put("rendezvousId", rendezvousId)
                })

                // 3. Wait for receiver to bind before streaming.
                delay(2000)

                // 4. Stream binary chunks (200KB each, under 256KB limit).
                // Small delay between chunks to avoid overwhelming the relay.
                val chunkSize = 200 * 1024
                var offset = 0
                while (offset < bytes.size) {
                    val end = minOf(offset + chunkSize, bytes.size)
                    signalingClient.sendBinary(bytes.sliceArray(offset until end))
                    offset = end
                    if (offset < bytes.size) delay(50) // pace chunks
                }

                // 5. Signal completion.
                delay(200)
                signalingClient.send(JSONObject().apply {
                    put("type", "file-complete")
                    put("targetDeviceId", targetDeviceId)
                    put("rendezvousId", rendezvousId)
                    put("transferId", transferId)
                })

                _toastEvents.tryEmit("Sent $fileName")
            } catch (e: Exception) {
                Log.e(TAG, "sendFile failed: ${e.message}", e)
                _toastEvents.tryEmit("Failed to send file: ${e.message}")
            }
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
