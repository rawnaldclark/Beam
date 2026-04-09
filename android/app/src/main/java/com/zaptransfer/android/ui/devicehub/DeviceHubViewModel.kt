package com.zaptransfer.android.ui.devicehub

import android.content.ClipData
import android.content.ClipboardManager
import android.util.Log
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.db.entity.TransferHistoryEntity
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import android.content.Context
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
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
    private val signalingClient: SignalingClient,
    @ApplicationContext private val appContext: Context,
) : ViewModel() {

    /** Shared flow for one-shot UI events (e.g., toast messages). */
    private val _toastEvents = MutableSharedFlow<String>(extraBufferCapacity = 5)
    val toastEvents: SharedFlow<String> = _toastEvents.asSharedFlow()

    /**
     * Listener that handles incoming clipboard-transfer messages from the relay.
     * Copies the content to the Android clipboard and emits a toast event.
     */
    private val clipboardListener = object : SignalingListener {
        override fun onMessage(message: RelayMessage) {
            if (message !is RelayMessage.Text) return
            val json = message.json
            if (json.optString("type") != "clipboard-transfer") return

            val content = json.optString("content", "")
            val from = json.optString("fromDeviceId", json.optString("deviceId", ""))
            Log.d(TAG, "Clipboard received from $from, length=${content.length}")

            // Copy to Android system clipboard
            val clipboardManager = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboardManager.setPrimaryClip(ClipData.newPlainText("Beam Clipboard", content))

            // Notify the UI
            val preview = if (content.length > 60) content.take(57) + "..." else content
            _toastEvents.tryEmit("Clipboard received: $preview")
        }
    }

    init {
        // Connect to relay if paired devices exist, so we can receive clipboard messages.
        viewModelScope.launch {
            val devices = deviceRepo.observePairedDevices().first()
            if (devices.isNotEmpty()) {
                try {
                    signalingClient.addListener(clipboardListener)
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
        signalingClient.removeListener(clipboardListener)
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
                    // TODO: real presence not yet wired — treat all paired devices as online
                    isOnline = true,
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
