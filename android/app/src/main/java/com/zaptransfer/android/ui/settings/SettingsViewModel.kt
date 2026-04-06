package com.zaptransfer.android.ui.settings

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.preferences.UserPreferences
import com.zaptransfer.android.data.preferences.UserPrefsSnapshot
import com.zaptransfer.android.data.repository.DeviceRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

private const val TAG = "SettingsViewModel"

/**
 * Combined UI state for the Settings screen.
 *
 * Merges [UserPrefsSnapshot] with the live list of paired devices so the screen
 * only needs to observe a single [StateFlow].
 *
 * @param prefs         Current user preference values.
 * @param pairedDevices All currently paired devices, ordered by name.
 */
data class SettingsUiState(
    val prefs: UserPrefsSnapshot = UserPrefsSnapshot(),
    val pairedDevices: List<PairedDeviceEntity> = emptyList(),
)

/**
 * ViewModel for [SettingsScreen].
 *
 * Exposes exactly 4 settings corresponding to the spec:
 *  1. Save location — [setSaveLocation] / [clearSaveLocation]
 *  2. Auto-accept toggle — [setAutoAccept]
 *  3. Device name — [setDeviceName]
 *  4. Paired devices — [unPairDevice] (list comes from [DeviceRepository])
 *
 * All mutations are suspend functions dispatched on [viewModelScope] so the
 * ViewModel outlives configuration changes without leaking coroutines.
 *
 * @param userPreferences DataStore-backed preference store.
 * @param deviceRepository Room-backed device persistence and presence.
 */
@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val userPreferences: UserPreferences,
    private val deviceRepository: DeviceRepository,
) : ViewModel() {

    /**
     * Unified UI state: combines DataStore preferences with the Room device list.
     *
     * [SharingStarted.WhileSubscribed(5_000)] keeps the upstream flows alive for
     * 5 seconds after the last collector disappears, covering configuration changes
     * without unnecessary re-subscriptions.
     */
    val uiState: StateFlow<SettingsUiState> = combine(
        userPreferences.preferencesFlow,
        deviceRepository.observePairedDevices(),
    ) { prefs, devices ->
        SettingsUiState(prefs = prefs, pairedDevices = devices)
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = SettingsUiState(),
    )

    // ── Setting 1: Save location ──────────────────────────────────────────────

    /**
     * Persists a new SAF tree URI as the preferred save location.
     *
     * The URI is obtained by the UI via [Intent.ACTION_OPEN_DOCUMENT_TREE] and must
     * be persisted via [ContentResolver.takePersistableUriPermission] by the caller
     * before passing it here.
     *
     * @param uri SAF content tree URI string from the system directory picker.
     */
    fun setSaveLocation(uri: String) {
        viewModelScope.launch {
            userPreferences.setSaveLocationUri(uri)
            Log.d(TAG, "Save location set: $uri")
        }
    }

    /**
     * Resets the save location to the system Downloads folder.
     */
    fun clearSaveLocation() {
        viewModelScope.launch {
            userPreferences.setSaveLocationUri(null)
            Log.d(TAG, "Save location cleared — will use Downloads")
        }
    }

    // ── Setting 2: Auto-accept ────────────────────────────────────────────────

    /**
     * Updates the auto-accept toggle.
     *
     * @param enabled true to auto-accept incoming transfers from paired devices.
     */
    fun setAutoAccept(enabled: Boolean) {
        viewModelScope.launch {
            userPreferences.setAutoAccept(enabled)
            Log.d(TAG, "Auto-accept set: $enabled")
        }
    }

    // ── Setting 3: Device name ────────────────────────────────────────────────

    /**
     * Updates the human-readable name this device advertises to peers.
     *
     * Silently ignored if [name] is blank after trimming.
     *
     * @param name New device name (max 50 chars — enforced by [UserPreferences]).
     */
    fun setDeviceName(name: String) {
        val trimmed = name.trim()
        if (trimmed.isBlank()) {
            Log.w(TAG, "setDeviceName: blank name ignored")
            return
        }
        viewModelScope.launch {
            userPreferences.setDeviceName(trimmed)
            Log.d(TAG, "Device name set: $trimmed")
        }
    }

    // ── Setting 4: Paired devices ─────────────────────────────────────────────

    /**
     * Unpairs a device by removing it from Room.
     *
     * After removal the [uiState] flow will emit a new value with the device absent
     * from [SettingsUiState.pairedDevices].
     *
     * @param deviceId The 22-char stable relay ID of the device to unpair.
     */
    fun unPairDevice(deviceId: String) {
        viewModelScope.launch {
            deviceRepository.removeDevice(deviceId)
            Log.i(TAG, "Device $deviceId unpaired")
        }
    }
}
