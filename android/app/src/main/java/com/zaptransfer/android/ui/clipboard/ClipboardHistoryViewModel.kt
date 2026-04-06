package com.zaptransfer.android.ui.clipboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.data.db.dao.ClipboardDao
import com.zaptransfer.android.data.db.entity.ClipboardEntryEntity
import com.zaptransfer.android.data.repository.DeviceRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

private const val CLIPBOARD_HISTORY_LIMIT = 20

/**
 * ViewModel for [ClipboardHistoryScreen].
 *
 * Provides:
 *  - [items]: live list of the last 20 clipboard entries, newest first.
 *  - [deviceNameFor]: synchronous lookup of a device name from the cached device map.
 *
 * Device names are loaded from [DeviceRepository.observePairedDevices] and cached in an
 * in-memory map so the per-item [deviceNameFor] call does not require a DB query per row.
 *
 * @param clipboardDao      Room DAO for clipboard history.
 * @param deviceRepository  Provides the paired device list for name resolution.
 */
@HiltViewModel
class ClipboardHistoryViewModel @Inject constructor(
    private val clipboardDao: ClipboardDao,
    private val deviceRepository: DeviceRepository,
) : ViewModel() {

    /** Latest clipboard entries, capped at 20 items, ordered newest-first. */
    val items: StateFlow<List<ClipboardEntryEntity>> = clipboardDao
        .getRecent(CLIPBOARD_HISTORY_LIMIT)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList(),
        )

    /**
     * Map of deviceId → device name for fast O(1) lookup in [deviceNameFor].
     * Updated reactively whenever a device is paired, renamed, or unpaired.
     */
    private val deviceNames: StateFlow<Map<String, String>> = deviceRepository
        .observePairedDevices()
        .combine(items) { devices, _ ->
            // Re-derive name map whenever either the device list or item list changes
            devices.associate { it.deviceId to it.name }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyMap(),
        )

    /**
     * Returns the human-readable name for a device ID.
     *
     * Falls back to a shortened device ID string if the device has been unpaired
     * or the mapping has not yet loaded.
     *
     * @param deviceId 22-char relay device ID.
     * @return Device name or a fallback "Unknown device" label.
     */
    fun deviceNameFor(deviceId: String): String =
        deviceNames.value[deviceId] ?: deviceId.take(8) + "…"
}
