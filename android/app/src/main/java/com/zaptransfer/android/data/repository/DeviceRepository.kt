package com.zaptransfer.android.data.repository

import android.util.Log
import com.zaptransfer.android.data.db.dao.PairedDeviceDao
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "DeviceRepository"

/**
 * Repository that mediates between the Room [PairedDeviceDao] and the rest of
 * the application (ViewModels, foreground service).
 *
 * Two data concerns:
 *  1. **Persistent device records** — stored in Room; exposed as [Flow] so UI
 *     layers react to additions, removals, and renames without polling.
 *  2. **Ephemeral online presence** — received from relay presence events; held
 *     in an in-memory [StateFlow] that resets on process restart. The spec
 *     (§6.7) explicitly notes presence is best-effort and not guaranteed.
 *
 * The presence set contains device IDs of devices currently reporting online
 * status via the relay. The UI overlays this with the persistent device list
 * to show green/grey indicators.
 *
 * Thread safety:
 *  - [MutableStateFlow] is safe for concurrent reads and writes.
 *  - DAO operations are suspend functions; Room dispatches them on its own executor.
 *  - [handlePresence] is not a suspend function so it can be called from OkHttp's
 *    WebSocket reader thread without launching a coroutine.
 *
 * @param dao Room DAO for paired device persistence.
 */
@Singleton
class DeviceRepository @Inject constructor(
    private val dao: PairedDeviceDao,
) {

    // ── Online presence (in-memory, ephemeral) ────────────────────────────────

    private val _onlineDevices = MutableStateFlow<Set<String>>(emptySet())

    /**
     * The current set of device IDs that have reported online presence.
     *
     * Consumers should combine this with [observePairedDevices] to determine
     * both the list of known devices and which are currently reachable:
     * ```kotlin
     * combine(repo.observePairedDevices(), repo.onlineDevices) { devices, online ->
     *     devices.map { it to (it.deviceId in online) }
     * }
     * ```
     *
     * Note: this set is reset to empty on process restart. Presence state is
     * re-populated as presence events arrive from the relay after reconnection.
     */
    val onlineDevices: StateFlow<Set<String>> = _onlineDevices.asStateFlow()

    /**
     * Updates the presence status for a device identified by [deviceId].
     *
     * Called by the [com.zaptransfer.android.webrtc.SignalingListener] when a
     * `{type:"presence", deviceId, online}` message arrives from the relay.
     *
     * This is NOT a suspend function — it uses [MutableStateFlow.update] which is
     * safe to call from any thread, including OkHttp's reader thread.
     *
     * @param deviceId The relay-registered 22-char device ID.
     * @param isOnline true if the device just came online; false if it went offline.
     */
    fun handlePresence(deviceId: String, isOnline: Boolean) {
        _onlineDevices.update { current ->
            if (isOnline) {
                Log.d(TAG, "Device $deviceId online")
                current + deviceId
            } else {
                Log.d(TAG, "Device $deviceId offline")
                current - deviceId
            }
        }
    }

    // ── Persistent device CRUD ────────────────────────────────────────────────

    /**
     * Observes all paired devices, ordered by name ascending.
     *
     * Returns a [Flow] that emits a new list every time any row in the
     * paired_devices table changes. The flow never completes unless the
     * database connection is closed.
     *
     * @return Reactive stream of all [PairedDeviceEntity] rows.
     */
    fun observePairedDevices(): Flow<List<PairedDeviceEntity>> = dao.getAll()

    /**
     * Inserts a newly paired device into the database.
     *
     * Uses the DAO's REPLACE conflict strategy, so calling this with an existing
     * [deviceId] overwrites the old record (handles re-pair after key rotation).
     *
     * Must be called from a coroutine context.
     *
     * @param device Fully populated [PairedDeviceEntity] from the pairing ceremony.
     */
    suspend fun addDevice(device: PairedDeviceEntity) {
        dao.insert(device)
        Log.d(TAG, "Device ${device.deviceId} (${device.name}) added to Room")
    }

    /**
     * Removes a paired device (unpair).
     *
     * Deletes the row by device ID. Any [TransferHistoryEntity] rows referencing
     * this device have their device_id column set to NULL via the FK ON DELETE
     * SET NULL rule (defined in [TransferHistoryEntity]).
     *
     * Must be called from a coroutine context.
     *
     * @param deviceId The 22-char stable device ID of the device to remove.
     */
    suspend fun removeDevice(deviceId: String) {
        dao.deleteById(deviceId)
        // Also remove from in-memory presence set
        _onlineDevices.update { it - deviceId }
        Log.d(TAG, "Device $deviceId unpaired and removed from Room")
    }

    /**
     * Renames a paired device and/or changes its icon.
     *
     * @param device Updated [PairedDeviceEntity] with the same [deviceId] as an
     *               existing row but with modified [name] or [icon].
     */
    suspend fun updateDevice(device: PairedDeviceEntity) {
        dao.update(device)
        Log.d(TAG, "Device ${device.deviceId} updated: name=${device.name} icon=${device.icon}")
    }

    /**
     * Looks up a single paired device by ID without subscribing to changes.
     *
     * Returns null if the device is not paired. Suitable for one-time lookups
     * in background operations where a [Flow] would be overly complex.
     *
     * Must be called from a coroutine context.
     *
     * @param deviceId The 22-char stable device ID.
     * @return The [PairedDeviceEntity] if found; null otherwise.
     */
    suspend fun getDevice(deviceId: String): PairedDeviceEntity? {
        return dao.getByIdOnce(deviceId)
    }

    /**
     * Snapshot of all paired devices. Used by the Beam v2 transport on
     * incoming frames so it can try each peer's K_AB until one decrypts.
     */
    suspend fun listDevices(): List<PairedDeviceEntity> = dao.listAll()

    /**
     * Update only the Beam v2 K_AB ring JSON for a device. Used when
     * rotation completes (rotate-commit): the transport hands us a new
     * ring shape and we persist it without rewriting the rest of the row.
     */
    suspend fun updateKABRing(deviceId: String, kABRingJson: String) {
        dao.updateKABRingJson(deviceId, kABRingJson)
    }

    /**
     * Returns true if there are no paired devices.
     *
     * Used by the Device Hub to decide whether to show the onboarding empty state
     * or the device list.
     *
     * Must be called from a coroutine context.
     */
    suspend fun isEmpty(): Boolean = dao.count() == 0
}
