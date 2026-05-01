package com.zaptransfer.android.data.db.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for the paired_devices table.
 *
 * All read operations return [Flow] so the Device Hub UI reactively updates
 * when pairing or unpair actions occur without polling.
 *
 * Insert uses REPLACE conflict strategy so a re-pair (e.g. after key rotation)
 * seamlessly overwrites stale key material for the same deviceId.
 */
@Dao
interface PairedDeviceDao {

    /**
     * Observe the full list of paired devices, ordered by name ascending.
     * Emits a new list whenever any row in paired_devices changes.
     */
    @Query("SELECT * FROM paired_devices ORDER BY name ASC")
    fun getAll(): Flow<List<PairedDeviceEntity>>

    /**
     * Observe a single paired device by its stable [deviceId].
     * Returns null if no device with that ID is paired.
     */
    @Query("SELECT * FROM paired_devices WHERE device_id = :deviceId")
    fun getById(deviceId: String): Flow<PairedDeviceEntity?>

    /**
     * Synchronous single-shot lookup — used from background threads where a
     * suspend function would require an explicit coroutine scope.
     * Returns null if not found.
     */
    @Query("SELECT * FROM paired_devices WHERE device_id = :deviceId LIMIT 1")
    suspend fun getByIdOnce(deviceId: String): PairedDeviceEntity?

    /**
     * Insert or replace a device record.
     * REPLACE handles the re-pair case where the same deviceId gets fresh keys.
     * Returns the row ID of the inserted/replaced record.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(device: PairedDeviceEntity): Long

    /**
     * Update an existing device record (e.g. rename or change icon after initial pairing).
     * Has no effect if the device row no longer exists.
     */
    @Update
    suspend fun update(device: PairedDeviceEntity)

    /**
     * Update only the [lastSeenAt] timestamp for presence tracking.
     * More efficient than a full Update when only presence changes.
     */
    @Query("UPDATE paired_devices SET last_seen_at = :lastSeenAt WHERE device_id = :deviceId")
    suspend fun updateLastSeen(deviceId: String, lastSeenAt: Long)

    /**
     * Update only the Beam v2 K_AB generation ring (serialised JSON).
     * Called by the transport on key rotation to swap in a new generation.
     */
    @Query("UPDATE paired_devices SET k_ab_ring_json = :kABRingJson WHERE device_id = :deviceId")
    suspend fun updateKABRingJson(deviceId: String, kABRingJson: String)

    /** Snapshot list — used by the v2 transport to try every K_AB on incoming frames. */
    @Query("SELECT * FROM paired_devices")
    suspend fun listAll(): List<PairedDeviceEntity>

    /**
     * Delete a paired device (unpair).
     * Transfer history rows referencing this device have their device_id set to NULL
     * via the FK ON DELETE SET NULL rule.
     */
    @Delete
    suspend fun delete(device: PairedDeviceEntity)

    /**
     * Delete by device ID without requiring the full entity — convenience for
     * unpair actions that only have the ID available.
     */
    @Query("DELETE FROM paired_devices WHERE device_id = :deviceId")
    suspend fun deleteById(deviceId: String)

    /** Returns the total number of paired devices. Used for empty-state detection. */
    @Query("SELECT COUNT(*) FROM paired_devices")
    suspend fun count(): Int
}
