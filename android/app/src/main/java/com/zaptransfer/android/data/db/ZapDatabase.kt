package com.zaptransfer.android.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import com.zaptransfer.android.data.db.dao.ChunkProgressDao
import com.zaptransfer.android.data.db.dao.ClipboardDao
import com.zaptransfer.android.data.db.dao.OfflineQueueDao
import com.zaptransfer.android.data.db.dao.PairedDeviceDao
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.data.db.entity.ChunkProgressEntity
import com.zaptransfer.android.data.db.entity.ClipboardEntryEntity
import com.zaptransfer.android.data.db.entity.OfflineQueueEntity
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.db.entity.TransferHistoryEntity

/**
 * Room database for the Beam application.
 *
 * Contains five tables:
 *  - [PairedDeviceEntity]    — trusted remote devices with their public keys.
 *  - [TransferHistoryEntity] — immutable audit log of completed/failed transfers.
 *  - [ChunkProgressEntity]   — resume checkpoints for in-progress receives.
 *  - [ClipboardEntryEntity]  — last-20 clipboard items received from paired devices.
 *  - [OfflineQueueEntity]    — outbound intents queued while target is offline.
 *
 * Migration strategy:
 *  - version = 1 is the initial schema; future migrations will be added to a
 *    `migrations/` list rather than using fallbackToDestructiveMigration.
 *  - Room schema JSON is exported to app/schemas/ (configured via KSP arg in
 *    app/build.gradle.kts) for offline migration validation in CI.
 *
 * Instantiation: provided via Hilt in DatabaseModule (Phase C — not yet created).
 * Usage example:
 * ```kotlin
 * val db = Room.databaseBuilder(context, ZapDatabase::class.java, "zap_db").build()
 * val devices = db.pairedDeviceDao().getAll()
 * ```
 *
 * NOTE: This class must remain abstract — Room generates the concrete implementation.
 */
@Database(
    entities = [
        PairedDeviceEntity::class,
        TransferHistoryEntity::class,
        ChunkProgressEntity::class,
        ClipboardEntryEntity::class,
        OfflineQueueEntity::class,
    ],
    // v2 (2026-04-30): Beam v2 added k_ab_ring_json column to paired_devices.
    // Pre-launch — destructive migration is acceptable. Wire it up in
    // DatabaseModule via fallbackToDestructiveMigration().
    version = 2,
    exportSchema = true,   // Schema JSON written to app/schemas/ — committed to git
)
abstract class ZapDatabase : RoomDatabase() {

    /** Access paired device CRUD operations and presence timestamp updates. */
    abstract fun pairedDeviceDao(): PairedDeviceDao

    /** Access transfer audit log — insert on start, update on completion. */
    abstract fun transferHistoryDao(): TransferHistoryDao

    /**
     * Access chunk resume checkpoints — read at startup for crash recovery,
     * written periodically during active receives.
     */
    abstract fun chunkProgressDao(): ChunkProgressDao

    /** Access clipboard history — last 20 items, capped by repository layer. */
    abstract fun clipboardDao(): ClipboardDao

    /** Access offline queue — outbound intents pending device presence. */
    abstract fun offlineQueueDao(): OfflineQueueDao
}
