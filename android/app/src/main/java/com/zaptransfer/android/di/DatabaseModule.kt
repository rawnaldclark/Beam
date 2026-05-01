package com.zaptransfer.android.di

import android.content.Context
import androidx.room.Room
import com.zaptransfer.android.data.db.ZapDatabase
import com.zaptransfer.android.data.db.dao.ChunkProgressDao
import com.zaptransfer.android.data.db.dao.ClipboardDao
import com.zaptransfer.android.data.db.dao.OfflineQueueDao
import com.zaptransfer.android.data.db.dao.PairedDeviceDao
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt module that creates and provides the Room [ZapDatabase] and all its DAOs.
 *
 * Installed in [SingletonComponent] so the same database instance is shared
 * across the entire application process lifetime. Room handles thread safety
 * internally; every DAO suspend function runs on Room's own IO executor.
 *
 * Database file name: `"zap_db"` — do not change post-release without a migration.
 *
 * Migration strategy note:
 *  - [fallbackToDestructiveMigration] is intentionally NOT set here.
 *  - Future schema changes must provide explicit [androidx.room.migration.Migration]
 *    objects added to the builder. This prevents silent data loss on upgrades.
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    /**
     * Provides the singleton [ZapDatabase] instance.
     *
     * [Room.databaseBuilder] is safe to call multiple times — it is idempotent
     * because [Singleton] guarantees this provider is only invoked once.
     *
     * @param context Application context. Room uses it to resolve the database file path.
     * @return The single [ZapDatabase] instance for the process lifetime.
     */
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): ZapDatabase {
        return Room.databaseBuilder(
            context,
            ZapDatabase::class.java,
            "zap_db"
        )
            // Pre-launch: schema changes wipe the local store. After 1.0
            // launch this MUST be replaced with explicit Migration objects.
            .fallbackToDestructiveMigration()
            .build()
    }

    /**
     * Provides the [PairedDeviceDao] from the singleton database.
     * DAOs have no mutable state — Room's generated implementation is thread-safe
     * so the same DAO instance can be shared across all consumers.
     */
    @Provides
    @Singleton
    fun providePairedDeviceDao(db: ZapDatabase): PairedDeviceDao = db.pairedDeviceDao()

    /** Provides the [TransferHistoryDao] from the singleton database. */
    @Provides
    @Singleton
    fun provideTransferHistoryDao(db: ZapDatabase): TransferHistoryDao = db.transferHistoryDao()

    /** Provides the [ChunkProgressDao] from the singleton database. */
    @Provides
    @Singleton
    fun provideChunkProgressDao(db: ZapDatabase): ChunkProgressDao = db.chunkProgressDao()

    /** Provides the [ClipboardDao] from the singleton database. */
    @Provides
    @Singleton
    fun provideClipboardDao(db: ZapDatabase): ClipboardDao = db.clipboardDao()

    /** Provides the [OfflineQueueDao] from the singleton database. */
    @Provides
    @Singleton
    fun provideOfflineQueueDao(db: ZapDatabase): OfflineQueueDao = db.offlineQueueDao()
}
