package com.zaptransfer.android

import android.app.Application
import android.content.Intent
import android.util.Log
import com.zaptransfer.android.data.db.dao.ChunkProgressDao
import com.zaptransfer.android.service.TransferForegroundService
import com.zaptransfer.android.util.FileUtil
import com.zaptransfer.android.util.NotificationChannels
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

private const val TAG = "ZapTransferApplication"

/**
 * Application entry point for Beam / ZapTransfer.
 *
 * Annotated with [@HiltAndroidApp] which triggers Hilt's code generation:
 *  - Creates the application-scoped component (AppComponent).
 *  - Injects @Singleton-scoped dependencies on first use.
 *
 * Responsibilities in [onCreate]:
 *  1. Register notification channels (idempotent — safe on every cold start).
 *  2. Delete stale partial files from crashed or abandoned transfers (>24 h old).
 *  3. Query [ChunkProgressDao] for incomplete transfers and restart
 *     [TransferForegroundService] to resume from the last checkpoint.
 *     This handles process-death recovery per spec §8.4.
 *
 * Declared in AndroidManifest.xml as:
 * ```xml
 * <application android:name=".ZapTransferApplication" ...>
 * ```
 */
@HiltAndroidApp
class ZapTransferApplication : Application() {

    /**
     * DAO for chunk resume checkpoints. Injected by Hilt after [onCreate] is called.
     *
     * NOTE: Hilt field injection is performed AFTER super.onCreate() returns, so
     * [chunkProgressDao] is available immediately after [super.onCreate] in this class.
     */
    @Inject
    lateinit var chunkProgressDao: ChunkProgressDao

    /**
     * Application-scoped coroutine scope. Survives as long as the process lives.
     * Uses [SupervisorJob] so individual startup tasks don't cancel each other.
     */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()

        // Step 1: Register TRANSFER_PROGRESS and TRANSFER_ALERTS notification channels.
        // Must run before any foreground service or notification is posted.
        NotificationChannels.create(this)

        // Steps 2 & 3 run on the IO dispatcher to avoid blocking the main thread.
        appScope.launch {
            // Step 2: Clean up stale partial files from transfers abandoned >24 h ago.
            // This frees cache space and removes orphaned Room rows. Must run before the
            // recovery scan below so getIncomplete() only returns resumable transfers.
            FileUtil.cleanupStalePartials(applicationContext, chunkProgressDao)

            // Step 3: Crash recovery — resume any incomplete transfers left by a previous
            // process death. If there are incomplete checkpoints, start the foreground
            // service with the EXTRA_RESUME flag so it can re-initiate those sessions.
            val incomplete = chunkProgressDao.getIncomplete()
            if (incomplete.isNotEmpty()) {
                Log.i(TAG, "Found ${incomplete.size} incomplete transfer(s) — resuming")
                val intent = Intent(this@ZapTransferApplication, TransferForegroundService::class.java)
                    .putExtra(TransferForegroundService.EXTRA_RESUME, true)
                startForegroundService(intent)
            } else {
                Log.d(TAG, "No incomplete transfers found on startup")
            }
        }
    }
}
