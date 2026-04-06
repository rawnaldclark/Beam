package com.zaptransfer.android.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.zaptransfer.android.MainActivity
import com.zaptransfer.android.util.NotificationChannels
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject

private const val TAG = "TransferForegroundService"

/**
 * Notification IDs — must be stable across service restarts so the OS updates the
 * existing notification rather than posting a new one.
 */
private const val NOTIF_ID_PROGRESS = 1001
private const val NOTIF_ID_COMPLETE = 1002

/** Actions embedded in PendingIntents for the cancel and complete notification buttons. */
const val ACTION_CANCEL_TRANSFER = "com.zaptransfer.android.ACTION_CANCEL_TRANSFER"
const val ACTION_OPEN_FILE = "com.zaptransfer.android.ACTION_OPEN_FILE"

/**
 * Foreground service that keeps active file transfers alive while the app is in the
 * background. Shows a persistent progress notification so the user is always aware
 * of ongoing transfers and can cancel them without returning to the app.
 *
 * ## Android 14 / API 34+ compliance
 *  - Declared in the manifest with `android:foregroundServiceType="dataSync"`.
 *  - [FOREGROUND_SERVICE_TYPE_DATA_SYNC] flag passed to [startForeground] to satisfy
 *    the type-must-match requirement (ForegroundServiceTypeMismatchException otherwise).
 *
 * ## Lifecycle
 *  1. [ZapTransferApplication] calls `startForegroundService(intent)` when there are
 *     incomplete transfers at startup (crash recovery).
 *  2. [TransferEngine] starts the service before initiating or receiving a transfer.
 *  3. This service subscribes to [TransferEngine.progress] and rebuilds the notification
 *     on every meaningful state change.
 *  4. [stopSelf] is called when the progress map becomes empty (no active transfers).
 *
 * ## Notification content
 *  - **Progress**: filename, peer, percentage bar, speed (MB/s), cancel button.
 *  - **Complete**: filename, "SHA-256 verified", open/save actions.
 *  - **Failed**: filename, error reason, dismiss button.
 *
 * @see WakeLockManager for CPU + Wi-Fi lock management during transfers.
 * @see NotificationChannels for channel IDs.
 */
@AndroidEntryPoint
class TransferForegroundService : LifecycleService() {

    @Inject
    lateinit var transferEngine: TransferEngine

    /** Holds CPU wake lock + Wi-Fi high-perf lock for the transfer duration. */
    private lateinit var wakeLockManager: WakeLockManager

    private lateinit var notificationManager: NotificationManager

    // ── Service lifecycle ─────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        wakeLockManager = WakeLockManager(applicationContext)
        notificationManager = getSystemService(NotificationManager::class.java)

        Log.d(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)

        when (intent?.action) {
            ACTION_CANCEL_TRANSFER -> {
                // Cancel button in the progress notification
                val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID)
                if (transferId != null) {
                    Log.d(TAG, "Cancel requested for transferId=$transferId")
                    transferEngine.cancelTransfer(transferId)
                }
                return START_NOT_STICKY
            }
        }

        // Acquire wake + wifi locks before doing any work
        wakeLockManager.acquire()

        // Start the service in the foreground immediately with an initial placeholder
        // notification. Must happen within 5 seconds of startForegroundService() on API 26+,
        // or within the ANR window on API 34+.
        val initialNotification = buildProgressNotification(
            fileName = "Preparing transfer…",
            peerName = "",
            progressPercent = 0,
            speedMBs = 0f,
            transferId = "",
        )

        // Android 14 (API 34): must pass FOREGROUND_SERVICE_TYPE_DATA_SYNC.
        // On older APIs, the no-arg overload is used automatically by AndroidX.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID_PROGRESS,
                initialNotification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIF_ID_PROGRESS, initialNotification)
        }

        // Subscribe to engine progress and update the notification on every change.
        observeProgress()

        return START_STICKY
    }

    override fun onDestroy() {
        wakeLockManager.release()
        Log.d(TAG, "Service destroyed — wake locks released")
        super.onDestroy()
    }

    override fun onBind(intent: Intent): IBinder? = null

    // ── Progress observation ──────────────────────────────────────────────────

    /**
     * Collects [TransferEngine.progress] on the service's lifecycle scope.
     *
     * Strategy:
     *  - One active transfer: show that transfer's progress notification.
     *  - Multiple active transfers: show aggregate (N transfers, total bytes).
     *  - No active transfers: stop the service (removes the notification automatically).
     *  - Any terminal COMPLETE state: post a separate alert notification with actions.
     */
    private fun observeProgress() {
        lifecycleScope.launch {
            transferEngine.progress.collectLatest { progressMap ->
                if (progressMap.isEmpty()) {
                    Log.d(TAG, "No active transfers — stopping foreground service")
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@collectLatest
                }

                // Find the most prominent in-progress entry to feature in the notification
                val active = progressMap.values.filter { it.state == "TRANSFERRING" || it.state == "REQUESTING" }
                val completed = progressMap.values.filter { it.state == "COMPLETE" }
                val failed = progressMap.values.filter { it.state == "FAILED" }

                // Post completion alert notifications (separate channel so they make sound)
                completed.forEach { prog ->
                    notificationManager.notify(
                        prog.transferId.hashCode(),
                        buildCompleteNotification(prog.fileName, prog.transferId),
                    )
                }

                // Post failure notifications
                failed.forEach { prog ->
                    notificationManager.notify(
                        prog.transferId.hashCode(),
                        buildFailedNotification(prog.fileName),
                    )
                }

                // Update the persistent foreground notification for in-progress transfers
                if (active.isNotEmpty()) {
                    val primary = active.first()
                    val speedMBs = primary.speedBytesPerSec / 1_048_576f
                    val percent = if (primary.totalBytes > 0) {
                        ((primary.transferredBytes.toFloat() / primary.totalBytes) * 100).toInt()
                    } else 0

                    val notification = buildProgressNotification(
                        fileName = primary.fileName,
                        peerName = primary.direction,  // direction ("send"/"receive") as context
                        progressPercent = percent,
                        speedMBs = speedMBs,
                        transferId = primary.transferId,
                    )
                    notificationManager.notify(NOTIF_ID_PROGRESS, notification)
                }
            }
        }
    }

    // ── Notification builders ─────────────────────────────────────────────────

    /**
     * Builds the persistent foreground progress notification.
     *
     * Uses [NotificationChannels.CHANNEL_TRANSFER_PROGRESS] (LOW importance — no sound).
     * Includes a [ACTION_CANCEL_TRANSFER] PendingIntent on the cancel action.
     *
     * @param fileName       Original filename to display.
     * @param peerName       Peer device name or direction hint for the sub-text.
     * @param progressPercent 0–100 integer for the progress bar.
     * @param speedMBs       Current throughput in MB/s.
     * @param transferId     Transfer UUID for the cancel action.
     */
    private fun buildProgressNotification(
        fileName: String,
        peerName: String,
        progressPercent: Int,
        speedMBs: Float,
        transferId: String,
    ): Notification {
        // Tap notification → open MainActivity to the transfer progress screen
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
                putExtra(EXTRA_TRANSFER_ID, transferId)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        // Cancel action — sends ACTION_CANCEL_TRANSFER back to this service
        val cancelIntent = PendingIntent.getService(
            this,
            transferId.hashCode(),
            Intent(this, TransferForegroundService::class.java).apply {
                action = ACTION_CANCEL_TRANSFER
                putExtra(EXTRA_TRANSFER_ID, transferId)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val speedText = if (speedMBs > 0) " · %.1f MB/s".format(speedMBs) else ""
        val subText = if (peerName.isNotBlank()) peerName else ""

        return NotificationCompat.Builder(this, NotificationChannels.CHANNEL_TRANSFER_PROGRESS)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(fileName.ifBlank { "Transferring…" })
            .setContentText("$progressPercent%$speedText")
            .setSubText(subText.ifBlank { null })
            .setProgress(100, progressPercent, progressPercent == 0)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentIntent)
            .addAction(
                android.R.drawable.ic_delete,
                "Cancel",
                cancelIntent,
            )
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .build()
    }

    /**
     * Builds a one-shot completion notification posted to [NotificationChannels.CHANNEL_TRANSFER_ALERTS].
     *
     * Actions:
     *  - "Open File": deep-link into MainActivity with the transfer ID so the
     *    [TransferCompleteSheet] is shown.
     *  - "Dismiss": auto-cancelled when the user taps this action (handled by the
     *    notification itself via auto-cancel).
     *
     * @param fileName   Original filename.
     * @param transferId Transfer UUID for deep-link.
     */
    private fun buildCompleteNotification(fileName: String, transferId: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            transferId.hashCode(),
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
                action = ACTION_OPEN_FILE
                putExtra(EXTRA_TRANSFER_ID, transferId)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, NotificationChannels.CHANNEL_TRANSFER_ALERTS)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Transfer Complete")
            .setContentText("$fileName · SHA-256 verified")
            .setAutoCancel(true)
            .setContentIntent(openIntent)
            .addAction(
                android.R.drawable.ic_menu_view,
                "Open File",
                openIntent,
            )
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .build()
    }

    /**
     * Builds a one-shot failure notification.
     *
     * @param fileName Original filename that failed to transfer.
     */
    private fun buildFailedNotification(fileName: String): Notification {
        return NotificationCompat.Builder(this, NotificationChannels.CHANNEL_TRANSFER_ALERTS)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("Transfer Failed")
            .setContentText(fileName)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .build()
    }

    companion object {
        /** Intent extra carrying the transfer UUID for cancel + open actions. */
        const val EXTRA_TRANSFER_ID = "extra_transfer_id"

        /**
         * Extra flag: when true, the service should query [ChunkProgressDao] and
         * resume all incomplete transfers from their last checkpoint.
         */
        const val EXTRA_RESUME = "extra_resume"
    }
}
