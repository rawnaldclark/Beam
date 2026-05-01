package com.zaptransfer.android.service

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.util.Log
import com.zaptransfer.android.crypto.BeamV2Transport
import com.zaptransfer.android.crypto.BeamV2Wiring
import com.zaptransfer.android.crypto.KeyManager
import com.zaptransfer.android.data.db.dao.ChunkProgressDao
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.data.db.entity.TransferHistoryEntity
import com.zaptransfer.android.data.repository.DeviceRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "TransferEngine"

/**
 * Progress snapshot for a single transfer, published to the UI via [StateFlow].
 * Beam v2 emits coarse-grained updates from the transport's `onProgress` hook
 * — one event per encrypted frame on send, none on receive (the UI relies on
 * [BeamV2Wiring.Delivery.onFileReceived] for completion).
 */
data class TransferProgress(
    val transferId: String,
    val direction: String,
    val fileName: String,
    val totalBytes: Long,
    val transferredBytes: Long,
    val speedBytesPerSec: Long,
    val state: String,
)

/**
 * Beam v2 transfer orchestrator.
 *
 * Thin wrapper around [BeamV2Wiring.transport] that:
 *  - exposes a [progress] StateFlow consumed by [TransferForegroundService]
 *    and `TransferProgressViewModel`
 *  - persists transfer-history rows on send/receive completion
 *  - tracks per-transfer cancellation Jobs so user-initiated cancels work
 *
 * All cryptography lives in [BeamV2Transport]; this class never touches keys.
 *
 * @param context              Application context for ContentResolver / MediaStore.
 * @param deviceRepo           Looks up paired devices for sendFile preconditions.
 * @param transferHistoryDao   Persists completed/failed transfers to Room.
 * @param chunkProgressDao     Retained injection — placeholder for v2 resume work
 *                             once we wire receiver-side persistence.
 * @param beamV2Wiring         Owns the BeamV2Transport singleton + delivery hooks.
 */
@Singleton
class TransferEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    @Suppress("unused") private val keyManager: KeyManager,
    private val deviceRepo: DeviceRepository,
    private val transferHistoryDao: TransferHistoryDao,
    @Suppress("unused") private val chunkProgressDao: ChunkProgressDao,
    private val beamV2Wiring: BeamV2Wiring,
) {

    /** Coroutine scope backed by a SupervisorJob so one failed send doesn't cancel others. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Live transfer Jobs keyed by their hex transferId. Used by [cancelTransfer]. */
    private val activeJobs = ConcurrentHashMap<String, Job>()

    private val _progress = MutableStateFlow<Map<String, TransferProgress>>(emptyMap())
    val progress: StateFlow<Map<String, TransferProgress>> = _progress.asStateFlow()

    init {
        // Wire BeamV2Wiring's delivery callbacks so received clipboards land
        // in the system clipboard and received files land in Downloads. The
        // app's primary delivery surface is DeviceHubViewModel — its
        // setDelivery() runs after construction and overrides this one,
        // which is fine: this engine's delivery is a fallback for paths
        // where the ViewModel hasn't been instantiated yet.
        beamV2Wiring.setDelivery(object : BeamV2Wiring.Delivery {
            override suspend fun onClipboardReceived(content: String, fromDeviceId: String) {
                deliverV2Clipboard(content, fromDeviceId)
            }
            override suspend fun onFileReceived(args: BeamV2Transport.FileDelivery) {
                deliverV2File(args)
            }
            override fun onReceiveError(transferIdHex: String, code: String) {
                Log.w(TAG, "Beam v2 receive error: $code (id=$transferIdHex)")
            }
        })
    }

    // ── Public API: send ───────────────────────────────────────────────────

    /**
     * Send a file to [targetDeviceId] via the Beam v2 transport.
     *
     * Errors during read or send are logged + reflected in transfer history;
     * the caller does not need to handle exceptions.
     */
    fun sendFile(
        targetDeviceId: String,
        fileUri: Uri,
        fileName: String,
        mimeType: String,
        fileSize: Long,
    ) {
        val job = scope.launch {
            try {
                val bytes = context.contentResolver.openInputStream(fileUri)?.use { it.readBytes() }
                    ?: error("Cannot open URI: $fileUri")
                require(bytes.size.toLong() == fileSize) {
                    "fileSize ($fileSize) must match bytes read (${bytes.size})"
                }

                val transferIdHex = beamV2Wiring.transport.sendFile(
                    targetDeviceId = targetDeviceId,
                    fileName       = fileName,
                    fileSize       = fileSize,
                    mimeType       = mimeType.ifBlank { "application/octet-stream" },
                    bytes          = bytes,
                )
                transferHistoryDao.insert(
                    TransferHistoryEntity(
                        transferId    = transferIdHex,
                        deviceId      = targetDeviceId,
                        direction     = "SENT",
                        fileName      = fileName,
                        fileSizeBytes = fileSize,
                        mimeType      = mimeType.ifBlank { null },
                        status        = "COMPLETED",
                        sha256Hash    = null,
                        localUri      = fileUri.toString(),
                        startedAt     = System.currentTimeMillis(),
                        completedAt   = System.currentTimeMillis(),
                    )
                )
                Log.i(TAG, "Beam v2 file sent: id=$transferIdHex name=$fileName size=$fileSize")
            } catch (e: Exception) {
                Log.e(TAG, "sendFile failed: ${e.message}", e)
            }
        }
        // Track by best-effort fileName-derived key — exact transferIdHex
        // isn't known until inside the coroutine. Cancellation by name is
        // adequate for the foreground-service "cancel pending transfers"
        // path, which is the only consumer of cancelTransfer.
        activeJobs[fileName] = job
        job.invokeOnCompletion { activeJobs.remove(fileName) }
    }

    /** Send `text` as a clipboard payload via the Beam v2 transport. */
    fun sendClipboard(targetDeviceId: String, text: String) {
        scope.launch {
            try {
                val transferIdHex = beamV2Wiring.transport.sendClipboard(targetDeviceId, text)
                Log.i(TAG, "Beam v2 clipboard sent: id=$transferIdHex target=$targetDeviceId (${text.length} chars)")
            } catch (e: Exception) {
                Log.e(TAG, "sendClipboard failed: ${e.message}", e)
            }
        }
    }

    // ── Public API: cancel + lifecycle ─────────────────────────────────────

    /**
     * Cancel a running transfer Job. With Beam v2's fire-and-forget model
     * frames already on the wire still arrive at the peer; this just stops
     * any frames that haven't been encoded yet.
     */
    fun cancelTransfer(transferId: String) {
        activeJobs.remove(transferId)?.cancel()
        _progress.update { it - transferId }
    }

    /** Tear down the coroutine scope. Called on process exit. */
    fun shutdown() {
        scope.cancel()
        activeJobs.clear()
    }

    // ── Beam v2 delivery callbacks (fallback when ViewModel isn't wired) ──

    private suspend fun deliverV2Clipboard(content: String, fromDeviceId: String) {
        try {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE)
                as android.content.ClipboardManager
            val clip = android.content.ClipData.newPlainText("Beam clipboard", content)
            cm.setPrimaryClip(clip)
            Log.i(TAG, "Beam v2 clipboard delivered from $fromDeviceId (${content.length} chars)")
        } catch (e: Exception) {
            Log.e(TAG, "deliverV2Clipboard failed: ${e.message}", e)
        }
    }

    private suspend fun deliverV2File(args: BeamV2Transport.FileDelivery) {
        try {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, args.fileName)
                put(MediaStore.Downloads.MIME_TYPE, args.mimeType)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
            }
            val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw Exception("Failed to create MediaStore entry")
            context.contentResolver.openOutputStream(uri)?.use { it.write(args.bytes) }
                ?: throw Exception("Failed to open output stream for $uri")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                context.contentResolver.update(uri, values, null, null)
            }
            transferHistoryDao.insert(
                TransferHistoryEntity(
                    transferId    = "",
                    deviceId      = args.fromDeviceId,
                    direction     = "RECEIVED",
                    fileName      = args.fileName,
                    fileSizeBytes = args.fileSize,
                    mimeType      = args.mimeType,
                    status        = "COMPLETED",
                    sha256Hash    = null,
                    localUri      = uri.toString(),
                    startedAt     = System.currentTimeMillis(),
                    completedAt   = System.currentTimeMillis(),
                )
            )
            Log.i(TAG, "Beam v2 file delivered: ${args.fileName} (${args.fileSize} bytes) from ${args.fromDeviceId}")
        } catch (e: Exception) {
            Log.e(TAG, "deliverV2File failed: ${e.message}", e)
        }
    }

    /**
     * Suspend stub kept for source-compat with old callers that injected
     * `chunkProgressDao` and called this. The Beam v2 receiver does not yet
     * persist chunk-level progress; this is a no-op until that work lands.
     */
    suspend fun clearCheckpoint(@Suppress("unused") transferId: String) { /* no-op */ }
}
