package com.zaptransfer.android.util

import android.content.Context
import android.util.Log
import com.zaptransfer.android.data.db.dao.ChunkProgressDao
import java.io.File

private const val TAG = "FileUtil"

/** Transfers abandoned more than this many milliseconds ago are considered stale. */
private const val STALE_THRESHOLD_MS = 24L * 60L * 60L * 1_000L  // 24 hours

/**
 * File-system utility functions for the Beam application.
 *
 * All functions in this object operate on the app's cache directory and are
 * designed to be called from a background (IO) coroutine.
 */
object FileUtil {

    /**
     * Removes partial reassembly files for abandoned or crashed transfers.
     *
     * ## Algorithm
     *  1. Compute a cutoff timestamp: `now - 24 hours`.
     *  2. Query [ChunkProgressDao] for rows whose `updated_at` is older than the cutoff.
     *  3. For each stale row: delete the [ChunkProgressEntity.tempFilePath] file on disk.
     *  4. Delete all stale rows from the DB via [ChunkProgressDao.deleteStale].
     *
     * Called once during [com.zaptransfer.android.ZapTransferApplication.onCreate] before
     * the crash-recovery scan, ensuring the recovery scan only returns genuinely resumable
     * transfers.
     *
     * ## Edge cases
     *  - Missing temp file (already deleted manually or by the OS): logged and skipped.
     *  - DB delete succeeds even if file delete fails (best-effort disk cleanup).
     *  - Very large temp files left by abandoned transfers are removed promptly on next launch.
     *
     * @param context           Application context for resolving the cache directory.
     * @param chunkProgressDao  DAO to query and delete stale checkpoint rows.
     */
    suspend fun cleanupStalePartials(context: Context, chunkProgressDao: ChunkProgressDao) {
        val cutoffTime = System.currentTimeMillis() - STALE_THRESHOLD_MS
        Log.d(TAG, "Cleaning up stale partial files (cutoff=${cutoffTime})")

        try {
            // Fetch stale rows before deleting so we can remove the associated files
            val allIncomplete = chunkProgressDao.getIncomplete()
            val stale = allIncomplete.filter { it.updatedAt < cutoffTime }

            var filesDeleted = 0
            var filesMissing = 0

            stale.forEach { entity ->
                val tempFile = File(entity.tempFilePath)
                if (tempFile.exists()) {
                    if (tempFile.delete()) {
                        filesDeleted++
                        Log.d(TAG, "Deleted stale temp file: ${entity.tempFilePath}")
                    } else {
                        Log.w(TAG, "Failed to delete stale temp file: ${entity.tempFilePath}")
                    }
                } else {
                    filesMissing++
                    Log.d(TAG, "Stale temp file already absent: ${entity.tempFilePath}")
                }
            }

            // Delete all stale DB rows in one query (more efficient than per-row delete)
            chunkProgressDao.deleteStale(cutoffTime)

            Log.i(
                TAG,
                "Stale cleanup complete: ${stale.size} rows removed, " +
                    "$filesDeleted files deleted, $filesMissing already absent"
            )
        } catch (e: Exception) {
            // Non-fatal: log and continue — a failed cleanup on this launch will
            // succeed on a subsequent launch once the files age past the threshold.
            Log.e(TAG, "cleanupStalePartials failed: ${e.message}", e)
        }
    }

    /**
     * Deletes a specific temp file from disk by its absolute path.
     *
     * Safe to call with a null or non-existent path — returns false in those cases.
     *
     * @param path Absolute path to the file to delete.
     * @return true if the file was deleted, false if it did not exist or deletion failed.
     */
    fun deleteTempFile(path: String?): Boolean {
        if (path.isNullOrBlank()) return false
        return try {
            val file = File(path)
            if (file.exists()) file.delete() else false
        } catch (e: Exception) {
            Log.w(TAG, "deleteTempFile failed for path=$path: ${e.message}")
            false
        }
    }

    /**
     * Deletes all files in the `transfer_tmp` cache subdirectory.
     *
     * Should only be called if the caller is certain no active transfers are using
     * the temp directory. In normal operation, prefer [cleanupStalePartials].
     *
     * @param context Application context.
     * @return Number of files deleted.
     */
    fun nukeAllTempFiles(context: Context): Int {
        val tempDir = File(context.cacheDir, "transfer_tmp")
        if (!tempDir.exists()) return 0

        var count = 0
        tempDir.listFiles()?.forEach { file ->
            if (file.delete()) count++
        }
        Log.d(TAG, "nukeAllTempFiles: deleted $count files")
        return count
    }
}
