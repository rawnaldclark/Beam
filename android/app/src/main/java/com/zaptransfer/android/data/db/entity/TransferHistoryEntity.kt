package com.zaptransfer.android.data.db.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import java.util.UUID

/**
 * Immutable audit record written once a transfer reaches a terminal state
 * (COMPLETED, FAILED, or CANCELLED).
 *
 * The record is never updated after creation — [status] transitions are
 * handled in memory by the TransferEngine and only the final state is persisted.
 * Exception: [completedAt] and [localUri] are filled in on success.
 *
 * [localUri] is a content:// or file:// URI that survives file moves — do NOT
 * store an absolute path here because the Downloads provider may rename files.
 *
 * This table is indexed by [deviceId] for fast per-device history queries,
 * and by [startedAt] DESC for the "recent transfers" list on the Device Hub.
 */
@Entity(
    tableName = "transfer_history",
    foreignKeys = [
        ForeignKey(
            entity = PairedDeviceEntity::class,
            parentColumns = ["device_id"],
            childColumns = ["device_id"],
            // Keep history even if device is unpaired — use SET_NULL so records survive
            onDelete = ForeignKey.SET_NULL,
        )
    ],
    indices = [
        Index("device_id"),
        Index("started_at"),
    ]
)
data class TransferHistoryEntity(

    /** UUID v4 string assigned by the sender at transfer initiation. */
    @PrimaryKey
    @ColumnInfo(name = "transfer_id")
    val transferId: String,

    /**
     * Device ID of the remote peer.
     * Nullable because a paired device may be deleted while history is retained.
     */
    @ColumnInfo(name = "device_id")
    val deviceId: String?,

    /**
     * Transfer direction relative to this device.
     * Valid values: "SENT", "RECEIVED".
     */
    @ColumnInfo(name = "direction")
    val direction: String,

    /** Original file name as reported in the transfer metadata envelope. */
    @ColumnInfo(name = "file_name")
    val fileName: String,

    /** Exact byte count from the metadata envelope (before chunking/padding). */
    @ColumnInfo(name = "file_size_bytes")
    val fileSizeBytes: Long,

    /** MIME type from metadata, e.g. "image/png". Null for clipboard text transfers. */
    @ColumnInfo(name = "mime_type")
    val mimeType: String?,

    /**
     * Terminal transfer status.
     * Valid values: "COMPLETED", "FAILED", "CANCELLED".
     */
    @ColumnInfo(name = "status")
    val status: String,

    /**
     * Lowercase hex SHA-256 of the complete file as computed by the receiver's HashAccumulator.
     * Null on failure/cancellation. Verified against sender's hash from the metadata envelope.
     */
    @ColumnInfo(name = "sha256_hash")
    val sha256Hash: String?,

    /**
     * Content URI or file URI of the saved file.
     * Null if transfer failed, was cancelled, or was a clipboard-only transfer.
     */
    @ColumnInfo(name = "local_uri")
    val localUri: String?,

    /** Unix epoch milliseconds when the transfer engine transitioned from IDLE → REQUESTING. */
    @ColumnInfo(name = "started_at")
    val startedAt: Long,

    /** Unix epoch milliseconds when status reached a terminal state. Null until then. */
    @ColumnInfo(name = "completed_at")
    val completedAt: Long? = null,
) {
    companion object {
        /**
         * Build a FAILED "SENT" audit row with a fresh unique primary key.
         *
         * A pre-flight-failed send never received a real transferId, so callers
         * used to pass `""` — but `transfer_id` is the PK under
         * [androidx.room.OnConflictStrategy.IGNORE], so the second `""` row
         * collided with the first and was silently dropped, hiding every failed
         * send after the first. Minting a UUID keeps each failed row distinct.
         */
        fun failedSent(
            deviceId: String,
            fileName: String,
            fileSizeBytes: Long,
            mimeType: String?,
            localUri: String?,
            startedAt: Long,
            completedAt: Long,
        ): TransferHistoryEntity = TransferHistoryEntity(
            transferId    = UUID.randomUUID().toString(),
            deviceId      = deviceId,
            direction     = "SENT",
            fileName      = fileName,
            fileSizeBytes = fileSizeBytes,
            mimeType      = mimeType,
            status        = "FAILED",
            sha256Hash    = null,
            localUri      = localUri,
            startedAt     = startedAt,
            completedAt   = completedAt,
        )
    }
}
