package com.zaptransfer.android.data.db.entity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the primary-key uniqueness contract for failed-send audit rows.
 *
 * Regression: history rows were inserted with `transferId = ""`, which is the
 * PK under OnConflictStrategy.IGNORE — so two failed sends collided and the
 * second was silently dropped. [TransferHistoryEntity.failedSent] must mint a
 * distinct, non-empty key per row.
 */
class TransferHistoryEntityTest {

    @Test
    fun `failedSent generates distinct non-empty primary keys`() {
        val a = TransferHistoryEntity.failedSent(
            deviceId = "peerA", fileName = "a.txt", fileSizeBytes = 0L,
            mimeType = "text/plain", localUri = "content://x", startedAt = 100L, completedAt = 200L,
        )
        val b = TransferHistoryEntity.failedSent(
            deviceId = "peerA", fileName = "a.txt", fileSizeBytes = 0L,
            mimeType = "text/plain", localUri = "content://x", startedAt = 100L, completedAt = 200L,
        )

        assertTrue("primary key must be non-empty", a.transferId.isNotEmpty())
        assertTrue("primary key must be non-empty", b.transferId.isNotEmpty())
        // Two failed sends of the same file must not share a PK, or the second
        // is dropped by the IGNORE-conflict insert.
        assertNotEquals(a.transferId, b.transferId)

        assertEquals("SENT", a.direction)
        assertEquals("FAILED", a.status)
    }
}
