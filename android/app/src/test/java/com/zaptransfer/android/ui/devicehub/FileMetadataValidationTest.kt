package com.zaptransfer.android.ui.devicehub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for [validateFileMetadata] — the boundary-enforcement helper
 * that protects the receiver from a malicious paired peer declaring an
 * oversized Beam file transfer.
 *
 * See Beam security audit finding #1 (Android half): without these caps
 * the receiver would blindly trust peer-supplied `fileSize` and
 * `totalChunks` and allocate an attacker-controlled ByteArray on assembly.
 */
class FileMetadataValidationTest {

    private val validMime = "application/octet-stream"
    private val validName = "photo.jpg"

    // ---------- valid boundary ----------

    @Test
    fun `valid metadata at max boundaries returns null`() {
        val result = validateFileMetadata(
            fileName = "a".repeat(MAX_FILENAME_LENGTH),
            fileSize = MAX_FILE_SIZE_BYTES,
            mimeType = validMime,
            totalChunks = MAX_CHUNKS,
        )
        assertNull("exactly-at-max metadata must be accepted", result)
    }

    @Test
    fun `typical small valid metadata returns null`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = 1024L,
            mimeType = "image/jpeg",
            totalChunks = 1,
        )
        assertNull(result)
    }

    // ---------- fileSize rejection ----------

    @Test
    fun `fileSize one byte over max is rejected`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = MAX_FILE_SIZE_BYTES + 1,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull("oversized fileSize must be rejected", result)
        assertEquals("invalid fileSize=${MAX_FILE_SIZE_BYTES + 1}", result)
    }

    @Test
    fun `fileSize well above 2 pow 31 is rejected (Int overflow guard)`() {
        // Reproduces the attack: peer declares a multi-GB transfer that
        // would previously have overflowed optInt silently.
        val huge = 5L * 1024 * 1024 * 1024 // 5 GB
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = huge,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull(result)
    }

    @Test
    fun `zero fileSize is rejected`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = 0L,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull(result)
    }

    @Test
    fun `negative fileSize is rejected`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = -1L,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull(result)
    }

    // ---------- totalChunks rejection ----------

    @Test
    fun `totalChunks one over max is rejected`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = 1024L,
            mimeType = validMime,
            totalChunks = MAX_CHUNKS + 1,
        )
        assertNotNull(result)
        assertEquals("invalid totalChunks=${MAX_CHUNKS + 1}", result)
    }

    @Test
    fun `zero totalChunks is rejected`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = 1024L,
            mimeType = validMime,
            totalChunks = 0,
        )
        assertNotNull(result)
    }

    @Test
    fun `negative totalChunks is rejected`() {
        val result = validateFileMetadata(
            fileName = validName,
            fileSize = 1024L,
            mimeType = validMime,
            totalChunks = -5,
        )
        assertNotNull(result)
    }

    // ---------- fileName rejection ----------

    @Test
    fun `blank fileName is rejected`() {
        val result = validateFileMetadata(
            fileName = "   ",
            fileSize = 1024L,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull(result)
    }

    @Test
    fun `empty fileName is rejected`() {
        val result = validateFileMetadata(
            fileName = "",
            fileSize = 1024L,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull(result)
    }

    @Test
    fun `fileName one character over max is rejected`() {
        val overlong = "a".repeat(MAX_FILENAME_LENGTH + 1)
        val result = validateFileMetadata(
            fileName = overlong,
            fileSize = 1024L,
            mimeType = validMime,
            totalChunks = 1,
        )
        assertNotNull(result)
        assertEquals("invalid fileName length=${MAX_FILENAME_LENGTH + 1}", result)
    }
}
