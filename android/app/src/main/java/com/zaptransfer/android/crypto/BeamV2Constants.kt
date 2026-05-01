package com.zaptransfer.android.crypto

/**
 * Single source of truth for Beam v2 protocol timings and limits.
 *
 * MUST stay byte-identical with `extension/crypto/beam-v2-constants.js` on
 * the Chrome side. Every value here has a comment naming the JS counterpart
 * so a reviewer changing one knows to update the other.
 *
 * Spec: docs/superpowers/specs/2026-04-30-beam-v2-design.md
 */
object BeamV2Constants {

    // ── Wire format ─────────────────────────────────────────────────────

    /** Wire-format magic; mirrors JS `MAGIC`. */
    val MAGIC: ByteArray = byteArrayOf(0x42, 0x45, 0x41, 0x32) // 'BEA2'

    /** Protocol version byte; mirrors JS `VERSION`. */
    const val VERSION: Byte = 0x02

    /** Header total bytes; mirrors JS `HEADER_LEN`. */
    const val HEADER_LEN: Int = 48

    /** AEAD nonce length (XChaCha20-Poly1305); mirrors JS `NONCE_LEN`. */
    const val NONCE_LEN: Int = 24

    /** Pairing-key length; mirrors JS `KAB_LEN`. */
    const val KAB_LEN: Int = 32

    /** Frame flag bits; mirrors JS `FLAG_IS_FINAL`. */
    const val FLAG_IS_FINAL: Byte = 0x01
    /** Mirrors JS `FLAG_HAS_META`. */
    const val FLAG_HAS_META: Byte = 0x02

    /** Plaintext file chunk size; mirrors JS `FILE_CHUNK_SIZE`. */
    const val FILE_CHUNK_SIZE: Int = 200 * 1024

    /** Hard cap on file size; mirrors JS `MAX_FILE_SIZE`. */
    const val MAX_FILE_SIZE: Long = 500L * 1024 * 1024

    /** Hard cap on total chunks; mirrors JS `MAX_CHUNKS`. */
    const val MAX_CHUNKS: Int = 3000

    // ── Retry semantics ────────────────────────────────────────────────

    /** Receiver gap before resend; mirrors JS `RECEIVE_GAP_MS`. */
    const val RECEIVE_GAP_MS: Long = 5_000

    /** Receiver total give-up window; mirrors JS `RECEIVER_GIVEUP_MS`. */
    const val RECEIVER_GIVEUP_MS: Long = 60_000

    /** Sender total give-up window; mirrors JS `SENDER_GIVEUP_MS`. */
    const val SENDER_GIVEUP_MS: Long = 30_000

    /** Sender cap on resend rounds; mirrors JS `MAX_RESENDS`. */
    const val MAX_RESENDS: Int = 2

    // ── Key rotation ───────────────────────────────────────────────────

    /** Old-generation grace window; mirrors JS `ROTATION_GRACE_MS`. */
    const val ROTATION_GRACE_MS: Long = 24L * 60 * 60 * 1000

    /** HKDF info prefix; mirrors JS `KAB_INFO_PREFIX`. */
    const val KAB_INFO_PREFIX: String = "beam-v2-pairing-key/"
}
