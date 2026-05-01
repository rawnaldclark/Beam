/**
 * @file beam-v2-constants.js
 * @description Single source of truth for Beam v2 protocol timings and limits.
 *
 * MUST stay byte-identical with `BeamV2Constants.kt` on the Android side.
 * Drift between the two is a silent interoperability bug — every value here
 * is named with a comment in the Kotlin file pointing back at this one.
 *
 * Spec: docs/superpowers/specs/2026-04-30-beam-v2-design.md
 */

/** Wire format magic. */
export const MAGIC = new Uint8Array([0x42, 0x45, 0x41, 0x32]); // 'BEA2'

/** Protocol version byte. */
export const VERSION = 0x02;

/** Header total bytes (excluding nonce + ciphertext). */
export const HEADER_LEN = 48;

/** AEAD nonce length (XChaCha20-Poly1305). */
export const NONCE_LEN = 24;

/** Pairing-key length. */
export const KAB_LEN = 32;

/** Frame flag bits. */
export const FLAG_IS_FINAL = 0x01;
export const FLAG_HAS_META = 0x02;

/** Plaintext file chunk size (matches v1; receiver's max plaintext per frame). */
export const FILE_CHUNK_SIZE = 200 * 1024;

/** Hard cap on file size (matches relay SESSION_LIMIT). */
export const MAX_FILE_SIZE = 500 * 1024 * 1024;

/** Hard cap on total chunks. */
export const MAX_CHUNKS = 3000;

// ── Retry semantics ────────────────────────────────────────────────────────

/** Receiver: gap with no incoming frames before requesting resend. */
export const RECEIVE_GAP_MS = 5_000;

/** Receiver: total time after first request before giving up the transfer. */
export const RECEIVER_GIVEUP_MS = 60_000;

/** Sender: total time after first send before giving up. */
export const SENDER_GIVEUP_MS = 30_000;

/** Sender: cap on resend rounds. */
export const MAX_RESENDS = 2;

// ── Key rotation ───────────────────────────────────────────────────────────

/** Old generation accepted-for-decrypt window after a rotate-commit. */
export const ROTATION_GRACE_MS = 24 * 60 * 60 * 1000;

/** HKDF info-string prefix for K_AB derivation. */
export const KAB_INFO_PREFIX = 'beam-v2-pairing-key/';
