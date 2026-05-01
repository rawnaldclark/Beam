/**
 * @file beam-v2.js
 * @description Beam v2 stateless E2E codec.
 *
 * Surface:
 *   - deriveKAB({ ourSk, peerPk, ourEdPk, peerEdPk, generation, rotateNonce? })
 *   - encodeFrame({ kAB, generation, transferId, index, isFinal, hasMeta, plaintext })
 *   - decodeFrame({ resolveKAB, frameBytes })
 *   - peekHeader(frameBytes)
 *
 * No state. No timers. Pure functions over inputs.
 *
 * Spec: docs/superpowers/specs/2026-04-30-beam-v2-design.md
 */

import { hkdfExtract, hkdfExpand, x25519 } from './beam-crypto.js';
import { loadSodium } from './sodium-loader.js';
import {
  MAGIC,
  VERSION,
  HEADER_LEN,
  NONCE_LEN,
  KAB_LEN,
  FLAG_IS_FINAL,
  FLAG_HAS_META,
  KAB_INFO_PREFIX,
} from './beam-v2-constants.js';

// ---------------------------------------------------------------------------
// Pairing-key derivation
// ---------------------------------------------------------------------------

/**
 * Compute the per-pair long-lived symmetric key K_AB.
 *
 * Both sides arrive at the same K_AB because:
 *   ikm  = X25519(ourSk, peerPk)             — DH is symmetric
 *   salt = SHA-256(sort_lex(edPkA, edPkB))   — sort makes role-independent
 *   info = "beam-v2-pairing-key/" || u32_be(generation) || rotateNonce?
 *
 * @param {{
 *   ourSk: Uint8Array,         // 32 bytes
 *   peerPk: Uint8Array,        // 32 bytes
 *   ourEdPk: Uint8Array,       // 32 bytes
 *   peerEdPk: Uint8Array,      // 32 bytes
 *   generation: number,        // u32, starts at 0
 *   rotateNonce?: Uint8Array,  // 16 bytes, only present for generation > 0
 * }} args
 * @returns {Promise<Uint8Array>} 32-byte K_AB
 */
export async function deriveKAB({
  ourSk,
  peerPk,
  ourEdPk,
  peerEdPk,
  generation,
  rotateNonce = null,
}) {
  if (ourSk.byteLength   !== 32) throw new Error('ourSk must be 32 bytes');
  if (peerPk.byteLength  !== 32) throw new Error('peerPk must be 32 bytes');
  if (ourEdPk.byteLength !== 32) throw new Error('ourEdPk must be 32 bytes');
  if (peerEdPk.byteLength !== 32) throw new Error('peerEdPk must be 32 bytes');
  if (!Number.isInteger(generation) || generation < 0 || generation > 0xFFFFFFFF) {
    throw new Error('generation must be a u32');
  }
  if (generation > 0 && (!rotateNonce || rotateNonce.byteLength !== 16)) {
    throw new Error('rotateNonce (16 bytes) required for generation > 0');
  }

  const ikm = await x25519(ourSk, peerPk);

  // Lex-sorted concatenation of both Ed25519 PKs → SHA-256 → salt.
  const sodium = await loadSodium();
  const a = ourEdPk;
  const b = peerEdPk;
  const cmp = compareBytes(a, b);
  const lower  = cmp <= 0 ? a : b;
  const higher = cmp <= 0 ? b : a;
  const concat = new Uint8Array(64);
  concat.set(lower);
  concat.set(higher, 32);
  const salt = new Uint8Array(sodium.crypto_hash_sha256(concat));

  // info = ASCII prefix || u32_be(generation) || rotateNonce?
  const prefix = new TextEncoder().encode(KAB_INFO_PREFIX);
  const genBE  = new Uint8Array(4);
  new DataView(genBE.buffer).setUint32(0, generation >>> 0, false);
  const infoLen = prefix.length + 4 + (rotateNonce ? 16 : 0);
  const info    = new Uint8Array(infoLen);
  info.set(prefix, 0);
  info.set(genBE, prefix.length);
  if (rotateNonce) info.set(rotateNonce, prefix.length + 4);

  const prk = await hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, KAB_LEN);
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

/**
 * Build a 48-byte header. The header IS the AEAD additional-data — it binds
 * version, transferId, index, flags, and generation to the ciphertext.
 *
 * @param {{
 *   transferId: Uint8Array,    // 16 bytes
 *   index: number,             // u32
 *   isFinal: boolean,
 *   hasMeta: boolean,
 *   generation: number,        // u32
 * }} args
 * @returns {Uint8Array} 48-byte header
 */
export function buildHeader({ transferId, index, isFinal, hasMeta, generation }) {
  if (transferId.byteLength !== 16) throw new Error('transferId must be 16 bytes');
  if (!Number.isInteger(index) || index < 0 || index > 0xFFFFFFFF) {
    throw new Error('index must be a u32');
  }
  if (!Number.isInteger(generation) || generation < 0 || generation > 0xFFFFFFFF) {
    throw new Error('generation must be a u32');
  }

  const h = new Uint8Array(HEADER_LEN);
  h.set(MAGIC, 0);
  h[4] = VERSION;
  let flags = 0;
  if (isFinal) flags |= FLAG_IS_FINAL;
  if (hasMeta) flags |= FLAG_HAS_META;
  h[5] = flags;
  // bytes 6..7 reserved zero
  h.set(transferId, 8);
  const dv = new DataView(h.buffer);
  dv.setUint32(24, index >>> 0, false);
  dv.setUint32(28, generation >>> 0, false);
  // bytes 32..47 reserved zero
  return h;
}

/**
 * Parse the fixed 48-byte header. Returns null on any structural mismatch
 * (wrong magic, wrong version, reserved-bit violation) so callers can drop
 * the frame without surfacing a noisy decrypt failure.
 *
 * @param {Uint8Array} bytes - At least HEADER_LEN bytes.
 * @returns {{
 *   transferId: Uint8Array,
 *   index: number,
 *   isFinal: boolean,
 *   hasMeta: boolean,
 *   generation: number,
 * } | null}
 */
export function peekHeader(bytes) {
  if (bytes.byteLength < HEADER_LEN) return null;
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) return null;
  if (bytes[4] !== VERSION) return null;
  const flags = bytes[5];
  if ((flags & ~(FLAG_IS_FINAL | FLAG_HAS_META)) !== 0) return null;
  if (bytes[6] !== 0 || bytes[7] !== 0) return null;
  for (let i = 32; i < 48; i++) if (bytes[i] !== 0) return null;

  const transferId = bytes.slice(8, 24);
  const dv = new DataView(bytes.buffer, bytes.byteOffset + 24, 8);
  const index      = dv.getUint32(0, false);
  const generation = dv.getUint32(4, false);
  return {
    transferId,
    index,
    isFinal: (flags & FLAG_IS_FINAL) !== 0,
    hasMeta: (flags & FLAG_HAS_META) !== 0,
    generation,
  };
}

/**
 * Encrypt a frame. Random 24-byte nonce per call (XChaCha20 collision-safe).
 *
 * `_testNonce` is an internal seam for the deterministic vector generator
 * (`scripts/gen-beam-v2-vectors.js`); production callers MUST omit it so a
 * fresh random nonce is generated.
 *
 * @param {{
 *   kAB: Uint8Array,           // 32 bytes
 *   generation: number,
 *   transferId: Uint8Array,    // 16 bytes
 *   index: number,
 *   isFinal: boolean,
 *   hasMeta: boolean,
 *   plaintext: Uint8Array,
 *   _testNonce?: Uint8Array,   // 24 bytes; test-only override
 * }} args
 * @returns {Promise<Uint8Array>} full frame: header || nonce || ciphertext
 */
export async function encodeFrame({
  kAB,
  generation,
  transferId,
  index,
  isFinal,
  hasMeta,
  plaintext,
  _testNonce = null,
}) {
  if (kAB.byteLength !== KAB_LEN) throw new Error(`kAB must be ${KAB_LEN} bytes`);
  const sodium = await loadSodium();

  const header = buildHeader({ transferId, index, isFinal, hasMeta, generation });
  let nonce;
  if (_testNonce) {
    if (_testNonce.byteLength !== NONCE_LEN) throw new Error(`_testNonce must be ${NONCE_LEN} bytes`);
    nonce = _testNonce;
  } else {
    nonce = new Uint8Array(NONCE_LEN);
    crypto.getRandomValues(nonce);
  }

  const ciphertext = new Uint8Array(
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, header, null, nonce, kAB),
  );

  const frame = new Uint8Array(HEADER_LEN + NONCE_LEN + ciphertext.byteLength);
  frame.set(header, 0);
  frame.set(nonce,  HEADER_LEN);
  frame.set(ciphertext, HEADER_LEN + NONCE_LEN);
  return frame;
}

/**
 * Decrypt a frame. The caller supplies a `resolveKAB(generation)` function
 * because in the rotation model the receiver may know multiple K_AB
 * generations; the codec stays stateless by deferring lookup to the caller.
 *
 * Returns null on any structural or cryptographic failure — caller decides
 * whether to log + drop or to mark the transferId as poisoned.
 *
 * @param {{
 *   resolveKAB: (generation: number) => Uint8Array | null,
 *   frameBytes: Uint8Array,
 * }} args
 * @returns {Promise<{
 *   header: ReturnType<typeof peekHeader>,
 *   plaintext: Uint8Array,
 * } | null>}
 */
export async function decodeFrame({ resolveKAB, frameBytes }) {
  const header = peekHeader(frameBytes);
  if (!header) return null;
  if (frameBytes.byteLength < HEADER_LEN + NONCE_LEN + 16 /* tag */) return null;

  const kAB = resolveKAB(header.generation);
  if (!kAB || kAB.byteLength !== KAB_LEN) return null;

  const headerBytes = frameBytes.subarray(0, HEADER_LEN);
  const nonce       = frameBytes.subarray(HEADER_LEN, HEADER_LEN + NONCE_LEN);
  const ciphertext  = frameBytes.subarray(HEADER_LEN + NONCE_LEN);

  let plaintext;
  try {
    const sodium = await loadSodium();
    plaintext = new Uint8Array(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, headerBytes, nonce, kAB),
    );
  } catch {
    return null;
  }
  return { header, plaintext };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compareBytes(a, b) {
  const len = Math.min(a.byteLength, b.byteLength);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.byteLength - b.byteLength;
}

/**
 * Generate a fresh 16-byte transferId.
 *
 * @returns {Uint8Array}
 */
export function newTransferId() {
  const id = new Uint8Array(16);
  crypto.getRandomValues(id);
  return id;
}
