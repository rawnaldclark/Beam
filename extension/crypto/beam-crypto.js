// Beam E2E encryption — Chrome crypto module.
//
// Implements the Triple-DH handshake, HKDF derivations, AAD layout, deterministic
// nonce derivation, padding, and XChaCha20-Poly1305 AEAD specified in
// docs/superpowers/specs/2026-04-10-e2e-encryption-design.md.
//
// All byte outputs of this module MUST match the canonical test vectors at
// server/test-vectors/crypto-v1.json (mirrored into this directory as
// test-vectors-v1.json) on every field. If they diverge, the Android client
// will produce different ciphertext and transfers will fail.
//
// This module has no networking and no session state — it is a pure functional
// layer consumed by session-registry.js and the integrations in background.js
// and background-relay.js.

import { loadSodium } from './sodium-loader.js';

// ---------------------------------------------------------------------------
// Constants — every magic byte and label comes from the spec.
// ---------------------------------------------------------------------------

export const PROTOCOL_VERSION = 1;

export const KIND_CLIPBOARD     = 0x01;
export const KIND_FILE_METADATA = 0x02;
export const KIND_FILE_CHUNK    = 0x03;

const LABEL_TRANSCRIPT = textEncode('beam-transcript-v1');
const LABEL_SESSION    = textEncode('beam-session-v1');
const LABEL_CHUNK      = textEncode('beam-chunk-v1');
const LABEL_META       = textEncode('beam-meta-v1');
const LABEL_NONCE      = textEncode('beam-nonce-v1');
const LABEL_AEAD       = textEncode('beam-aead-v1');

const PADDING_FLOOR_BYTES = 64; // smallest bucket; protects very small payloads

// ---------------------------------------------------------------------------
// Small byte helpers — no dependencies on sodium.
// ---------------------------------------------------------------------------

function textEncode(s) {
  return new TextEncoder().encode(s);
}

function concat(...parts) {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

function u8(n) {
  return new Uint8Array([n & 0xff]);
}

function u32be(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, false);
  return out;
}

function u64be(n) {
  // n is a safe integer (<= 2^53). We always write the high 32 bits as 0 on the
  // wire because Beam chunk indices never exceed 2^32 (enforced elsewhere).
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  const hi = Math.floor(n / 0x1_0000_0000);
  const lo = n >>> 0;
  dv.setUint32(0, hi, false);
  dv.setUint32(4, lo, false);
  return out;
}

function nextPowerOfTwo(n) {
  if (n <= 1) return 1;
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

// ---------------------------------------------------------------------------
// SHA-256 and HMAC-SHA256 via WebCrypto (always available in SW, faster than
// emulating through libsodium for small inputs).
// ---------------------------------------------------------------------------

async function sha256(data) {
  const buf = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buf);
}

async function hmacSha256(key, data) {
  const k = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', k, data);
  return new Uint8Array(sig);
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) — split into Extract and Expand so we can match the
// spec's two-stage derivation exactly.
// ---------------------------------------------------------------------------

export async function hkdfExtract(salt, ikm) {
  const saltBytes = salt && salt.byteLength > 0 ? salt : new Uint8Array(32);
  return hmacSha256(saltBytes, ikm);
}

export async function hkdfExpand(prk, info, length) {
  const out = new Uint8Array(length);
  let t = new Uint8Array(0);
  let offset = 0;
  let counter = 1;
  while (offset < length) {
    const input = concat(t, info, u8(counter));
    // eslint-disable-next-line no-await-in-loop
    t = await hmacSha256(prk, input);
    const take = Math.min(t.byteLength, length - offset);
    out.set(t.subarray(0, take), offset);
    offset += take;
    counter += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// X25519 keypair generation + Triple-DH.
// ---------------------------------------------------------------------------

/**
 * Generate a fresh X25519 ephemeral keypair.
 * @returns {Promise<{sk: Uint8Array, pk: Uint8Array}>}
 */
export async function generateEphemeral() {
  const sodium = await loadSodium();
  const kp = sodium.crypto_box_keypair();
  // sodium's crypto_box_keypair returns X25519 keys (curve25519 under the hood).
  return { sk: new Uint8Array(kp.privateKey), pk: new Uint8Array(kp.publicKey) };
}

/**
 * Derive the X25519 public key from a private key.
 */
export async function x25519PublicKey(sk) {
  const sodium = await loadSodium();
  return new Uint8Array(sodium.crypto_scalarmult_base(sk));
}

/**
 * Perform a raw X25519 scalar multiplication.
 */
export async function x25519(sk, peerPk) {
  const sodium = await loadSodium();
  return new Uint8Array(sodium.crypto_scalarmult(sk, peerPk));
}

/**
 * Beam Triple-DH, initiator perspective.
 * Both sides MUST concatenate dh1 || dh2 || dh3 in the same order regardless
 * of which side is computing. The responder computes the mirror via
 * computeTripleDHResponder below.
 */
export async function computeTripleDHInitiator({
  staticSkA,
  ephSkA,
  staticPkB,
  ephPkB,
}) {
  const dh1 = await x25519(staticSkA, ephPkB); // initiator static × responder ephemeral
  const dh2 = await x25519(ephSkA,    staticPkB); // initiator ephemeral × responder static
  const dh3 = await x25519(ephSkA,    ephPkB);    // ephemeral × ephemeral
  return { dh1, dh2, dh3, ikm: concat(dh1, dh2, dh3) };
}

/**
 * Beam Triple-DH, responder perspective. Must produce byte-identical
 * dh1/dh2/dh3 to the initiator.
 */
export async function computeTripleDHResponder({
  staticSkB,
  ephSkB,
  staticPkA,
  ephPkA,
}) {
  const dh1 = await x25519(ephSkB,    staticPkA);
  const dh2 = await x25519(staticSkB, ephPkA);
  const dh3 = await x25519(ephSkB,    ephPkA);
  return { dh1, dh2, dh3, ikm: concat(dh1, dh2, dh3) };
}

// ---------------------------------------------------------------------------
// Transcript hash.
// ---------------------------------------------------------------------------

/**
 * SHA-256('beam-transcript-v1' || u8(version) || staticPkA || staticPkB ||
 *         ephPkA || ephPkB || transferId)
 */
export async function computeTranscript({
  version,
  staticPkA,
  staticPkB,
  ephPkA,
  ephPkB,
  transferId,
}) {
  const buf = concat(
    LABEL_TRANSCRIPT,
    u8(version),
    staticPkA,
    staticPkB,
    ephPkA,
    ephPkB,
    transferId,
  );
  return sha256(buf);
}

// ---------------------------------------------------------------------------
// Session / chunk / meta key derivation.
// ---------------------------------------------------------------------------

/**
 * sessionKey = HKDF-Expand(HKDF-Extract(salt, ikm),
 *                          info = 'beam-session-v1' || transcript,
 *                          L = 32)
 */
export async function deriveSessionKey({ ikm, salt, transcript }) {
  const prk = await hkdfExtract(salt, ikm);
  const info = concat(LABEL_SESSION, transcript);
  return hkdfExpand(prk, info, 32);
}

/**
 * chunkKey = HKDF-Expand(sessionKey, info = 'beam-chunk-v1', L = 32)
 * Uses sessionKey directly as PRK (already 32 bytes, uniform).
 */
export async function deriveChunkKey(sessionKey) {
  return hkdfExpand(sessionKey, LABEL_CHUNK, 32);
}

export async function deriveMetaKey(sessionKey) {
  return hkdfExpand(sessionKey, LABEL_META, 32);
}

// ---------------------------------------------------------------------------
// Nonce and AAD.
// ---------------------------------------------------------------------------

/**
 * nonce(i) = HMAC-SHA256(chunkKey, 'beam-nonce-v1' || u64_be(i))[0..24]
 */
export async function deriveNonce(chunkKey, index) {
  const mac = await hmacSha256(chunkKey, concat(LABEL_NONCE, u64be(index)));
  return mac.subarray(0, 24);
}

/**
 * AAD = 'beam-aead-v1' || kindByte || u32_be(index) || u32_be(totalChunks) || transcript
 */
export function buildAAD({ kindByte, index, totalChunks, transcript }) {
  return concat(LABEL_AEAD, u8(kindByte), u32be(index), u32be(totalChunks), transcript);
}

// ---------------------------------------------------------------------------
// Padding — u32_be(actualLen) || data || zero pad to next power of two,
// with a floor of PADDING_FLOOR_BYTES.
// ---------------------------------------------------------------------------

export function padPlaintext(data) {
  const rawLen = data.byteLength;
  const prefixedLen = 4 + rawLen;
  const bucket = nextPowerOfTwo(Math.max(prefixedLen, PADDING_FLOOR_BYTES));
  const padded = new Uint8Array(bucket);
  padded.set(u32be(rawLen), 0);
  padded.set(data, 4);
  // The rest is already zero.
  return padded;
}

export function unpadPlaintext(padded) {
  if (padded.byteLength < 4) {
    throw new Error('padded plaintext shorter than length prefix');
  }
  const rawLen = new DataView(padded.buffer, padded.byteOffset, 4).getUint32(0, false);
  if (rawLen > padded.byteLength - 4) {
    throw new Error('padded plaintext length prefix exceeds buffer');
  }
  return padded.subarray(4, 4 + rawLen);
}

// ---------------------------------------------------------------------------
// AEAD wrappers — XChaCha20-Poly1305 IETF.
// ---------------------------------------------------------------------------

async function aeadEncryptRaw(plaintext, key, nonce, aad) {
  const sodium = await loadSodium();
  return new Uint8Array(
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key),
  );
}

async function aeadDecryptRaw(ciphertext, key, nonce, aad) {
  const sodium = await loadSodium();
  return new Uint8Array(
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key),
  );
}

/**
 * Encrypt a single clipboard payload. Uses index 0 / totalChunks 1 / kind 0x01.
 */
export async function encryptClipboard({ plaintext, chunkKey, transcript }) {
  const padded = padPlaintext(plaintext);
  const nonce = await deriveNonce(chunkKey, 0);
  const aad = buildAAD({
    kindByte: KIND_CLIPBOARD,
    index: 0,
    totalChunks: 1,
    transcript,
  });
  const ciphertext = await aeadEncryptRaw(padded, chunkKey, nonce, aad);
  return { ciphertext, nonce, aad };
}

export async function decryptClipboard({ ciphertext, chunkKey, transcript }) {
  const nonce = await deriveNonce(chunkKey, 0);
  const aad = buildAAD({
    kindByte: KIND_CLIPBOARD,
    index: 0,
    totalChunks: 1,
    transcript,
  });
  const padded = await aeadDecryptRaw(ciphertext, chunkKey, nonce, aad);
  return unpadPlaintext(padded);
}

/**
 * Encrypt the file-offer metadata envelope. Uses index 0 / totalChunks 0 /
 * kind 0x02 under metaKey.
 */
export async function encryptFileMetadata({ plaintext, metaKey, transcript }) {
  const padded = padPlaintext(plaintext);
  const nonce = await deriveNonce(metaKey, 0);
  const aad = buildAAD({
    kindByte: KIND_FILE_METADATA,
    index: 0,
    totalChunks: 0,
    transcript,
  });
  const ciphertext = await aeadEncryptRaw(padded, metaKey, nonce, aad);
  return { ciphertext, nonce, aad };
}

export async function decryptFileMetadata({ ciphertext, metaKey, transcript }) {
  const nonce = await deriveNonce(metaKey, 0);
  const aad = buildAAD({
    kindByte: KIND_FILE_METADATA,
    index: 0,
    totalChunks: 0,
    transcript,
  });
  const padded = await aeadDecryptRaw(ciphertext, metaKey, nonce, aad);
  return unpadPlaintext(padded);
}

/**
 * Encrypt a single file chunk at (1-indexed) `index`. totalChunks is the
 * receiver's expected count — used to prevent truncation attacks.
 */
export async function encryptFileChunk({
  plaintext,
  chunkKey,
  index,
  totalChunks,
  transcript,
}) {
  if (index < 1) throw new Error('file chunk index must be >= 1');
  if (index > totalChunks) throw new Error('file chunk index exceeds totalChunks');
  const padded = padPlaintext(plaintext);
  const nonce = await deriveNonce(chunkKey, index);
  const aad = buildAAD({
    kindByte: KIND_FILE_CHUNK,
    index,
    totalChunks,
    transcript,
  });
  const ciphertext = await aeadEncryptRaw(padded, chunkKey, nonce, aad);
  return { ciphertext, nonce, aad };
}

export async function decryptFileChunk({
  ciphertext,
  chunkKey,
  index,
  totalChunks,
  transcript,
}) {
  const nonce = await deriveNonce(chunkKey, index);
  const aad = buildAAD({
    kindByte: KIND_FILE_CHUNK,
    index,
    totalChunks,
    transcript,
  });
  const padded = await aeadDecryptRaw(ciphertext, chunkKey, nonce, aad);
  return unpadPlaintext(padded);
}

// ---------------------------------------------------------------------------
// Best-effort wipe. libsodium provides memzero, which is the strongest
// guarantee we can offer in JavaScript — the runtime may still have copies.
// ---------------------------------------------------------------------------

export async function wipe(...buffers) {
  const sodium = await loadSodium();
  for (const buf of buffers) {
    if (buf && buf.fill) {
      // Zero via both paths — memzero for libsodium's bookkeeping, fill for
      // any view that doesn't survive a memzero round-trip.
      try { sodium.memzero(buf); } catch (_) { /* ignore */ }
      try { buf.fill(0); } catch (_) { /* ignore */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Hex helpers for tests and logging. Not used on the data path.
// ---------------------------------------------------------------------------

export function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

export function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// PKCS8 X25519 private key → raw 32-byte scalar.
//
// WebCrypto X25519 private keys can only be exported as PKCS8 or JWK — they
// are never "raw" 32-byte scalars. For interop with libsodium (which expects
// the raw scalar in crypto_scalarmult), we extract it here. Beam's pairing
// code stores the PKCS8 bytes in chrome.storage.local; this helper turns
// them back into the scalar at runtime.
//
// RFC 8410 X25519 PKCS8 is a deterministic 48-byte structure:
//
//   30 2e                                  SEQUENCE (46)
//     02 01 00                             INTEGER 0 (version)
//     30 05                                SEQUENCE (5)  — AlgorithmIdentifier
//       06 03 2b 65 6e                     OID 1.3.101.110 (X25519)
//     04 22                                OCTET STRING (34) — outer wrapper
//       04 20 <32 bytes scalar>            OCTET STRING (32) — CurvePrivateKey
//
// Total: 48 bytes. Scalar is at offset 16. We verify the full header pattern
// before reading, so a malformed or attribute-carrying PKCS8 blob throws
// rather than silently returning garbage.
// ---------------------------------------------------------------------------

const PKCS8_X25519_HEADER = new Uint8Array([
  0x30, 0x2e,                               // SEQUENCE 46
  0x02, 0x01, 0x00,                         // INTEGER 0
  0x30, 0x05,                               // SEQUENCE 5
  0x06, 0x03, 0x2b, 0x65, 0x6e,             // OID 1.3.101.110
  0x04, 0x22,                               // OCTET STRING 34
  0x04, 0x20,                               // OCTET STRING 32
]);

export function pkcs8X25519SkToRaw(pkcs8) {
  const bytes = pkcs8 instanceof Uint8Array ? pkcs8 : new Uint8Array(pkcs8);
  if (bytes.byteLength !== 48) {
    throw new Error(`PKCS8 X25519 private key must be 48 bytes, got ${bytes.byteLength}`);
  }
  for (let i = 0; i < PKCS8_X25519_HEADER.length; i += 1) {
    if (bytes[i] !== PKCS8_X25519_HEADER[i]) {
      throw new Error('PKCS8 X25519 header mismatch at byte ' + i);
    }
  }
  return bytes.slice(16, 48);
}
