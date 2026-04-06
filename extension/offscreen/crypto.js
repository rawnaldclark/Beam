/**
 * @file crypto.js
 * @description Beam crypto module — thin, auditable wrapper around libsodium-wrappers-sumo.
 *
 * Primitives used:
 *   - Key agreement : X25519  (crypto_scalarmult)
 *   - Signing       : Ed25519 (crypto_sign_detached / _verify_detached)
 *   - AEAD          : XChaCha20-Poly1305-IETF (crypto_aead_xchacha20poly1305_ietf_*)
 *   - KDF / PRF     : HKDF-SHA-256 (implemented via crypto_auth_hmacsha256 for extract+expand)
 *   - Hash          : SHA-256 (crypto_hash_sha256) for device-ID derivation
 *
 * All exported functions are synchronous after init() has been awaited once.
 * The module uses a module-level `_sodium` reference so the wasm binary is
 * only initialised once per context.
 *
 * @module offscreen/crypto
 */

// libsodium loaded via <script> tags in transfer-engine.html (sets self.sodium).
// For Node.js tests, the npm module is loaded dynamically.
let _sodiumModule = null;
let _sodium = null;

// ── internal helpers ────────────────────────────────────────────────────────

/**
 * Returns the ready sodium instance, or throws if init() was not called first.
 *
 * @returns {import('libsodium-wrappers-sumo')} The initialized sodium object.
 * @throws {Error} If init() has not yet been awaited.
 */
function S() {
  if (!_sodium) {
    throw new Error('crypto not initialized — call init() first');
  }
  return _sodium;
}

/**
 * HKDF-Extract (RFC 5869 §2.2).
 * PRK = HMAC-SHA256(salt, IKM)
 *
 * libsodium's crypto_auth_hmacsha256 enforces a key length of exactly 32 bytes.
 * Per RFC 5869 §2.2, when the provided salt is longer than the hash output
 * length (32 bytes), it MUST be hashed down to 32 bytes before use.
 * When the salt is shorter or absent, a string of HashLen zeros is used.
 *
 * @param {Uint8Array} ikm  - Input keying material (any length).
 * @param {Uint8Array} salt - Salt (any length; will be normalised to 32 bytes).
 * @returns {Uint8Array} 32-byte pseudo-random key.
 */
function hkdfExtract(ikm, salt) {
  const s = S();
  let normalisedSalt;
  if (!salt || salt.length === 0) {
    // RFC 5869: use HashLen zeros when salt is not provided.
    normalisedSalt = new Uint8Array(32);
  } else if (salt.length === 32) {
    normalisedSalt = salt;
  } else {
    // Hash the salt down to exactly 32 bytes (covers lengths > 32 or < 32).
    normalisedSalt = s.crypto_hash_sha256(salt);
  }
  // HMAC-SHA256(key=normalisedSalt, data=ikm)
  return s.crypto_auth_hmacsha256(ikm, normalisedSalt);
}

/**
 * HKDF-Expand (RFC 5869 §2.3) for a single 32-byte output block (T(1)).
 * OKM = HMAC-SHA256(PRK, info || 0x01)
 *
 * This produces exactly 32 bytes, which is sufficient for all key-derivation
 * calls in this module (we never need more than one HMAC block).
 *
 * @param {Uint8Array} prk  - 32-byte pseudo-random key from hkdfExtract.
 * @param {Uint8Array} info - Context/application-specific label bytes.
 * @returns {Uint8Array} 32-byte output keying material.
 */
function hkdfExpand32(prk, info) {
  const s = S();
  // T(1) = HMAC-SHA256(PRK, info || 0x01)
  const expandInput = new Uint8Array(info.length + 1);
  expandInput.set(info);
  expandInput[info.length] = 1; // counter byte
  return s.crypto_auth_hmacsha256(expandInput, prk);
}

// ── public API ──────────────────────────────────────────────────────────────

/**
 * Initialise the module by waiting for the libsodium WASM binary to load.
 * Must be awaited before any other export is used.  Safe to call multiple
 * times — subsequent calls are no-ops.
 *
 * @returns {Promise<void>}
 */
export async function init() {
  if (_sodium) return; // already initialized
  // In browser (offscreen document): loaded via <script> tags, available as self.sodium
  if (typeof self !== 'undefined' && self.sodium && self.sodium.ready) {
    await self.sodium.ready;
    _sodium = self.sodium;
  } else {
    // In Node.js (tests): dynamic import from npm
    const mod = await import('libsodium-wrappers-sumo');
    _sodiumModule = mod.default;
    await _sodiumModule.ready;
    _sodium = _sodiumModule;
  }
}

/**
 * Generate a fresh pair of key pairs: one X25519 pair for key exchange and
 * one Ed25519 pair for signing.
 *
 * @returns {{
 *   x25519: { pk: Uint8Array, sk: Uint8Array },
 *   ed25519: { pk: Uint8Array, sk: Uint8Array }
 * }}
 */
export function generateKeyPairs() {
  const s = S();
  const x25519 = s.crypto_box_keypair();   // pk=32B, sk=32B
  const ed25519 = s.crypto_sign_keypair(); // pk=32B, sk=64B
  return {
    x25519: { pk: x25519.publicKey,  sk: x25519.privateKey },
    ed25519: { pk: ed25519.publicKey, sk: ed25519.privateKey },
  };
}

/**
 * Derive a stable, opaque device identifier from an Ed25519 public key.
 *
 * Algorithm: first 16 bytes of SHA-256(pk) → base64url (no padding) → 22 chars.
 *
 * @param {Uint8Array} ed25519Pk - 32-byte Ed25519 public key.
 * @returns {string} 22-character base64url string.
 */
export function deriveDeviceId(ed25519Pk) {
  const s = S();
  const hash = s.crypto_hash_sha256(ed25519Pk);
  const idBytes = hash.slice(0, 16);
  // Buffer.from works in Node; in a browser context use a manual b64url encoder.
  return Buffer.from(idBytes).toString('base64url');
}

/**
 * Sign a message with an Ed25519 secret key (detached signature).
 *
 * @param {Uint8Array | string} message  - The data to sign.
 * @param {Uint8Array}          ed25519Sk - 64-byte Ed25519 secret key.
 * @returns {Uint8Array} 64-byte detached signature.
 */
export function sign(message, ed25519Sk) {
  return S().crypto_sign_detached(message, ed25519Sk);
}

/**
 * Verify a detached Ed25519 signature.
 *
 * @param {Uint8Array | string} message   - The original data.
 * @param {Uint8Array}          signature - 64-byte detached signature.
 * @param {Uint8Array}          ed25519Pk - 32-byte Ed25519 public key.
 * @returns {boolean} true if the signature is valid, false otherwise.
 */
export function verify(message, signature, ed25519Pk) {
  return S().crypto_sign_verify_detached(signature, message, ed25519Pk);
}

/**
 * Perform an X25519 scalar multiplication (Diffie–Hellman step).
 *
 * @param {Uint8Array} mySk   - 32-byte X25519 secret key.
 * @param {Uint8Array} peerPk - 32-byte X25519 public key.
 * @returns {Uint8Array} 32-byte shared secret.
 */
export function deriveSharedSecret(mySk, peerPk) {
  return S().crypto_scalarmult(mySk, peerPk);
}

/**
 * Derive a 32-byte session key from three DH outputs (triple-DH) and a salt,
 * following HKDF-SHA-256 (RFC 5869).
 *
 * IKM  = dh1 || dh2 || dh3   (96 bytes)
 * PRK  = HKDF-Extract(salt, IKM)
 * OKM  = HKDF-Expand(PRK, "zaptransfer-session", 32)
 *
 * @param {Uint8Array} dh1  - First 32-byte DH output.
 * @param {Uint8Array} dh2  - Second 32-byte DH output.
 * @param {Uint8Array} dh3  - Third 32-byte DH output.
 * @param {Uint8Array} salt - 32-byte random salt.
 * @returns {Uint8Array} 32-byte session key.
 */
export function deriveSessionKey(dh1, dh2, dh3, salt) {
  // Concatenate the three DH outputs to form the input keying material.
  const ikm = new Uint8Array(96);
  ikm.set(dh1,  0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);

  const prk  = hkdfExtract(ikm, salt);
  const info = new TextEncoder().encode('zaptransfer-session');
  return hkdfExpand32(prk, info);
}

/**
 * Derive the chunk-encryption key from a session key.
 *
 * OKM = HKDF-Expand(sessionKey, "zaptransfer-chunk-encryption", 32)
 *
 * @param {Uint8Array} sessionKey - 32-byte session key.
 * @returns {Uint8Array} 32-byte chunk key.
 */
export function deriveChunkKey(sessionKey) {
  const info = new TextEncoder().encode('zaptransfer-chunk-encryption');
  return hkdfExpand32(sessionKey, info);
}

/**
 * Derive the metadata-encryption key from a session key.
 *
 * OKM = HKDF-Expand(sessionKey, "zaptransfer-metadata-encryption", 32)
 *
 * @param {Uint8Array} sessionKey - 32-byte session key.
 * @returns {Uint8Array} 32-byte metadata key.
 */
export function deriveMetadataKey(sessionKey) {
  const info = new TextEncoder().encode('zaptransfer-metadata-encryption');
  return hkdfExpand32(sessionKey, info);
}

/**
 * Derive a deterministic 24-byte XChaCha20 nonce for a specific chunk.
 *
 * OKM = HKDF-Expand(chunkKey, "chunk-nonce" || uint64_LE(chunkIndex), 32)
 * nonce = OKM[0..23]
 *
 * Using an index-based derived nonce (rather than random) ensures that a
 * re-encrypted chunk at the same position always uses the same nonce for
 * the same key — which is safe here because chunkKey is never reused
 * across sessions.
 *
 * @param {Uint8Array} chunkKey   - 32-byte chunk key.
 * @param {number}     chunkIndex - Non-negative integer chunk index.
 * @returns {Uint8Array} 24-byte nonce.
 */
export function deriveChunkNonce(chunkKey, chunkIndex) {
  // Build info label: "chunk-nonce" || uint64_LE(chunkIndex)
  const prefix    = new TextEncoder().encode('chunk-nonce');
  const indexBuf  = new ArrayBuffer(8);
  const view      = new DataView(indexBuf);
  view.setBigUint64(0, BigInt(chunkIndex), /* littleEndian= */ true);

  const info = new Uint8Array(prefix.length + 8);
  info.set(prefix);
  info.set(new Uint8Array(indexBuf), prefix.length);

  // Expand and take first 24 bytes (XChaCha20 nonce length).
  return hkdfExpand32(chunkKey, info).slice(0, 24);
}

/**
 * Pad plaintext into a fixed-size power-of-two bucket before encryption.
 *
 * Layout of the padded buffer:
 *   [0..3]   uint32 LE — original plaintext byte length
 *   [4..4+n] plaintext bytes
 *   [rest]   random bytes (padding)
 *
 * Bucket sizes (bytes):
 *   dataLen ≤  65 536 →  64 KiB
 *   dataLen ≤ 131 072 → 128 KiB
 *   dataLen ≤ 262 144 → 256 KiB
 *   else              → 512 KiB
 *
 * where dataLen = 4 + plaintext.length.
 *
 * @param {Uint8Array} plaintext - Raw chunk data.
 * @returns {Uint8Array} Padded buffer of exactly `bucketSize` bytes.
 * @throws {RangeError} If plaintext exceeds the maximum bucket payload.
 */
export function padChunk(plaintext) {
  const s       = S();
  const dataLen = 4 + plaintext.length;

  let bucketSize;
  if      (dataLen <=  65536)  bucketSize =  65536;
  else if (dataLen <= 131072)  bucketSize = 131072;
  else if (dataLen <= 262144)  bucketSize = 262144;
  else if (dataLen <= 524288)  bucketSize = 524288;
  else throw new RangeError(`padChunk: plaintext too large (${plaintext.length} bytes)`);

  const padded  = new Uint8Array(bucketSize);
  const lenView = new DataView(padded.buffer);

  // Write plaintext length prefix (little-endian uint32).
  lenView.setUint32(0, plaintext.length, /* littleEndian= */ true);

  // Copy plaintext data after the 4-byte length prefix.
  padded.set(
    plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext),
    4,
  );

  // Fill the remainder with random bytes to prevent leaking information via
  // compressed ciphertext length or padding patterns.
  const paddingLen = bucketSize - 4 - plaintext.length;
  if (paddingLen > 0) {
    padded.set(s.randombytes_buf(paddingLen), 4 + plaintext.length);
  }

  return padded;
}

/**
 * Recover the original plaintext from a padded buffer produced by padChunk().
 *
 * @param {Uint8Array} padded - Buffer produced by padChunk().
 * @returns {Uint8Array} Original plaintext bytes.
 */
export function unpadChunk(padded) {
  const view = new DataView(padded.buffer, padded.byteOffset);
  const len  = view.getUint32(0, /* littleEndian= */ true);
  return padded.slice(4, 4 + len);
}

/**
 * Encrypt a chunk using XChaCha20-Poly1305-IETF.
 *
 * The plaintext is padded to a fixed-size bucket before encryption so that
 * ciphertexts do not leak chunk sizes.  The nonce is derived deterministically
 * from (chunkKey, chunkIndex) — see deriveChunkNonce().
 *
 * @param {Uint8Array} plaintext   - Raw chunk data.
 * @param {Uint8Array} chunkKey    - 32-byte chunk encryption key.
 * @param {number}     chunkIndex  - Non-negative integer chunk index.
 * @param {Uint8Array} aad         - Additional authenticated data (not encrypted).
 * @returns {Uint8Array} Ciphertext + 16-byte Poly1305 authentication tag.
 */
export function encryptChunk(plaintext, chunkKey, chunkIndex, aad) {
  const s     = S();
  const nonce = deriveChunkNonce(chunkKey, chunkIndex);
  const padded = padChunk(plaintext);
  return s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    padded,
    aad,
    null,    // no additional secret nonce
    nonce,
    chunkKey,
  );
}

/**
 * Decrypt a chunk produced by encryptChunk().
 *
 * Throws if authentication fails (tampered ciphertext, wrong key, wrong AAD,
 * or wrong chunk index).
 *
 * @param {Uint8Array} ciphertext  - Output of encryptChunk().
 * @param {Uint8Array} chunkKey    - 32-byte chunk encryption key.
 * @param {number}     chunkIndex  - Non-negative integer chunk index.
 * @param {Uint8Array} aad         - Additional authenticated data.
 * @returns {Uint8Array} Original plaintext bytes.
 * @throws {Error} On authentication failure.
 */
export function decryptChunk(ciphertext, chunkKey, chunkIndex, aad) {
  const s     = S();
  const nonce = deriveChunkNonce(chunkKey, chunkIndex);
  const padded = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,   // no additional secret nonce
    ciphertext,
    aad,
    nonce,
    chunkKey,
  );
  return unpadChunk(padded);
}

/**
 * Encrypt a JSON-serialisable metadata object.
 *
 * Envelope layout:
 *   [0..23]  random 24-byte XChaCha20 nonce
 *   [24..]   XChaCha20-Poly1305-IETF ciphertext + 16-byte tag
 *
 * The AAD "zaptransfer-metadata-v1" binds the ciphertext to the protocol
 * version and prevents cross-context replay.
 *
 * @param {object}     metadataJson - JSON-serialisable metadata object.
 * @param {Uint8Array} metadataKey  - 32-byte metadata encryption key.
 * @returns {Uint8Array} Sealed envelope (nonce || ciphertext).
 */
export function encryptMetadata(metadataJson, metadataKey) {
  const s         = S();
  const nonce     = s.randombytes_buf(24);
  const plaintext = new TextEncoder().encode(JSON.stringify(metadataJson));
  const aad       = new TextEncoder().encode('zaptransfer-metadata-v1');

  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    metadataKey,
  );

  // Prepend the nonce so the receiver can open the envelope without side-channel.
  const envelope = new Uint8Array(24 + ciphertext.length);
  envelope.set(nonce,      0);
  envelope.set(ciphertext, 24);
  return envelope;
}

/**
 * Decrypt an envelope produced by encryptMetadata() and return the parsed
 * JSON object.
 *
 * @param {Uint8Array} envelope    - Sealed envelope (nonce || ciphertext).
 * @param {Uint8Array} metadataKey - 32-byte metadata encryption key.
 * @returns {object} Parsed JSON metadata.
 * @throws {Error} On authentication failure or JSON parse error.
 */
export function decryptMetadata(envelope, metadataKey) {
  const s          = S();
  const nonce      = envelope.slice(0, 24);
  const ciphertext = envelope.slice(24);
  const aad        = new TextEncoder().encode('zaptransfer-metadata-v1');

  const plaintext = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    metadataKey,
  );

  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ── SAS emoji table ─────────────────────────────────────────────────────────
// 256 visually distinct emoji (one per index 0-255) used for Short
// Authentication Strings so users can verbally confirm a session is secure.
const SAS_EMOJI = [
  '🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🐔',
  '🐧','🐦','🐤','🦆','🦅','🦉','🦇','🐺','🐗','🐴','🦄','🐝','🪱','🐛','🦋','🐌',
  '🐞','🐜','🪰','🪲','🪳','🦟','🦗','🕷','🦂','🐢','🐍','🦎','🦖','🦕','🐙','🦑',
  '🦐','🦞','🦀','🐡','🐠','🐟','🐬','🐳','🐋','🦈','🪸','🐊','🐅','🐆','🦓','🦍',
  '🦧','🐘','🦛','🦏','🐪','🐫','🦒','🦘','🦬','🐃','🐂','🐄','🐎','🐖','🐏','🐑',
  '🦙','🐐','🦌','🐕','🐩','🦮','🐈','🐓','🦃','🦤','🦚','🦜','🦢','🦩','🕊','🐇',
  '🦝','🦨','🦡','🦫','🦦','🦥','🐁','🐀','🐿','🦔','🐉','🐲','🌵','🎄','🌲','🌳',
  '🌴','🪵','🌱','🌿','🍀','🎋','🍃','🍂','🍁','🌾','🪻','🌺','🌸','🌼','🌻','🌞',
  '🌝','🌛','🌜','🌚','🌕','🌖','🌗','🌘','🌑','🌒','🌓','🌔','🌙','🌎','🌍','🌏',
  '🪐','💫','⭐','🌟','✨','⚡','☄️','💥','🔥','🌪','🌈','☀️','🌤','⛅','🌥','☁️',
  '🌦','🌧','⛈','🌩','🌨','❄️','☃️','⛄','🌬','💨','💧','💦','🫧','☔','☂️','🌊',
  '🌫','🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓','🫐','🍈','🍒','🍑','🥭','🍍','🥥',
  '🥝','🍅','🍆','🥑','🥦','🥬','🥒','🌶','🫑','🌽','🥕','🫒','🧄','🧅','🥔','🍠',
  '🫘','🥜','🌰','🍞','🥐','🥖','🫓','🥨','🥯','🧇','🍕','🌭','🍔','🍟','🧆','🌮',
  '🫔','🌯','🥙','🧁','🎂','🍰','🍫','🍬','🍭','🍮','🍩','🍪','🎯','🎲','🎮','🎸',
  '🎺','🎷','🥁','🎹','🎵','🎶','🔔','🔑','🗝','💎','🔮','🧲','🔭','🔬','🧬','🧪',
];

/**
 * Derive an 8-byte Short Authentication String (SAS) value that both peers
 * can display to confirm their session is secure.
 *
 * Algorithm:
 *   salt = pk1 || pk2
 *   PRK  = HMAC-SHA256(sharedSecret, salt)   [extract]
 *   OKM  = HMAC-SHA256("zaptransfer-sas-v1" || 0x01, PRK)[0..7]
 *
 * @param {Uint8Array} sharedSecret - 32-byte DH shared secret.
 * @param {Uint8Array} pk1          - First  party's 32-byte public key.
 * @param {Uint8Array} pk2          - Second party's 32-byte public key.
 * @returns {Uint8Array} 8-byte SAS value.
 */
export function deriveSAS(sharedSecret, pk1, pk2) {
  // Bind both public keys as salt to prevent unknown-key-share attacks.
  const salt = new Uint8Array(pk1.length + pk2.length);
  salt.set(pk1);
  salt.set(pk2, pk1.length);

  const prk  = hkdfExtract(sharedSecret, salt);
  const info = new TextEncoder().encode('zaptransfer-sas-v1');
  return hkdfExpand32(prk, info).slice(0, 8);
}

/**
 * Map a 8-byte SAS value to 4 emoji strings from the SAS_EMOJI table.
 *
 * Each pair of bytes is interpreted as a big-endian uint16, then taken
 * modulo 256 to index into the emoji table.
 *
 * @param {Uint8Array} sasBytes - 8-byte SAS value from deriveSAS().
 * @returns {string[]} Array of 4 emoji strings.
 */
export function sasToEmoji(sasBytes) {
  const emojis = [];
  for (let i = 0; i < 4; i++) {
    // Combine two bytes into a 16-bit value, then reduce to 0-255.
    const index = ((sasBytes[i * 2] << 8) | sasBytes[i * 2 + 1]) % 256;
    emojis.push(SAS_EMOJI[index]);
  }
  return emojis;
}
