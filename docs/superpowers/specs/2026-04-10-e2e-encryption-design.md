# Beam E2E Encryption Design

**Status:** Approved
**Date:** 2026-04-10

## Goal

Add true end-to-end encryption to all Beam transfers (clipboard + files) with forward secrecy, so the relay server and any network observer cannot read transfer contents even if long-term keys are later compromised.

## Threat Model

**In scope:**
- Passive relay observing all traffic
- Active relay modifying, reordering, or replaying messages
- Compromise of long-term identity keys *after* a transfer (forward secrecy)
- Network attackers between client and relay

**Out of scope:**
- Endpoint compromise (malware on the phone/laptop)
- Side-channel attacks on libsodium
- Traffic analysis (relay sees byte counts and timing)
- Post-compromise security (future transfers after key compromise — user must re-pair)

## Cryptographic Primitives

| Purpose | Primitive | libsodium function |
|---|---|---|
| AEAD | XChaCha20-Poly1305 | `crypto_aead_xchacha20poly1305_ietf_*` |
| Key exchange | X25519 | `crypto_scalarmult` |
| KDF | HKDF-SHA256 | `crypto_kdf_hkdf_sha256_*` |
| Hash | SHA-256 | `crypto_hash_sha256` |
| Nonce derivation | HMAC-SHA256 | `crypto_auth_hmacsha256` |
| Best-effort wipe | `sodium.memzero` | (documented as best-effort in JS/JVM) |

## Handshake: Beam Triple-DH v1

Not X3DH — Beam has no signed prekeys or one-time prekeys. Each transfer runs a fresh Triple-DH using the peers' long-term X25519 identity keys plus one ephemeral per side.

### Wire messages

Added to relay `SIGNALING_TYPES`:

```
transfer-init     { v: 1, transferId, kind, ephPkA, salt }
transfer-accept   { v: 1, transferId, ephPkB }
transfer-reject   { v: 1, transferId, errorCode }
```

- `v`: protocol version (u8). Receiver MUST reject unknown versions with `transfer-reject { errorCode: "VERSION" }`.
- `transferId`: 128-bit random, base64url, chosen by initiator. Receiver MUST reject duplicate IDs within an active session.
- `kind`: `"clipboard"` or `"file"`.
- `ephPkA` / `ephPkB`: 32-byte X25519 public keys, base64url.
- `salt`: 32-byte random, base64url, chosen by initiator.
- `errorCode`: enum: `VERSION`, `TIMEOUT`, `RATE_LIMIT`, `DECRYPT_FAIL`, `BAD_TRANSCRIPT`, `INTERNAL`.

### Role labels

The party that sends `transfer-init` is **A (initiator)**. The party that sends `transfer-accept` is **B (responder)**. All key derivation is defined from the initiator's perspective; both sides concatenate in the same order regardless of which side is computing.

### Triple-DH legs

Both sides compute, in initiator perspective:

```
dh1 = X25519(staticSk_A, ephPk_B)   // initiator static × responder ephemeral
dh2 = X25519(ephSk_A,    staticPk_B) // initiator ephemeral × responder static
dh3 = X25519(ephSk_A,    ephPk_B)    // ephemeral × ephemeral
```

The responder computes the mirror:

```
dh1 = X25519(ephSk_B,    staticPk_A)
dh2 = X25519(staticSk_B, ephPk_A)
dh3 = X25519(ephSk_B,    ephPk_A)
```

These produce byte-identical `dh1`, `dh2`, `dh3` on both sides. Concatenation order is fixed: `dh1 || dh2 || dh3`.

### Transcript hash

```
transcript = SHA-256(
  "beam-transcript-v1" ||
  u8(version) ||
  staticPk_A || staticPk_B ||
  ephPk_A    || ephPk_B    ||
  transferId_bytes
)
```

Identity binding: any swap of static or ephemeral keys yields a different transcript, so both sides derive different session keys and decryption fails. This defeats unknown key-share and identity misbinding attacks by a malicious relay.

### Key derivation

```
ikm        = dh1 || dh2 || dh3
prk        = HKDF-Extract(salt = salt, ikm = ikm)
sessionKey = HKDF-Expand(prk, info = "beam-session-v1" || transcript, L = 32)
chunkKey   = HKDF-Expand(sessionKey, info = "beam-chunk-v1",   L = 32)
metaKey    = HKDF-Expand(sessionKey, info = "beam-meta-v1",    L = 32)
```

After derivation, ephemeral private keys are wiped via `sodium.memzero` (best-effort in JS/JVM — documented).

## Nonce Derivation

All nonces are deterministic per (chunkKey, index) — safe because `chunkKey` is unique per transfer (fresh Triple-DH).

```
nonce(i) = HMAC-SHA256(chunkKey, "beam-nonce-v1" || u64_be(i))[0..24]
```

`transferId` is **not** used in nonce derivation to eliminate attacker-controlled input concerns. The per-transfer uniqueness of `chunkKey` is what guarantees global nonce uniqueness.

Indices:
- `i = 0` reserved for encrypted file metadata
- `i = 1..N` for file chunks
- For `kind: "clipboard"`, only `i = 0` is used (single sealed blob)

## AAD Layout

```
AAD = "beam-aead-v1" || kind_byte || u32_be(index) || u32_be(totalChunks) || transcript
```

- `kind_byte`: `0x01` = clipboard, `0x02` = file-metadata, `0x03` = file-chunk
- `totalChunks`: 0 for clipboard and file-metadata, N for file chunks
- Binding AAD to `transcript` means any identity confusion fails the authenticator.

## Payload Formats

### Encrypted metadata (file-offer)

Plaintext JSON:
```json
{ "fileName": "...", "fileSize": 12345, "mime": "...", "totalChunks": N }
```

Wire (extends existing `file-offer`):
```json
{
  "type": "file-offer",
  "transferId": "...",
  "envelope": { "nonce": "<b64>", "ciphertext": "<b64>" }
}
```

Encrypted with `metaKey`, index `0`, `kind_byte=0x02`.

### Encrypted clipboard

Unified onto the binary path — clipboard is a single encrypted chunk, not a JSON-wrapped base64 blob. Flow mirrors file transfer with `kind: "clipboard"`, `totalChunks = 1`, one binary frame.

### File chunks

Wire format per binary frame (unchanged framing, encrypted payload):
```
[u32_be index][ciphertext || poly1305_tag]
```

Plaintext before encryption is padded to the next power-of-2 bucket with a 4-byte big-endian length prefix:
```
plaintext_padded = u32_be(actual_len) || data || zero_pad
```

Receiver reads the length prefix after decryption and discards the padding.

Padding caveat: hides exact size, **not** order of magnitude. Acceptable because the relay already observes total bytes transferred.

## Session Lifecycle

State machine per `transferId`:

```
PENDING_INIT   → sender: ephemeral generated, transfer-init sent
                  timeout 10s → DESTROYED (errorCode TIMEOUT)
AWAITING_ACCEPT → sender only; receiving transfer-accept → ACTIVE
ACTIVE         → both sides; derives keys, encrypts/decrypts
                  inactivity timeout 60s → DESTROYED
COMPLETING     → final chunk decrypted OK; totalChunks matches
DESTROYED      → sodium.memzero(all keys); entry removed
```

Receiver-side:
- On `transfer-init`: immediately derive keys, transition directly to `ACTIVE`, send `transfer-accept`.
- Rate limit: max 5 pending handshakes per peer, max 20 handshakes/second globally. Excess → `transfer-reject { errorCode: "RATE_LIMIT" }`.

Sender-side ephemeral persistence (Chrome SW):
- Sender's `ephSk_A` is persisted in `chrome.storage.session` (memory-backed, cleared on browser close) keyed by `transferId` during `PENDING_INIT` / `AWAITING_ACCEPT`, to survive SW restarts during the handshake window.
- Deleted on transition to `ACTIVE` or `DESTROYED`.

Android does not have the SW death problem; ephemerals live in `PairingSession`-style in-memory state.

## File Integrity

Per-chunk AEAD prevents tampering within each chunk. To prevent truncation, the encrypted file-metadata envelope carries `totalChunks`, and the receiver refuses to finalize the file until exactly `totalChunks` chunks have decrypted successfully and in order (indices 1..N with no gaps). Missing chunks → abort, delete partial file, surface "transfer incomplete" error.

Out-of-order / dropped chunks → same as current behavior: abort whole transfer. No partial-resume in v1.

## Chrome libsodium Loading

**Primary approach:** Static ES module import of `libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs` inside the MV3 service worker (already `"type": "module"`). CSP `wasm-unsafe-eval` is already granted.

**Required spike (Task 1 of implementation plan):** Verify the ESM import works under MV3. If it fails (module resolution, WASM instantiation, top-level `await`), fall back to:

**Fallback approach:** Proxy all crypto operations to the existing offscreen document (which already loads the UMD build successfully). SW ↔ offscreen messages: `crypto/derive-session`, `crypto/encrypt-chunk`, `crypto/decrypt-chunk`, etc.

The crypto module API is the same in both cases so only the backing implementation changes.

## Cross-Platform Compatibility

To prevent drift between Chrome and Android implementations:

1. **Test vectors written first, from a third source.** A Python script using `pynacl` / `cryptography` generates a JSON file of test vectors: fixed static keys, fixed ephemerals, fixed salt, fixed plaintexts → expected ciphertexts, expected session/chunk/meta keys, expected transcript hash. Committed to `server/test-vectors/crypto-v1.json`.
2. Both Chrome and Android crypto modules have a test suite that loads this file and asserts byte-exact match before any other test runs.
3. CI runs both test suites; any drift fails the build.

## Security Properties (Claimed)

- **Confidentiality vs relay:** Relay sees only ciphertext, ephemeral public keys, and framing metadata.
- **Forward secrecy:** Compromise of long-term static keys does not reveal past transfers (ephemerals are wiped).
- **Authentication:** Triple-DH mixes both static keys; only the true paired peer derives the same session key.
- **Identity binding:** Transcript hash in HKDF info prevents unknown key-share attacks.
- **Integrity:** Per-chunk AEAD + `totalChunks` check in encrypted metadata prevents tampering and truncation.
- **Replay resistance:** Fresh ephemerals per transfer; receiver rejects duplicate `transferId` within a session.

## Security Properties (NOT Claimed)

- **Memory zeroization:** Best-effort only. JS and JVM runtimes may retain buffer copies beyond `sodium.memzero`.
- **Post-compromise security:** If long-term keys leak, future transfers are compromised until user re-pairs.
- **Traffic analysis resistance:** Relay sees timing, frequency, and rough size buckets.
- **Denial of service resistance beyond rate limiting:** A determined attacker with valid pairing can exhaust handshake slots up to the rate limit.

## File / Component Changes

### Server (`server/`)
- `src/protocol.js`: add `TRANSFER_INIT`, `TRANSFER_ACCEPT`, `TRANSFER_REJECT` message types
- `src/signaling.js`: add to `SIGNALING_TYPES`, relay to target with sender/target rendezvous validation (same as existing types)
- Add relay-side handshake timeout (30s) to prevent orphaned state
- `test-vectors/crypto-v1.json`: generated test vector file
- `scripts/gen-test-vectors.py`: Python script to generate test vectors

### Chrome extension (`extension/`)
- `extension/crypto/beam-crypto.js` (new): public API — `generateEphemeral`, `deriveSession`, `encryptChunk`, `decryptChunk`, `encryptMetadata`, `decryptMetadata`, `hashTranscript`, `wipeSession`
- `extension/crypto/sodium-loader.js` (new): primary ESM import + offscreen fallback
- `extension/crypto/beam-crypto.test.js` (new): test vector suite
- `extension/background.js`: integrate handshake into `sendClipboard`, `sendFileViaRelay`
- `extension/background-relay.js`: handle `transfer-init`, `transfer-accept`, `transfer-reject`; decrypt incoming; session map; rate limiting
- `extension/offscreen/transfer-engine.js`: add crypto proxy handlers (fallback path)

### Android (`android/`)
- `crypto/SessionCipher.kt`: update to match spec (transcript binding in HKDF info, AAD format, nonce derivation from `chunkKey` only)
- `crypto/BeamHandshake.kt` (new): Triple-DH handshake state machine
- `crypto/SessionRegistry.kt` (new): in-memory map of active sessions with lifecycle + timeout
- `crypto/CryptoTestVectors.kt` (new): test vector suite
- `ui/devicehub/DeviceHubViewModel.kt`: integrate handshake into `sendClipboard`, `sendFile`, `relayListener`

## Open Questions

None blocking — all previously-identified concerns integrated into this design.

## Implementation Order (Sketch)

1. Write test vectors (Python)
2. Spike SW libsodium loading — decide primary vs fallback
3. Chrome `beam-crypto.js` + tests (vectors pass)
4. Android `SessionCipher.kt` update + tests (vectors pass)
5. Handshake state machine (both sides)
6. Server wire types + routing + relay timeout
7. Integrate into clipboard send/receive (both sides)
8. Integrate into file send/receive (both sides)
9. Rate limiting + error codes
10. End-to-end test: Chrome ↔ Android clipboard and file with wireshark/relay log showing only ciphertext
