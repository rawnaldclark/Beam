# Beam E2E Encryption Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add true E2E encryption (Triple-DH + XChaCha20-Poly1305) to all Beam clipboard and file transfers with forward secrecy.

**Spec:** `docs/superpowers/specs/2026-04-10-e2e-encryption-design.md`

**Architecture:** Per-transfer Triple-DH handshake using long-term X25519 identity keys plus one ephemeral per side. Derives sessionKey → chunkKey/metaKey via HKDF-SHA256 with transcript-bound info. XChaCha20-Poly1305 AEAD with deterministic nonces HMAC(chunkKey, index). Test vectors generated from Python `pynacl` enforce byte-compatibility between Chrome and Android.

**Tech Stack:** libsodium (Android JVM + Chrome WASM), Python `pynacl` for vectors, Node.js relay passthrough.

---

## Task 1: Generate cryptographic test vectors (Python)

**Files:**
- Create: `server/scripts/gen-test-vectors.py`
- Create: `server/test-vectors/crypto-v1.json`
- Create: `server/test-vectors/README.md`

**Context:** Both Chrome and Android must produce byte-identical output. This task produces the ground-truth vectors from a third implementation (PyNaCl) that both clients will be tested against.

- [ ] **Step 1:** Create `server/scripts/gen-test-vectors.py` using `pynacl` and `cryptography`. Fixed inputs: two 32-byte static X25519 keypairs (A, B), two 32-byte ephemeral X25519 keypairs, 32-byte salt, 16-byte transferId, version=1.
- [ ] **Step 2:** Script computes dh1/dh2/dh3 (initiator perspective), transcript hash per spec, HKDF derivations (sessionKey, chunkKey, metaKey), three sample AEAD encryptions (clipboard text, file metadata JSON, 3 file chunks of 200KB with padding).
- [ ] **Step 3:** Script emits JSON with all inputs and expected outputs (hex-encoded) to `server/test-vectors/crypto-v1.json`.
- [ ] **Step 4:** Run the script, verify output JSON is well-formed and reproducible (run twice, diff = empty).
- [ ] **Step 5:** Write `server/test-vectors/README.md` documenting the format and regeneration command.
- [ ] **Step 6:** Commit: `feat(crypto): add Python-generated test vectors for Triple-DH + AEAD`

---

## Task 2: Spike — libsodium in MV3 service worker

**Files:**
- Create: `extension/crypto/sodium-loader.js`
- Create: `extension/crypto/sodium-loader.spike.md` (short note on result)
- Modify: `extension/background.js` (temporary import for spike, reverted after)

**Context:** The design's primary approach is static ESM import of libsodium in the SW. This must be verified before the rest of the crypto module is built. If it fails, the fallback (offscreen proxy) becomes primary.

- [ ] **Step 1:** Copy `libsodium-wrappers-sumo/dist/modules-sumo-esm/` into `extension/lib/sodium-esm/`.
- [ ] **Step 2:** Create `sodium-loader.js` that exports `async function loadSodium()` which attempts `import('../lib/sodium-esm/libsodium-wrappers.mjs')` and awaits `sodium.ready`.
- [ ] **Step 3:** Add a temporary call in `background.js` SW startup that calls `loadSodium()` and logs `sodium.crypto_scalarmult_base(new Uint8Array(32))`.
- [ ] **Step 4:** Load the unpacked extension in Chrome, inspect SW console, verify either success (hex output) or capture exact error.
- [ ] **Step 5:** Write `sodium-loader.spike.md` recording: OUTCOME (primary ESM works | fallback required), error log if any, decision.
- [ ] **Step 6:** If primary works: keep `sodium-loader.js` exporting the ESM loader. If fallback required: rewrite `sodium-loader.js` to proxy to offscreen via `chrome.runtime.sendMessage`, and add offscreen handlers.
- [ ] **Step 7:** Revert the temporary logging from `background.js`.
- [ ] **Step 8:** Commit: `feat(crypto): add sodium loader (spike result: <primary|fallback>)`

---

## Task 3: Chrome crypto module

**Files:**
- Create: `extension/crypto/beam-crypto.js`
- Create: `extension/crypto/beam-crypto.test.html` (manual test runner page)
- Create: `extension/crypto/beam-crypto.test.js`
- Copy: `server/test-vectors/crypto-v1.json` → `extension/crypto/test-vectors-v1.json`

**Context:** Pure crypto module, no networking. Every function is tested against the Python vectors before integration.

- [ ] **Step 1:** Create `beam-crypto.js` exporting: `generateEphemeral()`, `computeTripleDH(role, staticSk, staticPk, ephSk, ephPk, peerStaticPk, peerEphPk)`, `computeTranscript(version, staticPkA, staticPkB, ephPkA, ephPkB, transferId)`, `deriveSession(ikm, salt, transcript)`, `deriveChunkKey(sessionKey)`, `deriveMetaKey(sessionKey)`, `deriveNonce(chunkKey, index)`, `buildAAD(kindByte, index, totalChunks, transcript)`, `encryptChunk(plaintext, chunkKey, index, totalChunks, kindByte, transcript)`, `decryptChunk(...)`, `encryptMetadata(json, metaKey, transcript)`, `decryptMetadata(...)`, `padPlaintext(bytes)`, `unpadPlaintext(bytes)`, `wipe(...keys)`.
- [ ] **Step 2:** Write `beam-crypto.test.js` that loads `test-vectors-v1.json` and asserts each step matches byte-for-byte: Triple-DH legs, transcript, sessionKey, chunkKey, metaKey, three chunk encryptions, metadata encryption.
- [ ] **Step 3:** Create `beam-crypto.test.html` that loads sodium-loader, beam-crypto, and the test file, runs all assertions, and prints PASS/FAIL with details.
- [ ] **Step 4:** Open the test page in Chrome (via `file://` or loaded extension context). Iterate until every vector passes.
- [ ] **Step 5:** Commit: `feat(crypto): chrome beam-crypto module passing test vectors`

---

## Task 4: Android crypto module update

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/crypto/SessionCipher.kt`
- Create: `android/app/src/test/java/com/zaptransfer/android/crypto/SessionCipherTest.kt`
- Copy: `server/test-vectors/crypto-v1.json` → `android/app/src/test/resources/crypto-v1.json`

**Context:** SessionCipher.kt exists but uses a different nonce scheme and AAD layout than the spec. Update to match, then verify against the same Python vectors.

- [ ] **Step 1:** Update `SessionCipher.kt` to match spec: transcript hash computation, HKDF info strings (`beam-session-v1 || transcript`, `beam-chunk-v1`, `beam-meta-v1`), nonce = `HMAC-SHA256(chunkKey, "beam-nonce-v1" || u64_be(i))[0..24]`, AAD = `"beam-aead-v1" || kind_byte || u32_be(index) || u32_be(totalChunks) || transcript`, length-prefixed padding.
- [ ] **Step 2:** Add `computeTripleDH(role, ...)` with initiator-perspective leg ordering matching the spec exactly.
- [ ] **Step 3:** Write `SessionCipherTest.kt` as a JVM unit test loading `crypto-v1.json` from test resources and asserting byte-equality on every derivation and encryption step.
- [ ] **Step 4:** Run `./gradlew :app:testDebugUnitTest --tests SessionCipherTest`. Iterate until green.
- [ ] **Step 5:** Commit: `feat(crypto): android SessionCipher matches spec and test vectors`

---

## Task 5: Handshake state machine + session registry

**Files:**
- Create: `extension/crypto/session-registry.js`
- Create: `android/app/src/main/java/com/zaptransfer/android/crypto/BeamHandshake.kt`
- Create: `android/app/src/main/java/com/zaptransfer/android/crypto/SessionRegistry.kt`
- Create tests for both.

**Context:** Implements the `PENDING_INIT → AWAITING_ACCEPT → ACTIVE → COMPLETING → DESTROYED` state machine, per-peer rate limiting, and timeouts. Stateless with respect to the wire — callers feed it events.

- [ ] **Step 1:** Chrome: `session-registry.js` with `Map<transferId, Session>`. Session holds `{state, role, ephSk, ephPk, salt, sessionKey?, chunkKey?, metaKey?, transcript?, createdAt, lastActivity, kind, totalChunks?}`. Methods: `startInit(peerId, kind) → {transferId, ephPk, salt}`, `onInit(peerId, msg) → {ephPk}|reject`, `onAccept(peerId, msg) → void|reject`, `get(transferId)`, `destroy(transferId)`, `sweep()` (timeout enforcement via `setInterval`), rate limit check.
- [ ] **Step 2:** Chrome: persist sender's `ephSk` + `salt` + `peerId` in `chrome.storage.session` keyed by transferId during PENDING/AWAITING; clear on ACTIVE or DESTROYED. Rehydrate on SW wake.
- [ ] **Step 3:** Chrome: write unit tests (under `extension/crypto/session-registry.test.js`, runnable from `beam-crypto.test.html`) covering happy path, timeout, duplicate transferId, rate limit, version mismatch.
- [ ] **Step 4:** Android: `BeamHandshake.kt` + `SessionRegistry.kt` mirroring the same API shape. In-memory `ConcurrentHashMap`, coroutine-based timeout sweep.
- [ ] **Step 5:** Android: JVM unit tests under `SessionRegistryTest.kt` covering the same cases.
- [ ] **Step 6:** Commit: `feat(crypto): handshake state machine + session registry (chrome + android)`

---

## Task 6: Server wire types + relay routing

**Files:**
- Modify: `server/src/protocol.js`
- Modify: `server/src/signaling.js`
- Modify: `server/src/server.js`
- Modify: `server/test/signaling.test.js` (or equivalent)

**Context:** Relay is a dumb passthrough for the new message types. Only adds routing and a handshake timeout.

- [ ] **Step 1:** Add `TRANSFER_INIT = "transfer-init"`, `TRANSFER_ACCEPT = "transfer-accept"`, `TRANSFER_REJECT = "transfer-reject"` to `protocol.js`.
- [ ] **Step 2:** Add all three to `SIGNALING_TYPES` in `signaling.js`. Route via existing sender/target rendezvous validation.
- [ ] **Step 3:** Add switch cases in `server.js` routing each to `signaling.handleMessage()`.
- [ ] **Step 4:** Add a relay-side orphan cleanup: track `transferId → {createdAt}` in signaling, reap entries older than 30s, log warning. (Minimal — this is a soft guard, clients have their own timeout.)
- [ ] **Step 5:** Add unit tests: `transfer-init` from A reaches B; `transfer-accept` from B reaches A; unpaired sender is rejected; message with no target is dropped.
- [ ] **Step 6:** Run `npm test` in server/, verify all existing tests still pass plus new ones.
- [ ] **Step 7:** Commit: `feat(relay): route transfer-init/accept/reject handshake messages`

---

## Task 7: Clipboard encryption integration

**Files:**
- Modify: `extension/background.js` (sendClipboard path)
- Modify: `extension/background-relay.js` (receive path)
- Modify: `android/.../ui/devicehub/DeviceHubViewModel.kt` (sendClipboard + relayListener)

**Context:** Clipboard is the simplest transfer — one plaintext, one chunk, no metadata envelope. Good smoke test for the full handshake before tackling files.

- [ ] **Step 1:** Chrome `sendClipboard(targetDeviceId, text)`: call `sessionRegistry.startInit(targetDeviceId, "clipboard")`, send `transfer-init`, wait for `transfer-accept` (with 10s timeout), derive keys, encrypt text as single chunk (index 0, totalChunks 1), send binary frame. Destroy session.
- [ ] **Step 2:** Chrome `background-relay.js` handler for `transfer-init` with `kind: "clipboard"`: derive keys immediately, send `transfer-accept`, mark session ACTIVE awaiting one binary frame. On binary frame: decrypt, deliver plaintext to existing clipboard-paste code path, destroy session.
- [ ] **Step 3:** Chrome handler for `transfer-accept`: look up session, transition to ACTIVE, derive keys, resolve the pending send promise.
- [ ] **Step 4:** Chrome handler for `transfer-reject`: destroy session, surface error to UI.
- [ ] **Step 5:** Android `sendClipboard`: mirror chrome flow via `BeamHandshake`, encrypt via `SessionCipher`, send as single binary frame.
- [ ] **Step 6:** Android `relayListener` `transfer-init`/`transfer-accept`/`transfer-reject` + binary frame decrypt for clipboard kind.
- [ ] **Step 7:** Manual E2E test: Chrome → Android clipboard, Android → Chrome clipboard. Verify relay logs show only ciphertext for the data frame.
- [ ] **Step 8:** Commit: `feat(crypto): encrypted clipboard transfers`

---

## Task 8: File encryption integration

**Files:**
- Modify: `extension/background.js` (sendFileViaRelay)
- Modify: `extension/background-relay.js` (file receive path)
- Modify: `android/.../ui/devicehub/DeviceHubViewModel.kt` (sendFile + relayListener file path)

**Context:** Builds on Task 7. Adds encrypted metadata envelope and per-chunk encryption with totalChunks truncation protection.

- [ ] **Step 1:** Chrome `sendFileViaRelay`: handshake with `kind: "file"`, compute `totalChunks = ceil(fileSize / 200KB)`, encrypt metadata JSON `{fileName, fileSize, mime, totalChunks}` with index 0 / kind_byte 0x02, send `file-offer { transferId, envelope }`, then encrypt each 200KB chunk with index 1..N / kind_byte 0x03, send as binary frame. Send `file-complete`. Destroy session.
- [ ] **Step 2:** Chrome receive: on `transfer-init kind:"file"` → handshake. On `file-offer` → decrypt metadata, store `totalChunks` on session. On binary frames → decrypt with chunkKey, accumulate. On final chunk (bytesReceived matches and count == totalChunks) → assemble and route. If count mismatch on `file-complete` → abort.
- [ ] **Step 3:** Android mirror: `sendFile` runs handshake, encrypts metadata, encrypts chunks, sends `file-complete`.
- [ ] **Step 4:** Android receive: decrypt metadata envelope, decrypt chunks, enforce totalChunks, route to existing save/open flow.
- [ ] **Step 5:** Manual E2E: Chrome → Android 1MB image, Android → Chrome 50MB file. Verify relay logs show only ciphertext. Verify tamper: manually drop one chunk in relay → receiver aborts with clear error.
- [ ] **Step 6:** Commit: `feat(crypto): encrypted file transfers with truncation protection`

---

## Task 9: Error handling, rate limits, UX polish

**Files:**
- Modify: `extension/background-relay.js`
- Modify: `extension/popup/popup.js` (error surfacing)
- Modify: `android/.../ui/devicehub/DeviceHubScreen.kt` (error surfacing)
- Modify: `android/.../crypto/SessionRegistry.kt`

**Context:** Wire up the `errorCode` enum to UI messages, enforce rate limits, confirm timeout paths surface cleanly.

- [ ] **Step 1:** Both clients: map `errorCode` enum to user-facing strings (`VERSION` → "Update required", `TIMEOUT` → "Peer didn't respond", `RATE_LIMIT` → "Too many transfers", `DECRYPT_FAIL` → "Decryption failed — keys may not match", `BAD_TRANSCRIPT` → "Security check failed", `INTERNAL` → "Something went wrong").
- [ ] **Step 2:** Enforce rate limit in `session-registry.js` and `SessionRegistry.kt`: max 5 pending handshakes per peer, max 20/sec global. Over-limit → send `transfer-reject { errorCode: "RATE_LIMIT" }` and do not create session.
- [ ] **Step 3:** Surface rejections as toast/notification on both platforms.
- [ ] **Step 4:** Manual test: trigger timeout (block peer after init), trigger decrypt fail (tamper with a chunk in relay), trigger rate limit (script 10 rapid sends). Verify UI shows each error distinctly.
- [ ] **Step 5:** Commit: `feat(crypto): error code UX and rate limiting`

---

## Task 10: Final integration test and cleanup

**Files:**
- Modify: `README.md` (if exists) — brief mention of E2E encryption
- Delete: any debug logging added during development

**Context:** Final pass to verify the whole system works and remove scaffolding.

- [ ] **Step 1:** Full E2E scenario: pair fresh devices → send clipboard Chrome→Android → send clipboard Android→Chrome → send 10MB file Chrome→Android → send 100MB file Android→Chrome. All succeed, all relay frames for data are ciphertext.
- [ ] **Step 2:** Run full server test suite (`npm test` in server/) — all green.
- [ ] **Step 3:** Run Android unit tests (`./gradlew :app:testDebugUnitTest`) — all green.
- [ ] **Step 4:** Load Chrome crypto test page — all vectors pass.
- [ ] **Step 5:** Remove any temporary debug logging.
- [ ] **Step 6:** Commit: `chore(crypto): final cleanup, all tests green`
