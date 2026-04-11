# Beam crypto test vectors

Canonical byte-exact test vectors for the Beam E2E encryption scheme, generated
from a third-party implementation (PyNaCl / libsodium) to prevent drift between
the Chrome extension and Android client.

## Files

- `crypto-v1.json` — vectors for protocol version 1 (see
  `docs/superpowers/specs/2026-04-10-e2e-encryption-design.md`).

## Regeneration

```
python server/scripts/gen-test-vectors.py
```

This script uses fixed inputs, so the output is deterministic. If you need to
regenerate, commit both the script and the JSON together so both clients stay
in sync.

## Consumers

Both of the following test suites MUST load `crypto-v1.json` and assert
byte-exact equality on every field before any other assertion runs:

- Chrome: `extension/crypto/beam-crypto.test.js`
- Android: `android/app/src/test/java/com/zaptransfer/android/crypto/SessionCipherTest.kt`

If either client drifts from these vectors the build must fail.

## Contents

Each vector file contains:

- **inputs** — fixed static and ephemeral X25519 keypairs, salt, transferId.
- **tripleDH** — expected `dh1`, `dh2`, `dh3`, and concatenated `ikm`.
- **transcript** — SHA-256 transcript hash binding version + identities + ephemerals + transferId.
- **keys** — derived `sessionKey`, `chunkKey`, `metaKey` (HKDF-SHA256).
- **clipboard** — one sealed clipboard payload at index 0.
- **fileMetadata** — encrypted metadata envelope.
- **fileChunks** — three file chunks at indices 1..3, two full-size and one partial.

All byte fields are hex-encoded. Large ciphertexts use `ciphertextSha256` /
`plaintextSha256` digests rather than the raw bytes to keep the vector file
small. Clients must reproduce both the digest and the length.
