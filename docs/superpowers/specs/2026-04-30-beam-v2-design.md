# Beam v2 — Stateless E2E Transfer Encryption

**Status:** Draft
**Date:** 2026-04-30
**Replaces:** [`2026-04-10-e2e-encryption-design.md`](./2026-04-10-e2e-encryption-design.md) (Beam v1)

## Why v2

Beam v1 wraps every transfer in a Triple-DH handshake (`transfer-init` → `transfer-accept` → keys → frames). The handshake is correct in isolation but its **state** — pending-accept waiters, ephemeral keys, derived chunk/meta keys, `relay-bind` membership — lives in service-worker memory. Chrome MV3 terminates service workers at any time. Every state cell is a correctness liability that has produced reliability bugs (orphan WebSocket onclose, lost pendingAccepts, dropped chunk decrypt context) that recur in different shapes after each individual fix.

The handshake also doubles the implementation surface (Kotlin + JS), and any divergence — transcript byte-order, AAD layout, base64url padding — is a silent decrypt failure.

**v2 deletes the handshake.** Pairing produces one long-lived symmetric key per peer pair. Every transfer is one or more independent AEAD frames the receiver decrypts immediately. There is no per-transfer state on either side, no in-flight handshake to lose, and one round-trip becomes zero.

## Threat model — diff from v1

**In scope (unchanged from v1):** passive relay, active relay, network adversary, transcript binding against MITM.

**Forward-secrecy story changes.** v1 derived per-transfer keys from per-transfer ephemerals; an attacker who later steals `staticSk` could not decrypt past traffic. v2 derives a long-lived `K_AB` at pairing time; an attacker who steals `K_AB` decrypts every transfer ever sent under that pairing.

**Why this is acceptable for our use case.** The relevant attacker model for Beam is "someone gains access to the user's already-paired device." Such an attacker reads the device's filesystem, including `chrome.storage.local` (which holds `staticSk`) or Android Keystore-protected keys. Per-transfer ephemerals only protect past traffic if they are wiped before that compromise — but v1 keeps them mirrored in `chrome.storage.session` until the transfer completes, which is the same attack window. The marginal forward-secrecy benefit is near zero and is paid for with multi-thousand-line state machinery.

If true post-compromise forward secrecy is later required, it is added cleanly via key rotation (§Key Rotation) rather than per-transfer ephemerals.

**Newly out of scope:** breaking K_AB recovers all traffic since the last rotation. Mitigated by §Key Rotation.

## Cryptographic primitives

Same as v1.

| Purpose | Primitive | libsodium function |
|---|---|---|
| AEAD | XChaCha20-Poly1305 | `crypto_aead_xchacha20poly1305_ietf_*` |
| Key exchange | X25519 | `crypto_scalarmult` |
| KDF | HKDF-SHA256 | `crypto_kdf_hkdf_sha256_*` |
| Identity | Ed25519 (relay auth only) | n/a here |

XChaCha20's 24-byte nonce gives 2^192 random-nonce safety, eliminating any need for sender-side counter state.

## Pairing produces K_AB

During the existing pairing ceremony (QR + SAS, unchanged) both sides know:

```
staticSk_self (32B)            our X25519 private key
staticPk_self (32B)            our X25519 public key
staticPk_peer (32B)            peer's X25519 public key (from QR or pairing-request)
ed25519Pk_self, ed25519Pk_peer (32B each)
```

After SAS confirmation, both sides derive:

```
ikm   = X25519(staticSk_self, staticPk_peer)               // 32B, identical on both sides
salt  = SHA-256( sort_lex(ed25519Pk_A, ed25519Pk_B) )      // 32B, deterministic over the pair
info  = "beam-v2-pairing-key/" || generation_u32_be       // generation starts at 0
K_AB  = HKDF-SHA256(ikm, salt, info, 32)
```

The `generation` counter enables key rotation (§Key Rotation) without changing the format. Lex-sorted ed25519 keys make the salt symmetric — both sides compute the same value without role coordination.

`K_AB` is stored alongside the existing peer record:

- **Chrome:** `pairedDevices[i].kAB` (Array<number>, base64 in storage), `pairedDevices[i].kABGen` (integer)
- **Android:** new columns on `paired_devices`: `k_ab BLOB NOT NULL`, `k_ab_generation INTEGER NOT NULL DEFAULT 0`

Existing `x25519PublicKey` and `ed25519PublicKey` columns are retained (still needed for relay auth and for rotation).

## Wire format

A v2 transfer is a sequence of one or more **frames**. Frames for a single transfer share a `transferId`; frames from different transfers are independent and may interleave.

Header is 48 bytes, fixed:

```
offset  size  field
   0      4   magic   = 'B' 'E' 'A' '2'   (0x42 0x45 0x41 0x32)
   4      1   version = 0x02
   5      1   flags
                bit 0 (LSB) = isFinal      — last frame of this transfer
                bit 1       = hasMeta      — frame's plaintext begins with the meta JSON
                bits 2..7   = reserved, MUST be zero
   6      2   reserved, MUST be zero
   8     16   transferId   (16 random bytes per transfer)
  24      4   index        (u32 BE)
  28      4   kAB_generation (u32 BE) — selects which K_AB to use
  32     16   reserved, MUST be zero
  48      *   nonce + ciphertext        — see below
```

Bytes 48..72 are the AEAD nonce (24 bytes, freshly random per frame). Bytes 72.. are the XChaCha20-Poly1305 ciphertext, which already contains the 16-byte Poly1305 tag at its tail.

The 48-byte header is the AEAD `additional_data`. This binds version, transfer identity, sequence position, final-flag, and key-generation to the ciphertext — any tamper or reorder fails decrypt.

### Plaintext shape

The first frame of every transfer (frame at `index = 0`) MUST set `flags.hasMeta`. Its plaintext is:

```
2 bytes   meta-length (u16 BE)         — always > 0
N bytes   meta JSON                    — UTF-8, lengths defined below
M bytes   payload                      — optional, 0 bytes for kind="file"
```

Where the meta JSON is exactly one of:

```jsonc
// kind = clipboard: 1-frame transfer (isFinal=1 on this same frame)
{ "kind": "clipboard", "v": 2 }

// kind = file: N+1-frame transfer (isFinal=1 on the last chunk frame)
{
  "kind": "file",
  "v": 2,
  "fileName":    "report.pdf",     // 1..255 UTF-8 bytes
  "fileSize":    1234567,          // integer, > 0, <= 500_000_000
  "mime":        "application/pdf",// non-empty UTF-8
  "totalChunks": 7                 // integer, > 0, <= 3000
}
```

For `kind="clipboard"` the payload bytes immediately following meta are the UTF-8 clipboard text (length implied by `ciphertext_len - 2 - meta_len`).

For `kind="file"` the meta frame carries no payload. Subsequent frames at `index = 1..totalChunks` MUST clear `flags.hasMeta`; their plaintext is the raw chunk bytes (variable length, last chunk may be short). The frame at `index = totalChunks` MUST set `flags.isFinal`.

### Encrypt / decrypt

```
fn encrypt_frame(K_AB, header, plaintext) -> ciphertext:
    nonce = random_bytes(24)
    ct    = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, header, nonce, K_AB)
    return nonce || ct

fn decrypt_frame(K_AB_by_gen, full_frame) -> plaintext:
    header = full_frame[0..48]
    require header[0..4]    == 'BEA2'
    require header[4]       == 0x02
    require (header[5] & 0xFC) == 0
    require header[6..8]    == 00 00
    require header[32..48]  == 0..0
    gen     = u32_be(header[28..32])
    K       = K_AB_by_gen(gen)            // null → drop frame, log mismatch
    nonce   = full_frame[48..72]
    ct      = full_frame[72..]
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, header, nonce, K)
        // any failure: drop frame, mark transferId as poisoned
```

There is no transfer-init, transfer-accept, file-complete, or relay-release JSON message in v2. The relay still routes binary frames between paired peers exactly as today; the existing `relay-bind` JSON is **kept** for now (relay-side session tracking and bandwidth accounting) but becomes a one-shot init that the sender fires immediately before the first frame and never has to await.

## Receiver state machine

Per `transferId`, the receiver holds (in memory; no persistence required):

```
{ kind, totalChunks, chunksReceived, plainBuffer, deliveredAt }
```

This state is created when frame `index=0` arrives, populated as chunks decrypt, and **discarded** as soon as `isFinal` is processed. If the SW dies mid-file:

- v1: session keys are gone, all received chunks become un-decryptable garbage.
- v2: K_AB is in `chrome.storage.local`, so on SW wake the receiver simply has missing chunks; sender retransmits (§Retry semantics).

Idle-cleanup: any `transferId` with no new frames for 60 seconds is dropped.

## Sender semantics

`sendClipboardEncrypted(targetDeviceId, text)`:

1. Look up `K_AB`, `kAB_generation` from peer record.
2. Build frame: `index=0, hasMeta=1, isFinal=1, plaintext = u16BE(metaLen) || meta || textBytes`.
3. `pairingWs.send(frame)`. Done.

`sendFileEncrypted(targetDeviceId, {name, size, mime, bytes})`:

1. Compute `totalChunks = ceil(size / FILE_CHUNK_SIZE)` (200 KB plaintext).
2. Send frame 0: `hasMeta=1, isFinal=0`, plaintext = meta JSON.
3. For `i in 1..totalChunks`: send frame `i` with `isFinal = (i == totalChunks)`, plaintext = chunk bytes. 20 ms spacing between chunks (unchanged from v1's flow control).

Send is fire-and-forget. There is no awaitable promise inside the crypto layer; the popup's progress bar is driven off `progress` events the SW emits when each frame is buffered, not off cryptographic acks.

## Retry semantics — day-1 scope

v1 had no retry; a dropped frame meant a corrupt file. v2 ships retransmit on day 1.

**Receiver triggers** (whichever fires first):

1. `isFinal` received but `chunksReceived < totalChunks` — request immediately.
2. No new frame for any active `transferId` for `RECEIVE_GAP_MS = 5_000` — request the gap.

**Receiver request:**

```jsonc
{
  "type": "beam-v2-resend",
  "transferId": "<base64url(16)>",
  "missing": [3, 7, 12]   // ascending, deduped, frame indices including 0 if meta missing
}
```

Sent over the existing pairing WebSocket as a JSON message. The relay routes it to the sender via the same rendezvous lookup used for v1 JSON traffic.

**Sender response:**

- Re-encrypts each requested frame from the original plaintext (still in memory while the send promise is unresolved). Each retransmit MUST use a **fresh random nonce** — reusing a nonce with the same key breaks XChaCha20-Poly1305.
- Re-uses the original `transferId`, `index`, `flags`, `kAB_generation`. Receiver's AAD-bound dedupe naturally accepts the replacement.
- Sender enforces a per-transfer cap of `MAX_RESENDS = 2` rounds. After the cap or after `SENDER_GIVEUP_MS = 30_000` since first send, sender emits `{type: "beam-v2-fail", transferId, code: "PARTIAL"}` and the UX surfaces the error.

**Receiver give-up:** if no new frames arrive for `RECEIVER_GIVEUP_MS = 60_000` after a resend request, drop the transfer state and surface error.

**Why these numbers:** 5 s gap is long enough to absorb network jitter and SW wake latency; 60 s give-up bounds memory growth on stalled transfers; 2 retries keeps the worst-case bandwidth at 3× without unbounded loops.

Constants live in one shared header file imported by both implementations to prevent drift.

## Key rotation — day-1 scope

User-initiated rotation ships in the first build. Two triggers:

1. **Manual:** "Rotate keys" button in device-detail / settings. Either side may initiate; the side that taps the button is the **rotation initiator**.
2. **Automatic re-pair:** when the existing re-pair flow completes for an already-paired peer, treat it as an implicit rotation rather than a fresh pairing (the X25519 keys may not have changed).

**Wire protocol** — three new JSON messages over the pairing WebSocket:

```jsonc
// initiator → peer
{ "type": "beam-v2-rotate-init", "fromGen": 3, "toGen": 4, "nonce": "<base64url(16)>" }

// peer → initiator (acknowledges; both sides now know toGen)
{ "type": "beam-v2-rotate-ack",  "fromGen": 3, "toGen": 4, "nonce": "<echoed>" }

// initiator → peer (commits; both sides switch primary to toGen)
{ "type": "beam-v2-rotate-commit", "toGen": 4 }
```

The 16-byte nonce is mixed into the new generation's HKDF info string to ensure the new key differs from a hypothetical replay of the old derivation:

```
info_new = "beam-v2-pairing-key/" || u32_be(toGen) || nonce
K_AB_new = HKDF-SHA256(ikm, salt, info_new, 32)
```

`ikm` and `salt` are unchanged — `ikm` is still `X25519(staticSk_self, staticPk_peer)` from the original pairing, so rotation does not require any user-visible re-scan.

**Storage model** — both sides keep a small ring of generations:

```
{
  "currentGeneration": 4,
  "keys": {
    "4": { "kAB": "<32B base64>", "createdAt": 1745958123, "rotateNonce": "<16B base64>" },
    "3": { "kAB": "<32B base64>", "createdAt": 1745869872, "expiresAt": 1745956272 }
  }
}
```

- `currentGeneration` is the gen used by **outgoing** frames.
- `keys[g]` for `g <= currentGeneration` are accepted by `decrypt_frame`. Frames with unknown gen are dropped (logged once).
- On rotate-commit, the previous gen gets `expiresAt = now + ROTATION_GRACE_MS (24 h)`.
- Sweeper (runs at SW boot and on each rotation) deletes any gen with `expiresAt < now`.

**Race tolerance:** if both sides hit "Rotate" at the same moment, both will send rotate-init. The side with the lexicographically smaller deviceId wins; the other's init becomes a no-op (it sees its own deviceId is "larger" and instead acks the peer's init at the same `toGen`).

**Failure tolerance:** if the rotate-commit is lost, both sides have already stored the new gen — the next outgoing frame uses the new gen and the receiver decrypts via its `keys[toGen]` entry. The commit is a redundant signal, not a hard requirement.

**Why this is in day-1 scope:** rotation is the substitute for v1's per-transfer forward secrecy. Without it the FS argument in §Threat model collapses. We need it in the same release that removes per-transfer ephemerals.

## Code surface impact

**Deleted (Chrome):**

- `extension/crypto/session-registry.js` (659 lines)
- `extension/crypto/beam-relay-handlers.js` handshake portions (~300 lines of 651)
- `pendingAccepts` map and waiter timer machinery
- `transfer-init` / `transfer-accept` / `transfer-reject` / `file-complete` JSON paths in `background-relay.js` (~150 lines)
- `rehydratePendingHandshakes` (no longer needed)

**Replaced (Chrome):**

- New `extension/crypto/beam-v2.js` — single file, ~250 lines, exposing `encryptFrame(K_AB, kind, ...) ` and `decryptFrame(K_AB_resolver, bytes)`.
- `background-relay.js` keeps WebSocket lifecycle but loses all transfer-state code; `sendClipboardEncrypted` / `sendFileEncrypted` shrink to ~30 lines each.

**Deleted (Android):** `BeamSessionRegistry.kt` (463 lines), `SessionCipher.kt` (508 lines), `HashAccumulator.kt` (157 lines). Replaced by `BeamV2.kt` (~250 lines).

**Net code change:** roughly **-3,000 lines** across both implementations, with a clearer test surface (frame round-trip is a pure function).

## Migration plan

1. Implement v2 alongside v1 behind a per-pairing capability flag.
2. New pairings derive K_AB and mark themselves `protocol: "beam-v2"`.
3. Existing pairings stay on v1 until user re-pairs (offer a "rotate keys" button that does this).
4. After 1.0 has been stable for 30 days, remove v1 code path entirely.

A simpler alternative: since the app is pre-launch and storage can be wiped, just delete v1 wholesale and require all users to re-pair on first launch of the v2 build. **Recommended**, given pre-launch state.

## Test plan

Unit (both languages):

- Frame round-trip with random plaintext sizes 1 byte .. 256 KB.
- Tampered ciphertext, header, AAD bits → decrypt fails.
- Wrong K_AB → decrypt fails.
- Wrong generation → decrypt fails.
- Reordered frames → header AAD mismatch fails.

Cross-implementation (vector files in `server/test-vectors/beam-v2/`):

- Kotlin generates a frame with a fixed `K_AB`/`nonce`; JS decrypts.
- JS generates a frame with the same fixed inputs; Kotlin decrypts.
- Adds vectors for both clipboard and 3-chunk file flows.

E2E (against the local relay fixture):

- Clipboard PC → Android, Android → PC.
- File 100 KB, 1 MB, 10 MB in both directions.
- SW killed mid-file → receiver requests resend → sender completes.

## What this spec deliberately does NOT change

- Pairing ceremony (QR + SAS).
- Relay protocol for auth / presence / rendezvous / bind / release / binary forwarding.
- Web Crypto vs libsodium boundaries on Chrome (popup uses Web Crypto for ECDH; SW uses libsodium for AEAD).
- Android Keystore handling of `staticSk`.

The premise of v2 is that the cryptography belongs in the simplest possible layer — one symmetric key per pair, one AEAD frame per send — and that everything else stays exactly as it is.
