# Post-Audit Beta-Hardening Plan (two-track)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Each track runs in its **own git worktree / branch / session** (see "Execution model"). Steps use `- [ ]` for tracking. Keep the existing per-task workflow: implementer agent → spec-review + code-review (both opus, parallel) → commit.

**Goal:** Take the branch from "all tests green but broken end-to-end" to "works Chrome↔Android on the happy path, safe enough for closed beta." Driven by the full audit run on 2026-07-11 (6-agent fan-out; 771 tests passing but integration wiring broken in load-bearing places).

**Driving finding:** The Chrome↔Android liveness path is broken at three independent layers, and several core features are wired to dead code. Green unit tests hid all of it because they exercise modules in isolation, not the production wiring.

---

## Execution model — why two tracks

We run **two concurrent sessions**, each in its own git worktree/branch:

- **BUILD track** stays on **Fable 5** — plumbing, wiring, lifecycle, data, dead-code, tests. Nothing here names an attack or implements crypto, so it should not trip Fable's security auto-fallback.
- **SEC track** accepts regression to **Opus 4.8** — anything that names an attack technique or touches crypto / auth / secret-storage. We expect these to fall back and we isolate them so the fallback never stalls the BUILD track.

**Isolation guarantee = one-owner-per-file.** Every file the phase touches is owned by exactly one track, so the two branches never edit the same file and merges are conflict-free by construction. BUILD depends on nothing in SEC; only SEC's *end-to-end validation* waits for BUILD-1/2 to merge (its unit work is independent). So if SEC regresses to Opus, BUILD keeps flowing on Fable.

### File ownership (the mechanism)

| Track | Owns these files |
|---|---|
| **BUILD** | `server/src/server.js`, `SignalingClient.kt`, `ConnectionAuthority.kt`, new `ConnectionModule.kt`, `TransferEngine.kt`, `TransferForegroundService.kt`, `DeviceHubViewModel.kt`, `TransferCompleteViewModel.kt`, `extension/manifest.json`, `extension/background-relay.js`, dead-code files (extension `offscreen/*` v1, `popup/relay-client.js`; Android `PeerConnectionManager.kt`, `IceRestartPolicy.kt`, `TransferStateMachine.kt`, `FlowController.kt`, `ChunkSizer.kt`), most `test/` files, `backup_rules.xml`/`data_extraction_rules.xml` |
| **SEC** | `server/src/relay.js`, `server/src/gateway.js`, `extension/crypto/beam-v2-transport.js`, `extension/background.js`, `BeamV2Transport.kt`, `PairingViewModel.kt`, `KeyManager.kt`, `di/DatabaseModule.kt`, SEC-owned crypto `test/` files |

**Collision resolutions baked into the table above:**
- `server.js` routing (incl. `beam-v2-*` cases) is **BUILD** — it's pure plumbing (routes opaque bytes to an existing handler), names no attack. The crypto isolation lives in the transport files, which are SEC.
- Rung-3 `ServiceLifecycle` provider goes in a **new `ConnectionModule.kt`** (BUILD) so it doesn't touch SEC-owned `DatabaseModule.kt`.
- `manifest.json` is **BUILD** (`downloads` is delivery-critical); the SEC clipboard fix is **code-only** in `background.js`, no permission change.
- The **OOM streaming** fix spans BUILD `TransferEngine.kt` + SEC transport → **deferred to the convergence phase** (see below), not run concurrently.

---

## Phase 0 — shared base (runs first, on the current branch, Fable)

Both worktrees fork from this commit. Do NOT fork until this is pushed.

- [ ] Review the dirty tree. Commit the rendezvous own-id fix (`SignalingClient.kt` `buildRendezvousIds`/`reRegisterRendezvous` + `ConnectionAuthorityTest.kt`/webrtc test additions). Audit confirmed the fix is correct — it is **layer 1** of the liveness break.
- [ ] `observer.mjs`: benign throwaway diagnostic that never ships (Dockerfile copies only `src/`). `.gitignore` it or move to `server/scripts/`; do not add it to relay source.
- [ ] Also fold in the extension `background.js`/`background-relay.js` dirty changes if they belong with the rendezvous fix; otherwise stage them into the right track's first task. Verify `npm test` (extension + server) and `gradlew testDebugUnitTest` still green.
- [ ] Push. **This commit is the fork point.**

---

## BUILD track (Fable) — files never touched by SEC

### B1 — Server: route the liveness + rotation message types
**Files:** modify `server/src/server.js`. **Why (verified this session):** `SIGNALING_TYPES` in `signaling.js:35-59` already lists `PEER_PING`, `PEER_PONG`, and every `BEAM_V2_*` type, and `handleMessage` will relay them — but the production `switch (msg.type)` at `server.js:405-419` never routes those types to `signaling.handleMessage`, so they hit `default:` and are dropped. This is **layer 2** of the liveness break and also kills Beam v2 key rotation. The passing `signaling.test.js` peer-ping test calls `handleMessage` *directly*, bypassing this switch — which is why it's green.
**Acceptance:** add the missing `case` labels to the switch. New test drives a `peer-ping` from A **through the server's message dispatch** (not `handleMessage` directly) and asserts B receives it; same for a `beam-v2-rotate-init`. Existing 88 server tests still pass.

### B2 — Android: `peer-pong` responder
**Files:** modify `ConnectionAuthority.kt` (and `SignalingClient.kt` if the send path lives there). **Why:** `ConnectionAuthority.kt:406-428` handles inbound `peer-online/offline/pong` but nothing in `src/main` ever constructs a `peer-pong` reply to an inbound `peer-ping` — **layer 3**. Even after B1 routes Chrome's ping to the phone, the phone drops it, Chrome marks it FAILED, and gates every send `PEER_UNREACHABLE`.
**Acceptance:** inbound `peer-ping` → Android emits a `peer-pong` with the same nonce and correct routing keys. Unit test asserts the responder fires. **After B1+B2 merge, the real-device smoke is meaningful** (deferred to convergence).

### B3 — Extension: `downloads` permission + received-file delivery
**Files:** modify `extension/manifest.json`, `extension/background-relay.js`. **Why (verified):** `background-relay.js:708` calls `chrome.downloads.download()` but `"downloads"` is absent from `manifest.json:6` permissions, so `chrome.downloads` is `undefined`; with auto-save on, every received file throws into a catch, the bytes are discarded, and the user still gets a "File Saved" notification (CRITICAL). Also wire the missing `onReceiveError`/`notifyReceiveFailure` so receive failures surface instead of vanishing.
**Acceptance:** add `"downloads"`. A test/stub asserting `chrome.downloads` exists when delivery runs (would have caught this). Received file actually lands; failures notify.

### B4 — Android: foreground-service progress population
**Files:** modify `TransferEngine.kt`, `TransferForegroundService.kt`. **Why:** `TransferEngine.progress` (`TransferEngine.kt:87`) is never populated — only removed in `cancelTransfer` — so `observeProgress` sees an empty map on first collect and `stopSelf()`. Result: no FG service, no wakelocks, no progress notification, OS can kill mid-transfer. Also fix the `cancelTransfer` key mismatch (jobs stored under `fileName`, looked up by `transferId`, `TransferEngine.kt:208` vs `247`) and stop swallowing send failures silently (log-only catch → FAILED history row + user surface).
**Acceptance:** service stays alive during a transfer; progress flow is non-empty; cancel actually cancels; a send failure produces a FAILED row.

### B5 — Android: Rung-3 `ServiceLifecycle` DI wiring
**Files:** create `ConnectionModule.kt`; modify `ConnectionAuthority.kt` if needed. **Why:** the production `@Inject` ctor (`ConnectionAuthority.kt:208`) delegates without `serviceLifecycle`, so it watches a fresh, permanently-`Stopped` instance; there's no Hilt `@Provides`. Rung 3's success predicate needs `serviceLifecycle.state == Running`, which can never be true, so Rung 3 and the manual Reconnect button always surrender. Committed "Step G" (5a46013) is inert because of this.
**Acceptance:** a single `@Singleton ServiceLifecycle` is provided and observed by *both* the service and CA (assert same instance). An integration-style test that Rung 3 observes the state the service dispatches.

### B6 — Android 8–9 `MediaStore` guard
**Files:** modify `TransferEngine.kt`, `DeviceHubViewModel.kt`, `TransferCompleteViewModel.kt`. **Why:** `MediaStore.Downloads` (API 29) used unguarded despite `minSdk 26` → `NoClassDefFoundError` (not caught by the surrounding `catch (Exception)`) on every file receive/save on Android 8.0–9. Also `TransferCompleteViewModel.kt:104,147` does `File(Uri.parse(contentUri).path)` on a `content://` URI, which never resolves → "Save to Downloads" silently no-ops.
**Acceptance:** version-gated MediaStore paths with a pre-29 fallback; save actually writes on all supported API levels.

### B7 — Android: history `transferId` primary-key fix
**Files:** modify `TransferEngine.kt`, `DeviceHubViewModel.kt`. **Why:** history rows inserted with `transferId = ""` on a PK column under `OnConflictStrategy.IGNORE` → after the first such row, every later RECEIVED/FAILED row is silently dropped; the list lies.
**Acceptance:** rows carry real unique IDs; a DAO test inserts two receives and asserts both persist.

### B8 — Extension: reconnect deadlock + auth-fail loop
**Files:** modify `extension/background-relay.js`. **Why:** `_doConnect`'s promise never settles on a pre-auth clean socket close, so `_inflightConnect` hangs and the single-flight guard blocks every future reconnect — extension stays offline until SW death. Separately, an `auth-fail` triggers an unthrottled 2s retry loop with the same bad credentials.
**Acceptance:** a connect/auth timeout rejects and clears the inflight guard; auth-fail backs off instead of hammering. Test against the existing relay fixture (already used by pairing-race/e2e tests).

### B9 — Delete v1 dead code
**Files:** delete extension `offscreen/transfer-manager.js`, `ws-client.js`, `webrtc-manager.js`, `checkpoint.js`, `popup/relay-client.js`; remove the fake-success popup features (Screenshot / Send-tab-URL / Resend routing to the dead offscreen pipeline). Delete Android `PeerConnectionManager.kt`, `IceRestartPolicy.kt`, `TransferStateMachine.kt`, `FlowController.kt`, `ChunkSizer.kt`, unwired `OfflineQueueDao` (verify first), `validateFileMetadata`, `PairedDeviceDao.updateLastSeen`. **Why:** all verified zero-production-caller. The dormant extension pipeline is worse than dead — it fakes success toasts and holds four latent corruption bugs. **Do not touch `background.js`** (SEC-owned); leave any v1 router case there for SEC or the convergence pass.
**Acceptance:** grep confirms no remaining callers; both test suites still green after deletion; no fake success toasts remain.

### B10 — Production-wiring integration tests
**Files:** `server/test/`, `extension/test/`. **Why:** the entire audit's headline (green tests hiding broken wiring) exists because no test drives the production seam. Add: (1) a server test that routes `peer-ping` **through the dispatch switch** (guards B1 forever); (2) a manifest-vs-`chrome.downloads` assertion (guards B3); (3) optionally a Rung-3/`ServiceLifecycle` same-instance assertion (overlaps B5).
**Acceptance:** each new test fails against the pre-fix code and passes after.

---

## SEC track (Opus fallback expected) — disjoint files

### S1 — Relay membership authorization
**Files:** modify `server/src/relay.js`. **Why:** `RELAY_BIND` (`relay.js:247-304`) does no rendezvous-membership check (unlike `signaling.js:134-151`), so any authenticated device can stream binary frames at any online deviceId (forced-decrypt/DoS); and the second-binder branch (`relay.js:289-297`) unconditionally overwrites the receiver, allowing session hijack by anyone who knows an in-flight `transferId`.
**Acceptance:** bind rejected unless both devices share a rendezvous; no unconditional receiver rebind. Add the `relay.js` tests that don't exist today (session-hijack path, membership rejection).

### S2 — Cross-transfer replay protection
**Files:** modify `extension/crypto/beam-v2-transport.js`, `BeamV2Transport.kt`. **Why:** v2 dropped v1's duplicate-`transferId` rejection and has no timestamp/nonce in the AAD, so the untrusted relay can re-inject a completed transfer — receiver re-delivers an old file or a stale clipboard value (e.g. a crypto address). (HIGH — protocol regression.)
**Acceptance:** receiver keeps a persistent seen-`transferId` set (or AAD freshness) and rejects replays. Cross-impl parity preserved (update `vectors.json` if the AAD changes).

### S3 — `expiresAt` enforcement + rotation tiebreaker
**Files:** modify `extension/crypto/beam-v2-transport.js`, `BeamV2Transport.kt`. **Why:** `resolveKAB` returns the generation key regardless of `expiresAt` and nothing prunes expired generations, so rotated-out keys decrypt forever (the documented 24h grace is fictional). Also Chrome's concurrent-rotation tiebreaker is dead (`getOurDeviceId` returns `null`), so simultaneous rotation commits diverging `K_AB` and desyncs until re-pair; Android implements the rule, Chrome doesn't.
**Acceptance:** expired generations rejected on decrypt and pruned; Chrome tiebreaker wired to a real device id; unit tests for both. (E2E rotation validation waits on B1 merge.)

### S4 — PIN pairing: disable for beta
**Files:** modify `PairingViewModel.kt` (and the popup counterpart if it exposes PIN). **Why:** the PIN path sends the raw PIN over the untrusted relay (`PairingViewModel.kt:283`), giving the relay a pair-MITM window up to SAS; SPAKE2 is a TODO stub. **Recommended:** disable the PIN entry path for beta (SAS-QR pairing already works and is MITM-resistant); full SPAKE2 is a large build we don't need to gate the beta on.
**Acceptance:** PIN pairing UI is unreachable/removed for beta; QR-SAS pairing unaffected. (If you want SPAKE2 instead, that's its own spec — say so and we re-scope.)

### S5 — K_AB at-rest encryption
**Files:** modify `di/DatabaseModule.kt` (+ Gradle dep). **Why:** long-lived symmetric transfer keys (`k_ab_ring_json`) are stored plaintext in Room while the *less* sensitive identity keys get Keystore/EncryptedSharedPreferences — inverted protection. Compromising `K_AB` breaks confidentiality of every transfer under the pairing.
**Acceptance:** Room opened via SQLCipher `SupportFactory` (key from Keystore); existing DAO tests still pass against the encrypted DB.

### S6 — Clipboard-exfiltration fix
**Files:** modify `extension/background.js` (code-only, no manifest change). **Why:** the `send-clipboard` shortcut (`background.js:592-623`) injects a textarea into the active page's DOM and runs `execCommand('paste')`; a hostile page with a `paste` listener captures the full clipboard (passwords, tokens).
**Acceptance:** clipboard read happens in an in-extension context (offscreen document / `navigator.clipboard` in the extension), never in page DOM. No cross-world leak.

---

## Convergence phase (after both tracks merge)

Runs on whichever session is free; these can't parallelize cleanly.

- [ ] **OOM streaming** — stream file send/receive instead of buffering whole files in RAM. Spans BUILD `TransferEngine.kt` (`readBytes()`) + SEC `BeamV2Transport.kt`/`beam-v2-transport.js` frames maps. Reliability, not a beta blocker, but a paired peer can OOM-kill remotely.
- [ ] **Signature domain-separation tag** — add a context prefix to the relay-auth signature. Lockstep client (`SignalingClient.kt` + `background-relay.js`) + server (`gateway.js`) wire change; LOW severity, safe today. Both sides must ship together.
- [ ] **Real-device E2E smoke** — the deferred smoke from project memory (kill relay, observe Rungs 1+2 fail → Rung 3 service restart → recovery without user tap; plus a real Chrome↔Android file + clipboard round-trip). Only meaningful once B1+B2 land.

---

## Merge protocol

1. Phase 0 commit is the shared fork point (push it first).
2. BUILD and SEC each run in their own worktree/branch off that commit.
3. **BUILD merges to `master` first** (critical path; unblocks SEC's E2E validation).
4. **SEC rebases onto the updated `master`, then merges.** Disjoint ownership ⇒ no conflicts.
5. Convergence tasks run last, on a fresh branch off the merged `master`.

**Sanity check before merging either track:** all three suites green (Android `gradlew testDebugUnitTest`, extension + server `npm test`) *and* the new B10 wiring tests present — green-in-isolation is exactly what this whole phase exists to stop trusting.
