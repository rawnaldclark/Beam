# Connection Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-source-of-truth `ConnectionAuthority` per side (Chrome SW + Android FG service) that owns relay-WS lifecycle, peer-level liveness, recovery escalation, and a send-time pre-flight gate. Eliminates the user's force-stop workaround and silent transfer failures.

**Spec:** `docs/superpowers/specs/2026-05-02-connection-authority-design.md`

**Architecture:** Plaintext JSON `peer-ping`/`peer-pong` over the existing relay rendezvous channel. Per side: a `selfState` flow (OFFLINE/CONNECTING/ONLINE/RECONNECTING) and a per-peer `peerHealth` flow (UNKNOWN/HEALTHY/STALE/FAILED/OFFLINE). A 4-rung recovery ladder (re-register → WS reconnect → full session reset → user-visible failure with backoff) runs as one cancelable coroutine. Every `sendFile`/`sendClipboard` first calls `ensureSendable(deviceId)`; failures route through a "Failed — Retry?" UX with no fake mock-progress.

**Tech Stack:** Chrome MV3 service worker, vanilla JS modules, Node `node:test`. Android Kotlin + coroutines, Hilt singletons, Room. Existing relay (Node.js) gets a 3-line allow-list addition.

---

## Phase 1 — Foundation: wire protocol + skeletons

## Task 1: Server allow-list for `peer-ping` / `peer-pong`

**Files:**
- Modify: `server/src/protocol.js` — add MSG constants
- Modify: `server/src/relay.js` or `server/src/signaling.js` — wherever the rendezvous-routed message allow-list lives (verify by reading)
- Modify: `server/test/<existing relay test>` — add coverage that the relay forwards these types

**Context:** The relay is a passthrough — `peer-ping`/`peer-pong` carry no server state. We just have to teach it to forward them by `targetDeviceId` like it already does for `relay-bind` and `beam-v2-*` messages.

- [ ] **Step 1:** Read `server/src/protocol.js` and `server/src/signaling.js` end-to-end to find where the forwarded-message allow-list is defined and how new types are added (look for `relay-bind`, `beam-v2-resend` for the pattern). **Pay particular attention to which field names route the message** — in this codebase `rendezvousId` and `targetDeviceId` semantics have varied across message types (sender's-id vs recipient's-id). Match exactly what `beam-v2-resend` uses to keep the new ping/pong consistent.

- [ ] **Step 2:** Write a failing test (in whichever file under `server/test/` covers rendezvous-routed forwarding). Two clients, A and B, both registered to rendezvous IDs. A sends `{type:"peer-ping", nonce:"abc", targetDeviceId:B, rendezvousId:B}`. Assert B receives it byte-identical. Then B sends `{type:"peer-pong", nonce:"abc"}` with appropriate routing keys. Assert A receives it.

- [ ] **Step 3:** Run the test, expect FAIL (`peer-ping` rejected by allow-list).

- [ ] **Step 4:** Add to `server/src/protocol.js`:
   ```js
   // Inside MSG = Object.freeze({...
   PEER_PING: 'peer-ping',
   PEER_PONG: 'peer-pong',
   ```
   And add these two strings to the existing rendezvous-routed allow-list in `signaling.js` / `relay.js` (whichever the existing patterns use).

- [ ] **Step 5:** Run the test, expect PASS.

- [ ] **Step 6:** Commit:
   ```
   feat(server): allow-list peer-ping/peer-pong for rendezvous routing
   ```

---

## Task 2: Chrome — `peer-ping` protocol module (pure logic, no WS)

**Files:**
- Create: `extension/connection/peer-ping.js`
- Create: `extension/test/peer-ping.test.js`

**Context:** Pure module that owns:
- Generating ping JSON with a fresh random nonce
- An in-memory map of pending pings (`nonce → { sentAt, deadline, peerId }`)
- A `recordPong(nonce)` that resolves the matching ping if it's still in flight
- A `sweepExpired(now)` that returns the IDs of pings that timed out
- No WS dependency — caller passes a `sendJson` function in.

- [ ] **Step 1:** Write `extension/test/peer-ping.test.js` with these cases:
   - `sendPing(peerId)` returns a `{nonce, promise}` where promise is pending; calls `sendJson` once with the right shape.
   - `recordPong(nonce)` resolves the matching ping's promise to `{ok:true, rttMs:N}`.
   - `recordPong("unknown")` is a no-op, does not throw.
   - `sweepExpired(now)` after the deadline rejects the promise with `{ok:false, reason:"timeout"}` and removes the entry.
   - Each ping's nonce is unique (16 random bytes, b64url, no padding).

- [ ] **Step 2:** Run: `cd extension && npm test -- peer-ping.test.js`. Expect FAIL (module not yet created).

- [ ] **Step 3:** Create `extension/connection/peer-ping.js` exporting `class PeerPingTracker { constructor({sendJson, timeoutMs}) ... sendPing(peerId) ... recordPong(nonce) ... sweepExpired(now) }`. Use `crypto.getRandomValues(new Uint8Array(16))` for the nonce; b64url-encode without padding.

- [ ] **Step 4:** Run tests, expect PASS.

- [ ] **Step 5:** Commit:
   ```
   feat(connection): chrome peer-ping protocol tracker module
   ```

---

## Task 3: Chrome — `peerHealth` state machine (pure)

**Files:**
- Create: `extension/connection/peer-health.js`
- Create: `extension/test/peer-health.test.js`

**Context:** Pure state-machine reducer. Given current state + event, returns new state. No WS, no timers, no pings — those live in the authority. This is the math.

States: `UNKNOWN | HEALTHY | STALE | FAILED | OFFLINE`.

Events:
- `pong-received` → `HEALTHY` from any state except `OFFLINE`
- `frame-received` (real v2 frame decoded) → `HEALTHY` from any state except `OFFLINE`
- `send-completed` → `HEALTHY` from any state except `OFFLINE`
- `ping-missed` → `UNKNOWN→STALE`, `HEALTHY→STALE`, `STALE→FAILED` (one miss tolerated)
- `pre-flight-failed` → `FAILED` from any state
- `relay-peer-online` → `OFFLINE→UNKNOWN` (NOT `HEALTHY`; weaker evidence)
- `relay-peer-offline` → `OFFLINE` from any state
- `recovery-succeeded` → `FAILED→UNKNOWN` (next ping will promote)
- `recovery-given-up` → `FAILED` (stays; surfaces to user via UI)

- [ ] **Step 1:** Write `extension/test/peer-health.test.js` covering every transition above plus a few combined sequences (`HEALTHY → ping-missed → STALE → ping-missed → FAILED`; `OFFLINE → relay-peer-online → UNKNOWN → pong-received → HEALTHY`).

- [ ] **Step 2:** Run, expect FAIL.

- [ ] **Step 3:** Create `extension/connection/peer-health.js` exporting:
   ```js
   export const PeerHealth = { UNKNOWN:'UNKNOWN', HEALTHY:'HEALTHY', STALE:'STALE', FAILED:'FAILED', OFFLINE:'OFFLINE' };
   export function reducePeerHealth(state, event) { ... }
   ```

- [ ] **Step 4:** Run, expect PASS.

- [ ] **Step 5:** Commit:
   ```
   feat(connection): chrome peerHealth state-machine reducer + tests
   ```

---

## Task 4: Chrome — `selfState` state machine (pure)

**Files:**
- Create: `extension/connection/self-state.js`
- Create: `extension/test/self-state.test.js`

**Context:** Same shape as peer-health: pure reducer. States `OFFLINE | CONNECTING | ONLINE | RECONNECTING`. Events: `start-connect`, `auth-complete`, `ws-closed`, `recovery-began`, `recovery-succeeded`, `recovery-given-up`, `stop`.

Per spec §"Entry triggers for CONNECTING": entry from `OFFLINE → CONNECTING` happens on first pair, on cold boot with paired devices, on `requestReconnect`, and at the start of Rungs 2/3.

- [ ] **Step 1:** Write `extension/test/self-state.test.js`. Cover each transition explicitly. Cover the cold-boot sequence: `OFFLINE → start-connect → CONNECTING → auth-complete → ONLINE → ws-closed → RECONNECTING → recovery-succeeded → ONLINE`.

- [ ] **Step 2:** Run, expect FAIL.

- [ ] **Step 3:** Create the module, mirror Task 3's shape.

- [ ] **Step 4:** Run, expect PASS.

- [ ] **Step 5:** Commit:
   ```
   feat(connection): chrome selfState state-machine reducer + tests
   ```

---

## Phase 2 — Chrome authority skeleton + recovery

## Task 5: Chrome — `ConnectionAuthority` skeleton (no recovery, no pre-flight)

**Files:**
- Create: `extension/connection/connection-authority.js`
- Create: `extension/test/connection-authority.test.js`

**Context:** Wires `PeerPingTracker` + the two reducers into a coherent object. Exposes `selfState` and `peerHealth` as observable subjects (a small `Observable` helper class) and a `dispatch(event)` private. No recovery ladder yet, no pre-flight.

The authority subscribes to a `SignalingHooks` interface passed in (it does NOT import background-relay directly — that's the wiring step). The hooks let us swap a fake relay in tests.

```js
// extension/connection/connection-authority.js
export class ConnectionAuthority {
  constructor({ signalingHooks, options = {} }) { ... }
  get selfState()  { return this._selfState; }       // Observable<SelfState>
  get peerHealth() { return this._peerHealth; }      // Observable<Map<DeviceId, PeerHealth>>

  // Called by hooks layer when WS lifecycle events occur
  notifyWsOpened()      { /* dispatch start-connect transition was earlier */ }
  notifyAuthComplete()  { /* dispatch auth-complete */ }
  notifyWsClosed()      { /* dispatch ws-closed */ }
  notifyPeerOnline(id)  { /* dispatch relay-peer-online for that peer */ }
  notifyPeerOffline(id) { /* dispatch relay-peer-offline */ }

  // Called when an incoming v2 frame from peer X decodes successfully
  notifyFrameReceived(peerId) { /* dispatch frame-received */ }

  // Called when an outgoing send to peer X completes successfully
  notifySendCompleted(peerId) { /* dispatch send-completed */ }

  // Called by hooks when peer-pong arrives
  notifyPongReceived(nonce) { ... }

  // Public — caller awaits before encoding frames. Stub for now.
  async ensureSendable(peerId) { return { ok: true }; }   // Real impl in later task
  async requestReconnect()      { /* stub */ }            // Real impl in later task

  shutdown() { /* clear timers */ }
}
```

- [ ] **Step 1:** Write a small `extension/connection/observable.js` (10-line `class Observable { value; subscribe(fn); next(v) }`). Add a unit test for it (`extension/test/observable.test.js`) — subscribe/unsubscribe/replay-current-on-subscribe.

- [ ] **Step 2:** Run obs test, expect FAIL → implement → PASS → commit (`feat(connection): tiny Observable helper`).

- [ ] **Step 3:** Write `extension/test/connection-authority.test.js` covering:
   - On `notifyWsOpened` then `notifyAuthComplete`, `selfState` flips `OFFLINE → CONNECTING → ONLINE`.
   - On `notifyWsClosed` from ONLINE, flips to `RECONNECTING`.
   - On `notifyPeerOnline("X")`, peer X enters `peerHealth` map as `UNKNOWN`.
   - On `notifyFrameReceived("X")`, peer X promotes to `HEALTHY`.
   - On `notifyPeerOffline("X")`, peer X is `OFFLINE`.
   - `ensureSendable(...)` returns `{ok:true}` for now (stub).

- [ ] **Step 4:** Run, expect FAIL.

- [ ] **Step 5:** Implement `connection-authority.js` skeleton — wire the two reducers, the ping tracker (idle for now), and the notify methods. No background ping timer, no recovery, no pre-flight.

- [ ] **Step 6:** Run, expect PASS.

- [ ] **Step 7:** Commit:
   ```
   feat(connection): chrome ConnectionAuthority skeleton (no recovery, no pre-flight)
   ```

---

## Task 6: Chrome — wire authority into `background-relay.js` (read-only)

**Files:**
- Modify: `extension/background-relay.js`
- Create: `extension/connection/connection-authority-wiring.js`

**Context:** The authority is now plumbed in but does nothing visible: its hooks observe WS lifecycle, peer-online/offline events, and v2 frame decode events. UI does not read from it yet — that's the next step.

- [ ] **Step 1:** Create `extension/connection/connection-authority-wiring.js` that exports `getConnectionAuthority()` — a singleton accessor like `getBeamV2Transport`. It constructs the authority once with `signalingHooks` that wrap `sendPairingMessage` (for outbound JSON) and provide a stub `onPongReceived` that the message dispatcher will call.

- [ ] **Step 2:** In `extension/background-relay.js`, find where `_doConnect`'s `ws.onopen` resolves auth (around line 294 — `[Beam SW] Pairing relay authenticated as ...`). After that line, call `getConnectionAuthority().notifyAuthComplete()`. Before opening the WS, call `notifyWsOpening()` (we may need to add that — a synonym for `start-connect`).

- [ ] **Step 3:** In `ws.onclose` (line 382), call `getConnectionAuthority().notifyWsClosed()`.

- [ ] **Step 4:** In the `peer-online` / `peer-offline` handlers (line 334), call `notifyPeerOnline(deviceId)` / `notifyPeerOffline(deviceId)`.

- [ ] **Step 5:** In `extension/crypto/beam-v2-wiring.js`'s `onClipboardReceived` and `onFileReceived` hook registrations, also call `notifyFrameReceived(fromDeviceId)` so successful inbound traffic counts as proof of life.

- [ ] **Step 6:** In `sendClipboardEncrypted` and `sendFileEncrypted` (background-relay.js), after the v2 transport call resolves, call `notifySendCompleted(targetDeviceId)`. (Pre-flight comes in Task 9.)

- [ ] **Step 7:** Add a JSON dispatch case for `peer-ping` in `background-relay.js`'s message handler: when a `peer-ping` arrives, immediately reply `{type:"peer-pong", nonce, targetDeviceId:fromDeviceId, rendezvousId:fromDeviceId}` via `sendPairingMessage`. For `peer-pong`: call `getConnectionAuthority().notifyPongReceived(msg.nonce)`.

- [ ] **Step 8:** Run the existing extension test suite — should still pass (no new tests added; wiring is observational only). `cd extension && npm test`.

- [ ] **Step 9:** Commit:
   ```
   feat(connection): wire ConnectionAuthority into chrome background-relay
   ```

---

## Task 7: Chrome — background ping cadence + peer-health pulses

**Files:**
- Modify: `extension/connection/connection-authority.js`
- Modify: `extension/test/connection-authority.test.js`

**Context:** Now the authority actively sends `peer-ping` every 120s for each peer in `peerHealth`. On miss, the state machine handles `STALE → FAILED` correctly. No recovery ladder yet; `FAILED` just stays `FAILED`.

- [ ] **Step 1:** Add a test using a manual clock helper (`fakeNow` injectable; advance time manually). Cover:
   - Adding a peer (e.g. via `notifyPeerOnline`) schedules a ping after 120s.
   - At 120s, a ping is sent (assert `signalingHooks.sendJson` called with `peer-ping`).
   - If pong arrives within 10s, peer is `HEALTHY`, next ping scheduled for 120s later.
   - If no pong within 10s, peer goes `STALE`, next ping cycle still happens at 240s mark.
   - Two consecutive misses → `FAILED`.

- [ ] **Step 2:** Run, expect FAIL.

- [ ] **Step 3:** Add the cadence logic in `connection-authority.js`. Use `setInterval`-style scheduling via injectable timer functions (so tests can use a fake clock). Constants `BG_PING_INTERVAL_MS=120_000` and `PING_TIMEOUT_MS=10_000` exported from `extension/connection/constants.js` (create that file).

- [ ] **Step 4:** Run, expect PASS.

- [ ] **Step 5:** Commit:
   ```
   feat(connection): chrome background peer-ping cadence with miss → FAILED escalation
   ```

---

## Task 8: Chrome — recovery ladder Rungs 1 + 2

**Files:**
- Create: `extension/connection/recovery-ladder.js`
- Create: `extension/test/recovery-ladder.test.js`
- Modify: `extension/connection/connection-authority.js`

**Context:** When any peer goes `FAILED` (or `selfState` goes `RECONNECTING`), kick the ladder. Rung 1: re-register-rendezvous via the existing `sendPairingMessage` path. Rung 2: tear down WS and reconnect. Rung 3 comes in a later task.

The ladder is ONE coroutine-equivalent (chained promises). Cancelable. Sequential. Logged.

- [ ] **Step 1:** Write tests covering (with mocks for the rung actions):
   - On entry, ladder runs Rung 1, Rung 2 sequentially (with the configured 5s and 15s budgets).
   - If Rung 1's success indicator (`peerHealth becomes HEALTHY` for the affected peer) fires within 5s, ladder stops, returns success.
   - If Rung 1 times out, Rung 2 runs.
   - If Rung 2 succeeds, ladder returns success.
   - If both fail, ladder enters Rung 3 (mock — just throws "rung-3 stub" for now).
   - Cancellation mid-ladder cleans up.

- [ ] **Step 2:** Run, expect FAIL.

- [ ] **Step 3:** Implement `recovery-ladder.js`:
   ```js
   export class RecoveryLadder {
     constructor({ rungs, onTransition }) { ... }
     async run() { /* sequence each rung, respect budgets, support cancel */ }
     cancel() { ... }
   }
   ```
   The `rungs` arg is `[ {name:'rung1', budgetMs:5000, action: async() => boolean}, ...]`. Action returns `true` on recovery, `false` on timeout.

- [ ] **Step 4:** Wire into `connection-authority.js`:
   - On `peerHealth[X] = FAILED` transition, start the ladder if no ladder is already running.
   - **Rung 1 success criterion (general rule for all rungs):** the rung succeeds if `peerHealth[X]` reaches `HEALTHY` *by any path* during the budget — that includes a `relay-peer-online` event, an inbound v2 frame from X, OR a successful pong. Don't hard-code the await on `relay-peer-online` alone.
   - Rung 1 action: send `register-rendezvous` and wait up to 5s for `peerHealth[X] === HEALTHY`.
   - Rung 2 action: call into hooks `forceWsReconnect()` (a new method on the wiring layer that closes pairingWs and triggers `_doConnect`); wait up to 15s for `selfState === ONLINE` AND any paired peer reaching `HEALTHY`.
   - Rung 3 action: stub for now (throws "TODO Rung 3").

- [ ] **Step 5:** Run authority tests + ladder tests, expect PASS.

- [ ] **Step 6:** Commit:
   ```
   feat(connection): chrome recovery ladder rungs 1+2 (re-register, WS reconnect)
   ```

---

## Task 9: Chrome — `ensureSendable` pre-flight + send-path wiring

**Files:**
- Modify: `extension/connection/connection-authority.js`
- Modify: `extension/test/connection-authority.test.js`
- Modify: `extension/background-relay.js` — wire into `sendClipboardEncrypted` / `sendFileEncrypted`

**Context:** Replace the pre-flight stub with the full algorithm from spec §"Send-time pre-flight". Add the 30s recent-traffic skip via a `lastTrafficAt` map. Wire into both send paths so they bail early when peer is unreachable.

- [ ] **Step 1:** Tests:
   - `ensureSendable` returns `{ok:true}` immediately if peerHealth = HEALTHY and lastTrafficAt < 30s ago.
   - `ensureSendable` sends a peer-ping (5s timeout) if peerHealth != HEALTHY OR no recent traffic; returns ok on pong.
   - On pre-flight timeout, kicks recovery ladder; awaits ladder result (mock recovery success → returns ok after re-ping); on ladder failure → returns `{ok:false, reason:"PEER_UNREACHABLE"}`.
   - Returns `{ok:false, reason:"SELF_OFFLINE"}` immediately if `selfState != ONLINE`.

- [ ] **Step 2:** Run, expect FAIL.

- [ ] **Step 3:** Implement `ensureSendable` per spec. Track `lastTrafficAt: Map<DeviceId, number>` updated on `notifyFrameReceived` and `notifySendCompleted`.

- [ ] **Step 4:** Wire into `background-relay.js`:
   ```js
   // Top of sendFileEncrypted, sendClipboardEncrypted:
   const gate = await getConnectionAuthority().ensureSendable(targetDeviceId);
   if (!gate.ok) {
     const err = new Error(`pre-flight ${gate.reason}`);
     err.code = gate.reason;
     throw err;
   }
   ```

- [ ] **Step 5:** Update SW message handlers in `background.js` (`SEND_FILE`, `SEND_CLIPBOARD` cases) to translate `PEER_UNREACHABLE` / `SELF_OFFLINE` codes into typed responses popup can render.

- [ ] **Step 6:** Run extension tests, expect PASS.

- [ ] **Step 7:** Commit:
   ```
   feat(connection): chrome ensureSendable pre-flight + send-path wiring
   ```

---

## Task 10: Chrome — popup UI: replace mock progress, render peer health, Reconnect button

**Files:**
- Modify: `extension/popup/popup.js`
- Modify: `extension/popup/popup.html` (likely small additions for banner)
- Modify: `extension/popup/popup.css` (yellow dot pulse, banner styling)
- Modify: `extension/background.js` — add `GET_CONNECTION_STATE`, `SUBSCRIBE_CONNECTION_STATE` message handlers

**Context:** Popup currently reads `chrome.storage.session`'s `devicePresence` to show online dots. After this task, it reads from the authority through SW message bridge. Mock progress in `sendFile` (popup.js:1482) is deleted.

- [ ] **Step 1:** In `extension/background.js` add two message handlers:
   - `GET_CONNECTION_STATE`: returns `{ selfState, peerHealth: {...} }` snapshot.
   - The authority broadcasts state changes via `chrome.runtime.sendMessage({type:'CONNECTION_STATE_CHANGED', payload:{selfState, peerHealth}})`. Popup listens.

- [ ] **Step 2:** In `popup.js`, add a listener for `CONNECTION_STATE_CHANGED` and call a new `applyConnectionState(payload)` that updates `currentDevices[*].isOnline` (HEALTHY/STALE → online, FAILED/OFFLINE → offline) plus a `peerHealth` map for richer UI.

- [ ] **Step 3:** Update the device-row renderer to show:
   - `HEALTHY` → green dot
   - `STALE` → green dot with subtle CSS pulse class
   - `FAILED` → yellow dot + "Reconnecting…" subtle text below the row
   - `OFFLINE` → grey dot

- [ ] **Step 4:** Add a top banner that appears when `selfState != ONLINE`:
   - `OFFLINE` / `RECONNECTING` → "Not connected — Reconnect" with a button calling `chrome.runtime.sendMessage({type:'REQUEST_RECONNECT'})`.

- [ ] **Step 5:** Add the SW handler for `REQUEST_RECONNECT`: calls `getConnectionAuthority().requestReconnect()` (still mostly stub — Rung 3 lands in Task 11). For now, makes Rung 2 fire by closing+reopening WS.

- [ ] **Step 6:** **Delete** the mock-progress code: `startMockTransferProgress` calls in `sendFile` (line ~1482) and the `startMockTransferProgress` function definition. Real progress will come from the v2 transport's `onProgress` (already wired).

- [ ] **Step 7:** Manual smoke check (load unpacked, verify dots reflect health correctly; simulate disconnect by killing wifi briefly, verify banner appears, tap Reconnect, verify recovery).

- [ ] **Step 8:** Commit:
   ```
   feat(popup): bind UI to ConnectionAuthority, remove mock progress, add reconnect button
   ```

---

## Task 11: Chrome — Recovery ladder Rung 3 (full session reset)

**Files:**
- Modify: `extension/connection/recovery-ladder.js` (Rung 3 action)
- Modify: `extension/connection/connection-authority-wiring.js` (expose full-reset hook)
- Modify: `extension/background-relay.js` (implement `forceFullReset` hook)
- Modify: `extension/crypto/beam-v2-wiring.js` (reset `_transport` singleton)
- Modify: `extension/test/recovery-ladder.test.js`

**Context:** Replace Rung 3 stub with the real thing per spec §"Rung 3 — Full session reset (Chrome)".

- [ ] **Step 1:** Test: with a mocked wiring, verify Rung 3 calls `stopPairingListener`, nulls out `pairingWs` / `_inflightConnect` / `_inflightDeviceId`, resets v2 transport singleton, calls `autoStartRelayIfPaired`, and waits up to 30s for `selfState=ONLINE`.

- [ ] **Step 2:** Run, expect FAIL.

- [ ] **Step 3:** In `background-relay.js`, expose `forceFullReset(): Promise<void>` that performs the steps. Add a `_resetTransportSingleton()` exported from `beam-v2-wiring.js`.

- [ ] **Step 4:** Wire Rung 3 in `connection-authority.js`: action calls `signalingHooks.forceFullReset()`, then awaits `selfState === ONLINE` or 30s timeout.

- [ ] **Step 5:** Add the thrash guard: track Rung-3 attempts in last 5 min; if ≥2, skip Rungs 1+2 + Rung 3 and go directly to Rung 4.

- [ ] **Step 6:** Add Rung 4 logic: emit a `selfState = RECONNECTING` with `surrenderedToUser=true` flag in the state object that the popup reads to show "Connection failed — tap to reconnect" with no auto-retry text. Begin exponential-backoff timer (30s → 2m → 10m → 30m cap) for next auto-attempt.

- [ ] **Step 7:** Update `requestReconnect()` to cancel any running ladder and dispatch a fresh one starting at Rung 3. Always bypasses backoff.

- [ ] **Step 8:** Run all tests, expect PASS. Manual smoke: deliberately break the relay URL temporarily (point at a wrong host) → observe Rung 1, 2, 3 fire in console logs with timing, then surrender to Rung 4 banner.

- [ ] **Step 9:** Commit:
   ```
   feat(connection): chrome recovery ladder Rung 3 (full session reset) + Rung 4 backoff
   ```

---

## Task 12: Chrome — Failed-transfer UX + retry + persisted history

**Files:**
- Modify: `extension/popup/popup.js`
- Modify: `extension/popup/popup.html` (Failed card markup variant)
- Modify: `extension/popup/popup.css` (Failed state styling, Retry button)
- Modify: `extension/background.js` — extend transfer history schema with `status:'failed'` plus a re-pick prompt for persisted retries

**Context:** Surface `PEER_UNREACHABLE` and `SELF_OFFLINE` failures from the SW as Failed transfer cards with a Retry button. Live retry re-runs `sendFile(file)`. Persisted retry from history prompts the user to re-pick.

- [ ] **Step 1:** In `popup.js`, the `chrome.runtime.sendMessage` `.then(resp)` for `SEND_FILE` (line ~1494): if `resp.error === 'PEER_UNREACHABLE'`, render a Failed card with `Retry` that re-invokes `sendFile(file)` (the original `File` is still in the closure). For `SELF_OFFLINE`, do not render a card; the top banner already informs the user.

- [ ] **Step 2:** Extend the persisted transfer history (chrome.storage.local entry) to include status: `'completed'|'failed'`. Failed entries store `{deviceId, fileName, fileSize, mimeType, failedAt, reason}` — but no blob.

- [ ] **Step 3:** In the history list UI, render Failed entries with a Retry button. Tap → show a file-picker dialog (`<input type='file'>` triggered programmatically); on file chosen, validate `fileName` matches and `fileSize` matches, then call `sendFile(picked)`. If size mismatches, show a confirmation toast.

- [ ] **Step 4:** Verify in browser by simulating a `PEER_UNREACHABLE` (disconnect wifi briefly while a peer is registered, attempt a send). Failed card appears with Retry; tapping retries.

- [ ] **Step 5:** Commit:
   ```
   feat(popup): failed-transfer card with retry + persisted history fallback
   ```

---

## Phase 3 — Android port (mirrors Chrome)

## Task 13: Android — sealed-class state types + peer-ping protocol

**Files:**
- Create: `android/app/src/main/java/com/zaptransfer/android/connection/PeerHealth.kt`
- Create: `android/app/src/main/java/com/zaptransfer/android/connection/SelfState.kt`
- Create: `android/app/src/main/java/com/zaptransfer/android/connection/SendGate.kt`
- Create: `android/app/src/main/java/com/zaptransfer/android/connection/PeerPingTracker.kt`
- Create: `android/app/src/test/java/com/zaptransfer/android/connection/PeerPingTrackerTest.kt`

**Context:** Mirror Chrome's modules with idiomatic Kotlin: sealed classes for states, suspend / Flow surface, JUnit + kotlinx-coroutines-test for testing.

- [ ] **Step 1:** Create `PeerHealth` sealed class with values matching JS: `UNKNOWN`, `HEALTHY`, `STALE`, `FAILED`, `OFFLINE`.

- [ ] **Step 2:** Create `SelfState` sealed class: `OFFLINE`, `CONNECTING`, `ONLINE`, `RECONNECTING(val surrenderedToUser:Boolean = false)`.

- [ ] **Step 3:** Create `SendGate` sealed class: `Ok`, `SelfOffline`, `PeerUnreachable(reason:String)`.

- [ ] **Step 4:** Write `PeerPingTrackerTest.kt` mirroring the JS tests in Task 2 (use `runTest` + `TestScope`).

- [ ] **Step 5:** Implement `PeerPingTracker.kt`. Use `SecureRandom` for nonce; b64url-encode without padding. Public surface: `sendPing(peerId): Pair<String, Deferred<PingResult>>`, `recordPong(nonce)`, `sweepExpired(now)`.

- [ ] **Step 6:** Run `./gradlew :app:testDebugUnitTest --tests "*PeerPingTrackerTest*"`, expect PASS.

- [ ] **Step 7:** Commit:
   ```
   feat(connection): android peer-ping tracker + state classes
   ```

---

## Task 14: Android — `peerHealth` and `selfState` reducers

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/PeerHealth.kt` (add `reduce` companion fn)
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/SelfState.kt` (add `reduce`)
- Create: `android/app/src/test/java/com/zaptransfer/android/connection/PeerHealthReduceTest.kt`
- Create: `android/app/src/test/java/com/zaptransfer/android/connection/SelfStateReduceTest.kt`

**Context:** Match Chrome's Tasks 3 + 4 behavior. Pure reducers with the same event vocabulary.

- [ ] **Step 1:** Define a `PeerHealthEvent` sealed class with all the events from Task 3 (PongReceived, FrameReceived, SendCompleted, PingMissed, PreFlightFailed, RelayPeerOnline, RelayPeerOffline, RecoverySucceeded, RecoveryGivenUp).

- [ ] **Step 2:** Same for `SelfStateEvent`.

- [ ] **Step 3:** Write tests covering every transition.

- [ ] **Step 4:** Implement `reduce(state, event)` companion functions on each.

- [ ] **Step 5:** Run tests, expect PASS.

- [ ] **Step 6:** Commit:
   ```
   feat(connection): android peerHealth + selfState reducers + tests
   ```

---

## Task 15: Android — `ConnectionAuthority` skeleton

**Files:**
- Create: `android/app/src/main/java/com/zaptransfer/android/connection/ConnectionAuthority.kt`
- Create: `android/app/src/test/java/com/zaptransfer/android/connection/ConnectionAuthorityTest.kt`

**Context:** Hilt `@Singleton`. Constructor-injected `SignalingClient`, `DeviceRepository`. Exposes `selfState: StateFlow<SelfState>`, `peerHealth: StateFlow<Map<DeviceId, PeerHealth>>`, `ensureSendable(deviceId)`, `requestReconnect()`. No recovery ladder yet (mirror Task 5 in JS).

- [ ] **Step 1:** Tests covering the same matrix as JS Task 5.

- [ ] **Step 2:** Implement: register a `SignalingListener` to observe relay messages; call `notifyAuthComplete` when `signalingClient.connectionState` flips to Connected; etc.

- [ ] **Step 3:** Wire into `BeamV2Wiring.kt`: call `connectionAuthority.notifyFrameReceived(deviceId)` after a successful inbound v2 frame decode.

- [ ] **Step 4:** Wire into `TransferEngine.kt`: call `connectionAuthority.notifySendCompleted(targetDeviceId)` after a successful `sendFile`/`sendClipboard` resolution.

- [ ] **Step 5:** Run tests + `./gradlew :app:compileDebugKotlin :app:testDebugUnitTest`, expect PASS.

- [ ] **Step 6:** Commit:
   ```
   feat(connection): android ConnectionAuthority skeleton
   ```

---

## Task 16: Android — background ping cadence

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/ConnectionAuthority.kt`
- Modify: `android/app/src/test/java/com/zaptransfer/android/connection/ConnectionAuthorityTest.kt`

**Context:** Mirror Chrome Task 7. Use `kotlinx.coroutines.delay` with an injectable `TimeSource` for testability.

- [ ] **Step 1:** Tests using `runTest` and `TestScope.testScheduler.advanceTimeBy(...)`. Cover the same scenarios as Chrome Task 7.

- [ ] **Step 2:** Implement: per peer in `peerHealth`, launch a coroutine that pings every 120s; on timeout, dispatches `PingMissed`.

- [ ] **Step 3:** Run, expect PASS.

- [ ] **Step 4:** Commit:
   ```
   feat(connection): android background peer-ping cadence
   ```

---

## Task 17: Android — Recovery ladder rungs 1+2

**Files:**
- Create: `android/app/src/main/java/com/zaptransfer/android/connection/RecoveryLadder.kt`
- Create: `android/app/src/test/java/com/zaptransfer/android/connection/RecoveryLadderTest.kt`
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/ConnectionAuthority.kt`

**Context:** Mirror Chrome Task 8. Single coroutine, sequential rungs, cancelable via `kotlinx.coroutines.cancel`.

- [ ] **Step 1:** Tests mirroring Chrome's ladder test matrix.

- [ ] **Step 2:** Implement `RecoveryLadder` with the same `Rung(name, budgetMs, action)` shape.

- [ ] **Step 3:** Wire Rungs 1 (re-register-rendezvous via `signalingClient`) and 2 (`signalingClient.disconnect(); signalingClient.connect(); registerRendezvous(...)`).

- [ ] **Step 4:** Run tests, expect PASS.

- [ ] **Step 5:** Commit:
   ```
   feat(connection): android recovery ladder rungs 1+2
   ```

---

## Task 18: Android — `ensureSendable` + TransferEngine wiring

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/ConnectionAuthority.kt`
- Modify: `android/app/src/main/java/com/zaptransfer/android/service/TransferEngine.kt`
- Modify: `android/app/src/test/java/com/zaptransfer/android/connection/ConnectionAuthorityTest.kt`

**Context:** Mirror Chrome Task 9. Implement the full pre-flight algorithm with the 30s recent-traffic skip.

- [ ] **Step 1:** Test matrix mirroring Chrome.

- [ ] **Step 2:** Implement `ensureSendable(deviceId): SendGate` per spec.

- [ ] **Step 3:** In `TransferEngine.sendFile` and `sendClipboard`, call `connectionAuthority.ensureSendable(targetDeviceId)` first; on `SendGate.Ok`, proceed; on failure, throw a typed exception that the UI layer translates.

- [ ] **Step 4:** Update `DeviceHubViewModel` to surface preflight failures as a transfer-history `FAILED` entry with a retry-eligible flag.

- [ ] **Step 5:** Run tests + a real device smoke-test (build APK, install, attempt send to disconnected peer → see Failed card immediately).

- [ ] **Step 6:** Commit:
   ```
   feat(connection): android ensureSendable + transfer-engine wiring
   ```

---

## Task 19: Android — UI binding (Compose) for peer health + reconnect

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/ui/devicehub/DeviceHubViewModel.kt`
- Modify: `android/app/src/main/java/com/zaptransfer/android/ui/devicehub/<DeviceHub composable>` (find via grep)
- Modify: any existing dot-color helper

**Context:** Mirror Chrome Task 10. Bind the per-device dot to `peerHealth` and the top banner to `selfState`. Add a "Reconnect" button (visible when `RECONNECTING(surrenderedToUser=true)`).

- [ ] **Step 1:** In `DeviceHubViewModel`, expose `connectionAuthority.peerHealth` and `selfState` as `StateFlow`s the composable can collect.

- [ ] **Step 2:** Update the composable to render dots by health state with the same color rules as Chrome.

- [ ] **Step 3:** Add a top-of-screen banner when `selfState != ONLINE`. Tapping its button calls `viewModel.requestReconnect()` → `connectionAuthority.requestReconnect()`.

- [ ] **Step 4:** Visual smoke check on a device (kill wifi briefly, observe banner; tap reconnect, observe ladder progress in logcat).

- [ ] **Step 5:** Commit:
   ```
   feat(android-ui): bind device hub to ConnectionAuthority state
   ```

---

## Task 20: Android — Recovery ladder Rung 3 (foreground service restart)

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/ConnectionAuthority.kt`
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/RecoveryLadder.kt`
- Modify: `android/app/src/main/java/com/zaptransfer/android/service/TransferForegroundService.kt`
- Modify: `android/app/src/test/java/com/zaptransfer/android/connection/RecoveryLadderTest.kt`

**Context:** Mirror Chrome Task 11. The Android-specific dance: `stopService` → wait for `onDestroy` (use a singleton `serviceLifecycle: MutableStateFlow<ServiceState>`) → clear in-memory transport state → `startForegroundService` again.

- [ ] **Step 1:** Add a `serviceLifecycle: MutableStateFlow<ServiceState>` (`STARTING | RUNNING | STOPPING | STOPPED`) updated from `TransferForegroundService.onCreate / onDestroy`.

- [ ] **Step 2:** Implement Rung 3 action: dispatch a `STOP_SERVICE` Intent → await `serviceLifecycle == STOPPED` (or 10s timeout) → `BeamV2Wiring`'s in-memory state cleared → dispatch a fresh `START_SERVICE` Intent → await `serviceLifecycle == RUNNING` AND `selfState = ONLINE` → declare success.

- [ ] **Step 3:** Add the same thrash guard as Chrome: 2 Rung-3 failures within 5 min → Rung 4. Rung 4 sets `selfState = RECONNECTING(surrenderedToUser=true)` and starts the exponential backoff schedule.

- [ ] **Step 4:** `requestReconnect()` cancels any running ladder and starts a fresh one at Rung 3, bypassing backoff.

- [ ] **Step 5:** Tests + manual smoke: simulate the "says connected nothing sends" by killing relay-side WS; observe rung 1+2 fail; observe Rung 3 successfully restart the FG service; verify the green dot recovers without user action.

- [ ] **Step 6:** Commit:
   ```
   feat(connection): android recovery ladder Rung 3 (FG service restart) + Rung 4 backoff
   ```

---

## Task 21: Android — Failed-transfer UX + retry

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/ui/devicehub/DeviceHubViewModel.kt`
- Modify: existing transfer-history composable
- Modify: `android/app/src/main/java/com/zaptransfer/android/data/db/entity/TransferHistoryEntity.kt` (add `failureReason: String?` if not present)

**Context:** Mirror Chrome Task 12. Failed transfers appear as cards with retry; persisted retry from history asks the user to re-select the file via SAF.

- [ ] **Step 1:** In `DeviceHubViewModel`, when `transferEngine.sendFile` throws a typed `PreFlightFailureException`, write a Failed history entry and surface it to the active-transfers panel.

- [ ] **Step 2:** Update the transfer-history list composable to render Failed entries with a Retry button. Live retry re-invokes the same send if the `Uri` is still valid (try-read + fallback to file picker on `SecurityException`/`FileNotFoundException`).

- [ ] **Step 3:** Add a SAF "Re-select file to retry" intent for persisted retries.

- [ ] **Step 4:** Manual smoke + commit:
   ```
   feat(android-ui): failed-transfer card with retry + SAF re-pick
   ```

---

## Task 22: Android — `ConnectivityManager.NetworkCallback` integration

**Files:**
- Modify: `android/app/src/main/java/com/zaptransfer/android/service/NetworkMonitor.kt`
- Modify: `android/app/src/main/java/com/zaptransfer/android/connection/ConnectionAuthority.kt`

**Context:** Per spec §"Android lifecycle": on `onLost`, mark `selfState = RECONNECTING` immediately; on `onAvailable`, trigger Rung 2 proactively. Shaves ~30s off recovery during walks/commutes.

- [ ] **Step 1:** Verify what `NetworkMonitor` already exposes (its `Flow<NetworkState>`); add observation hooks if needed.

- [ ] **Step 2:** In `ConnectionAuthority.init`, collect `NetworkMonitor.networkState`. On `Disconnected`, dispatch `NetworkLost` event (new) which transitions self to `RECONNECTING`. On the next non-Disconnected, kick the ladder at Rung 2.

- [ ] **Step 3:** Add tests using a fake `NetworkMonitor` flow.

- [ ] **Step 4:** Manual smoke: toggle airplane mode briefly while paired peer is online; observe banner appear immediately and recovery on re-enable.

- [ ] **Step 5:** Commit:
   ```
   feat(connection): android NetworkCallback integration with recovery ladder
   ```

---

## Phase 4 — Cross-platform integration test + smoke

## Task 23: Cross-platform integration test (Chrome ↔ Android over relay fixture)

**Files:**
- Create: `extension/test/connection-authority-integration.test.js`
- Modify: `extension/test/_helpers/relay-fixture.js` (extend if missing peer-ping forwarding from Task 1)

**Context:** Two simulated clients (one acting as Chrome SW, one as Android) connect to the fixture relay and exercise the authority end-to-end: ping/pong, recovery ladder progression, pre-flight blocking.

- [ ] **Step 1:** Spin up the relay fixture, instantiate two `ConnectionAuthority` (one configured as "chrome", one as "android") — they share the codebase but identify by deviceId.

- [ ] **Step 2:** Test: A and B paired; A's authority sends a peer-ping; B's authority responds with peer-pong; A's `peerHealth[B]` becomes `HEALTHY`. Assert latency < 100ms in fixture.

- [ ] **Step 3:** Test: kill B's WS server-side. A's next ping misses; after second miss, A's ladder runs Rung 1 (no effect — relay still dead-routing), Rung 2 (A reconnects own WS — still no B), then Chrome-side Rung 3's `forceFullReset` (which is testable in the fixture; only Android Rung 3 is excluded since it depends on a real foreground service). Assert ladder eventually reaches Rung 4 with `selfState = RECONNECTING(surrenderedToUser=true)`.

- [ ] **Step 4:** Test: bring B back. A's `requestReconnect()` triggers Rung 3 (full reset of A's WS path), peer comes online, ping cycle starts, `peerHealth[B]` returns to `HEALTHY`.

- [ ] **Step 5:** Test: with A and B healthy, an `ensureSendable` returns `Ok` immediately (within 30s of the last successful ping → recent-traffic skip).

- [ ] **Step 6:** Run, expect PASS. Commit:
   ```
   test(connection): cross-platform integration test for authority + ladder
   ```

---

## Task 24: Manual smoke checklist + release prep

**Files:**
- Create: `docs/superpowers/specs/2026-05-02-connection-authority-smoke-checklist.md`

**Context:** Per spec §"Manual smoke checklist". Run before merging the feature branch / shipping.

- [ ] **Step 1:** Walk through each of the 6 scenarios from the spec on a real Pixel + Chrome desktop:
   1. Force-stop Android — Chrome detects within ~5 min; subsequent send fails fast with Retry card.
   2. Disconnect Android wifi mid-transfer — sender shows "Failed — Retry?" within ~50s.
   3. Phone sleeps 10 min in pocket — opens to fully-healthy state without manual action.
   4. Tap manual Reconnect — fresh session within 30s, peer goes green.
   5. Drop 5 files in rapid succession — only one pre-flight ping fires (recent-traffic skip).
   6. Disable wifi entirely — top banner shows "Not connected — Reconnect"; tapping after wifi back recovers.

- [ ] **Step 2:** Document each scenario's PASS/FAIL with timestamps and notes in the markdown file.

- [ ] **Step 3:** Address any FAILures (loop back into earlier tasks or add follow-up tasks).

- [ ] **Step 4:** Commit:
   ```
   docs: connection-authority smoke checklist results
   ```

---

## Cross-cutting principles (apply to every task)

- **TDD first** for pure logic (state machines, ping tracker, ladder). For wiring tasks, write integration smoke tests where possible; otherwise verify via the manual smoke checklist.
- **DRY** between Chrome and Android — keep the public surface identical (`selfState`, `peerHealth`, `ensureSendable`, `requestReconnect`) so anyone reading either side recognizes the other.
- **YAGNI** — no auto-resume, no blob persistence, no encrypted ping. The spec explicitly defers them.
- **Frequent commits** — one per task minimum; sub-tasks may warrant additional commits if they leave the tree in a clean intermediate state.
- **Constants centralized** — `extension/connection/constants.js` and `android/.../connection/Constants.kt` define `BG_PING_INTERVAL_MS`, `PING_TIMEOUT_MS`, `RUNG_BUDGETS`, `BACKOFF_SCHEDULE_MS`, `RECENT_TRAFFIC_WINDOW_MS = 30_000`. Both sides must agree.

## Skills referenced

- @superpowers:test-driven-development — for the TDD discipline in pure-logic tasks
- @superpowers:systematic-debugging — when wiring tasks surface unexpected behavior
- @superpowers:verification-before-completion — before claiming any task complete

## Risk register (worth tracking during execution)

- **Chrome MV3 SW lifetime** during a 30s Rung-3 timeout — keepalive port should hold; verify in Task 11.
- **Android service restart timing** in Rung 3 — `stopService` is async; the spec recommends awaiting `onDestroy`; failure mode is racy restart.
- **Network-callback granularity** on Android — some OEMs throttle these; on Pixel they should fire reliably. Document behavior on test devices.
- **Mock-progress removal** in popup — make sure no other code path still expects `startMockTransferProgress` to exist before deleting (grep before commit).
