# Connection Authority — Reliable Connection + Transfer

**Status:** Draft
**Date:** 2026-05-02
**Builds on:** [`2026-04-30-beam-v2-design.md`](./2026-04-30-beam-v2-design.md)

## Why

The Beam v2 transport (just landed) is correct on the cryptography and frame‑level wire format, but the *connection layer above it* is unreliable in two specific ways the user has named:

1. **Force-stop required.** On Android, the user occasionally has to force-stop the app and reload the Chrome extension to recover any connection at all. The most common trigger is a "says connected, nothing sends" state — UI shows the peer as online, but transfers silently disappear.
2. **Silent transfer failures.** A send that *appears* to succeed (mock progress completes, no error toast) but never reaches the peer. Today's `popup.js` starts a mock progress animation *before* dispatching the SW message, so visual feedback does not reflect actual transmission state.

Both symptoms come from the same root cause: **multiple components hold opinions about "is the peer reachable," and those opinions disagree.** Relay presence events, WebSocket `readyState`, the v2 transport's outbox, and the popup's UI each have a partial view. There is no single authoritative answer to "can I send to device X right now?", so failures hide between the cracks.

This spec defines a single per-side authority that owns the answer.

## Goals

1. Eliminate the force-stop workaround. Whatever recovery the user does manually, the system must be able to do automatically.
2. Eliminate silent send failures. Every attempted transfer either succeeds, or the user sees a clear "Failed — Retry?" affordance with no fake progress.
3. Detect "WS open but peer unreachable" zombie states within ~5 minutes background, and ~5 seconds when the user taps send.
4. Provide a single observable connection state per peer that the UI and transport both read from.

## Non-goals (explicit, deferred)

- **Auto-resume mid-transfer.** A transfer interrupted by a connection drop is marked Failed; the user taps Retry and we re-send from frame 0. No persistent transfer state across disconnects, no resume protocol.
- **Persistent blob storage for retry.** Retrying a Failed transfer from history *after* an app restart prompts the user to re-pick the file. We do not cache file contents in `chrome.storage` or app cache.
- **Encrypted peer-ping.** The liveness ping carries no user data, no `transferId`, no key generation. Plaintext JSON over the existing rendezvous channel.
- **Auto-retry without user tap.** When the user chose C in brainstorming, we honored it: the system never re-sends without a tap.

## High-level design

Each side (Chrome SW + Android foreground service) runs one `ConnectionAuthority` singleton. It owns:

- The relay WebSocket lifecycle (open, auth, register-rendezvous, close)
- The peer-level liveness pings (background cadence + on-send pre-flight)
- A state machine for self-state and per-peer health
- A recovery ladder triggered when health degrades
- The single API surface that send paths and UI bind to

Everything else — `BeamV2Transport`, the popup, view models, transfer history — reads from the authority's flows. Nothing else holds an opinion about connectivity.

```
┌───────────────────┐                            ┌───────────────────┐
│   ConnectionAuth  │ ◄── peer-ping/pong (JSON)──► │   ConnectionAuth  │
│   (Chrome SW)     │   recovery ladder events    │   (Android FGSrv) │
└─────────┬─────────┘                            └─────────┬─────────┘
          │ exposes                                        │ exposes
          ▼                                                ▼
   ┌─────────────────┐                              ┌─────────────────┐
   │ selfState:      │                              │ selfState:      │
   │   Flow<Self>    │                              │   Flow<Self>    │
   │ peerHealth:     │                              │ peerHealth:     │
   │   Flow<Map>     │                              │   Flow<Map>     │
   │ ensureSendable()│                              │ ensureSendable()│
   │ requestReconnect│                              │ requestReconnect│
   └────────┬────────┘                              └────────┬────────┘
            │                                                │
        UI / popup                                       UI / Compose
        v2 transport sender                              v2 transport sender
```

## Wire protocol — peer-ping / peer-pong

A new pair of relay-routed JSON messages. The relay forwards them by `targetDeviceId` exactly like `register-rendezvous` and the existing `beam-v2-*` messages.

**Sender → peer:**
```json
{
  "type": "peer-ping",
  "nonce": "8f7c9a2b1e3d4f6a...",   // 16 random bytes, b64url, fresh per ping
  "targetDeviceId": "<peer id>",
  "rendezvousId":   "<peer id>"
}
```

**Peer → sender:**
```json
{
  "type": "peer-pong",
  "nonce": "8f7c9a2b1e3d4f6a..."     // echoed verbatim from the ping
}
```

The receiver does *no* validation of the ping beyond echoing the nonce. There is nothing to spoof — a forged pong with a stolen nonce only convinces us a dead peer is alive briefly until the next ping cycle, at which point a real send (which uses the v2 codec, not ping/pong) would still fail through the existing pre-flight + interrupt UX.

### Cadence

| Trigger | Timeout | On miss |
|---|---|---|
| Background, every 120s per online peer | 10s | first miss → `STALE`; second consecutive miss → `FAILED` + recovery ladder |
| On-send pre-flight | 5s | `FAILED` + recovery ladder; user-visible "Reconnecting…" in transfer card |

Two missed background pings before escalation absorbs single-packet loss without flickering UI.

### Server changes

Add `peer-ping` and `peer-pong` to the relay's allow-list of forwarded message types in `server/src/protocol.js`. No new state on the server.

### Sender bookkeeping

Per side: `Map<nonce_b64url, { sentAt: number, deadline: number, peerId: string }>`. Entries expire on pong receipt or on timeout sweep (1s tick).

## Connection state model

Two reactive flows. UI binds to `peerHealth` for per-device dots and to `selfState` for the top-level banner.

### Self state — "am I connected to the relay?"

```
   ┌───────────┐   user paired      ┌────────────┐
   │  OFFLINE  │ ─────────────────► │ CONNECTING │
   └───────────┘                     └─────┬──────┘
        ▲                                  │ WS open + auth + register
        │ stop()                           ▼
        │                            ┌────────────┐
        │           WS close   ┌─────│   ONLINE   │
        │       ┌──────────────┘     └────────────┘
        │       ▼
        │ ┌────────────────┐
        └─│ RECONNECTING   │ ──── recovery ladder ────► ONLINE on success
          └────────────────┘                            OFFLINE if surrenderred to user
```

- `OFFLINE` — no attempt active (not paired, app just started, user disabled)
- `CONNECTING` — initial handshake in progress
- `ONLINE` — WS open, auth complete, rendezvous registered
- `RECONNECTING` — was ONLINE, recovery ladder running

**Entry triggers for `CONNECTING`** (full set, not only the diagram's "user paired" arrow):
1. User completes pairing (first time)
2. App / SW cold boot with at least one paired device in storage
3. `requestReconnect()` invoked by user tap (transitions through `CONNECTING` on the way back to `ONLINE`)
4. Recovery ladder Rung 2 or Rung 3 begins (re-enters via `RECONNECTING → CONNECTING`)

### Peer health — for each paired device, "is this peer reachable?"

```
                 first observation
   ┌──────────┐ ─────────────────►  ┌──────────┐
   │ UNKNOWN  │     ping ok          │ HEALTHY  │
   └──────────┘                      └─────┬────┘
                                           │  one missed ping
                                           ▼
                                     ┌──────────┐
                                     │  STALE   │
                                     └─────┬────┘
                                           │  second missed ping
                              relay says   │  or pre-flight timeout
                                offline    ▼
                                ┌────────────────────┐
                                │      FAILED        │ ──► recovery ladder
                                │   recovery active  │
                                └────────────────────┘
                                           │
                                           ▼
                                     ┌──────────┐
                                     │ OFFLINE  │  (relay emitted peer-offline)
                                     └──────────┘
```

### What promotes a peer back to HEALTHY

Any of these counts as proof of life and resets the state to `HEALTHY`:

1. Successful `peer-pong` arrival (background or pre-flight)
2. Successful inbound v2 frame from that peer (`handleIncomingFrame` decoded successfully)
3. Successful outbound transfer completion to that peer (`sendFile` / `sendClipboard` returned OK)

Real send activity is its own liveness signal; we don't redundant-ping in the wake of a successful frame exchange.

### Exit from `OFFLINE`

A relay `peer-online` event for a device currently in `OFFLINE` transitions it to `UNKNOWN`, *not* directly to `HEALTHY`. The relay's view ("their WS is open") is weaker than ours ("they answered our ping"). The next background ping cycle (or first user-tap pre-flight) confirms reachability and promotes to `HEALTHY`. This avoids the "relay says online, app is dead" false-positive that already triggers the `says connected, nothing sends` symptom today.

### UI mapping

| Internal state | Per-device dot | Top banner (`selfState`) |
|---|---|---|
| `HEALTHY` | green | — |
| `STALE` | green with subtle pulse | — |
| `FAILED` | yellow + "Reconnecting…" | — |
| `OFFLINE` | grey | — |
| Self `OFFLINE` / `RECONNECTING` overrides all peers | grey | "Not connected — Reconnect" / "Reconnecting…" |

A single missed background ping must NOT flip the dot's color — that produces visual noise from harmless packet loss. Two misses, with a settle time, is the threshold for visible UI change.

### Public surface

```kotlin
// Android
interface ConnectionAuthority {
  val selfState:  StateFlow<SelfState>
  val peerHealth: StateFlow<Map<DeviceId, PeerHealth>>
  suspend fun ensureSendable(deviceId: DeviceId): SendGate
  suspend fun requestReconnect()                       // user tap
  fun observeForUi(deviceId: DeviceId): Flow<UiPeerState>  // collapsed view
}

sealed class SendGate {
  object Ok : SendGate()
  object SelfOffline : SendGate()
  data class PeerUnreachable(val reason: String) : SendGate()
}
```

```js
// Chrome (mirror)
class ConnectionAuthority {
  selfState   /* observable */;
  peerHealth  /* observable */;
  async ensureSendable(deviceId)       // returns { ok: true } or { ok: false, reason }
  async requestReconnect()
  observeForUi(deviceId) /* observable */
}
```

`ensureSendable` is what every sender (Beam v2 `sendFile` / `sendClipboard` callers) invokes before encoding the first frame.

`requestReconnect` is wired to the popup's "Reconnect" button and the Android UI equivalent. Always jumps to recovery ladder Rung 3.

## Recovery ladder

When peer health flips to `FAILED` (or self-state goes `RECONNECTING`), the authority runs **one** sequential ladder. Cheapest rung first. One ladder runs at a time per side — no parallelism, no nested retries.

### Rung 1 — Re-register rendezvous (5s budget)

The relay may have GC'd our session; resending `register-rendezvous` nudges it. If we receive `peer-online` for the suspect device within 5s, recovery succeeded.

### Rung 2 — WebSocket reconnect (15s budget)

Tear down `pairingWs`; open a fresh one; re-auth; re-register. This is what current auto-reconnect does — formalized as a rung. Wait for full handshake and at least one `peer-online` event for any paired device. If healthy, done.

### Rung 3 — Full session reset (30s budget)

The piece that replaces force-stop. New code on both sides.

**Android:**
1. Stop the foreground service that owns the WS (`stopService`)
2. Wait for service onDestroy
3. Clear in-memory transport state: outbox, inbox, pendingRotations
4. Reload paired devices from Room DB
5. Re-init crypto from `KeyManager`
6. Restart foreground service via Intent
7. Wait for `selfState = ONLINE` and `peerHealth` to populate

**Chrome:**
1. Call `stopPairingListener()`
2. Set `pairingWs = null`, `_inflightConnect = null`, `_inflightDeviceId = null`
3. Reset the v2 transport singleton (`_transport = null` in `beam-v2-wiring.js`)
4. Call `autoStartRelayIfPaired()` from a clean slate
5. Wait for `selfState = ONLINE` and `peerHealth` to populate

If healthy at the end, ladder resets to idle and next failure starts at Rung 1 again.

### Rung 4 — Surface to user (no auto-retry)

UI shows red dot + "Connection failed — tap to reconnect." Manual tap re-runs Rung 3 (skipping 1+2). Automatic re-attempt uses exponential backoff so a dead relay doesn't burn battery:

| Attempt | Delay before next auto-attempt |
|---|---|
| 1st | 30s |
| 2nd | 2 min |
| 3rd | 10 min |
| 4th+ | 30 min (cap) |

Manual tap always bypasses backoff.

### Discipline rules

- A rung that succeeds resets the ladder to idle. Next failure starts at Rung 1.
- Two full Rung-3 failures within 5 min → promote to Rung 4 immediately. Don't thrash.
- A "full Rung-3 failure" means: the ladder reached Rung 3, ran its 30s budget, and `selfState` did not become `ONLINE` (either because of timeout, thrown exception, or sub-step failure). Successful Rung 1 or Rung 2 in subsequent attempts does not count toward this promotion rule — only Rung 3 attempts.
- The whole ladder runs as one cancelable coroutine (Android) / promise chain (Chrome). `requestReconnect` mid-ladder cancels and restarts at Rung 3.
- Every rung transition is logged with timing: `[CA] ladder: rung=2 start`, `[CA] ladder: rung=2 ok t=12.4s`. Diagnoses regressions without manual instrumentation.

### Worst-case latencies

- **Pre-flight failure → user-visible result:** 5s (initial ping) + 5s (rung 1) + 15s (rung 2) + 30s (rung 3) = **~55s** with all rungs failing
- **Background failure → recovery complete:** 240s (two missed pings) + 50s (full ladder) = **~5 min** before user even knows there was a problem (only if all three rungs fail)

A user is never sitting watching the 55s — they tap retry. The 5min background ceiling means a phone in your pocket recovers without you opening the app.

## Send-time pre-flight

This is what fixes the "says connected, nothing sends" symptom directly. Every send path runs through `authority.ensureSendable(deviceId)` before encoding **any** frame.

### Flow

```
ensureSendable(deviceId):
  1. selfState != ONLINE         → return FAIL_SELF_OFFLINE
  2. peerHealth[deviceId] == HEALTHY
       AND lastTrafficAt[deviceId] < 30s ago
                                  → return OK            (skip ping)
  3. send peer-ping (5s timeout)
       pong received              → mark HEALTHY
                                  → return OK
       timeout                    → mark FAILED
                                  → kick recovery ladder
                                  → await ladder up to 50s
                                  → on success: retry one pre-flight ping
                                  → still failing: return FAIL_PEER_UNREACHABLE
```

The 30s "recent traffic" optimization prevents ping spam when the user drags 5 files in quick succession. Any successful send/receive within 30s counts as proof of life.

### Failure semantics

| Result | UI |
|---|---|
| `OK` | Transfer proceeds normally; v2 sendFile / sendClipboard called. |
| `FAIL_SELF_OFFLINE` | Top banner: "Not connected — Reconnect". No transfer card created. |
| `FAIL_PEER_UNREACHABLE` | Transfer card immediately appears as **Failed** with retry button. |

**Critically: zero frames are encoded or transmitted on failure.** We do not call the v2 transport's `sendFile`/`sendClipboard` at all. This kills the entire class of "encoded all 9 chunks, none arrived, mock progress shows 100%" bugs.

### Hook points

| Place | Today | After |
|---|---|---|
| `extension/background-relay.js` `sendFileEncrypted` | calls `getBeamV2Transport().sendFile(...)` directly | `await ensureSendable(targetDeviceId)`; then call sendFile |
| `extension/background-relay.js` `sendClipboardEncrypted` | calls `getBeamV2Transport().sendClipboard(...)` directly | same |
| `android/.../TransferEngine.kt` `sendFile` | calls `beamV2Wiring.transport.sendFile(...)` directly | `connectionAuthority.ensureSendable(...)`; then call sendFile |
| `android/.../TransferEngine.kt` `sendClipboard` | calls `beamV2Wiring.transport.sendClipboard(...)` directly | same |

### Edge case — connection dies between pre-flight and first frame

The existing path catches this: `_sendBinary` returns false → transport throws `NO_TRANSPORT` → caught by SW dispatch / Android scope handler → routed through the same Failed UX. Pre-flight makes this rare; it doesn't claim to eliminate it.

### Mock-progress removal

Today `popup.js` (~line 1482) calls `startMockTransferProgress` *before* dispatching the SW message — the bar animates regardless of reality. With pre-flight blocking the call:

- If pre-flight fails: card opens directly as Failed. No mock animation.
- If pre-flight passes: real progress comes from the v2 transport's `onProgress` callback.

The mock-progress code is deleted entirely.

## Failed-transfer UX + retry

### Where failed transfers appear

- **Live transfer card** on the device row / transfer panel — shown the moment failure is detected, with no fake progress.
- **Transfer history** — persisted entry with `status = FAILED`, visible after the live card is dismissed.

### Detection points (all converge on the same UX)

1. Pre-flight `ensureSendable` returns `FAIL_PEER_UNREACHABLE` — no frames encoded; card opens directly as Failed.
2. Mid-transfer interrupt — `_sendBinary` returns false during the send loop, OR `peerHealth` flips to `FAILED` mid-stream. Sender aborts the loop, marks card Failed.
3. Sender-side giveup — receiver never acks all chunks within `SENDER_GIVEUP_MS` (already exists in v2; routed through this UX now).
4. Receiver-side timeout — `RECEIVER_GIVEUP_MS` fires with missing chunks. Receiver shows an *informational* "Incoming transfer from <name> interrupted" history entry. **No retry button on receiver side** — sender owns retry.

### Retry semantics

| Where the user is | Retry behavior |
|---|---|
| **Card live on screen, app open** | Tap Retry → `ensureSendable` → re-encode from scratch → send. The original `File` object / Android `Uri` / bytes are still in memory. Friction-free. |
| **From history after app restart** | Tap Retry → because the original file may no longer be accessible (Chrome lost the `File` reference; Android URI may have lost permission), prompt: "Re-select the file to retry." |

This is the deliberate trade-off given the C choice: live retry is friction-free; persisted retry asks for the file again. We do not store multi-MB blobs.

### Caps + backoff

- **User-initiated retry**: no cap, no backoff. Tap as many times as you want.
- **Automatic retry**: none. Honors the C choice.

### Receiver-side history

| Outcome | History entry |
|---|---|
| File complete | `RECEIVED — Completed`, full size, name |
| Receiver giveup with missing chunks | `RECEIVED — Interrupted`, partial byte count |
| Decrypt failure | `RECEIVED — Decrypt failed` |

No retry button on receiver in any case.

## Platform concerns

### Chrome service worker lifecycle

The SW *will* die — keepalive port (commit `e0cfbf4`) extends its life but does not make it permanent. Browser restart, OOM, extension reload all kill it. Authority handles this by being **reconstructable, not persistent**:

- Authority is in-memory only. On SW wake, it boots `OFFLINE → CONNECTING`. All paired peers start as `UNKNOWN`. First ping cycle promotes them to `HEALTHY`. Cold start is the same code path as recovery from Rung 3.
- Popup opens → asks SW for `(selfState, peerHealth)` snapshot via `chrome.runtime.sendMessage`. If SW is asleep, the message wakes it (standard MV3). Popup then subscribes to push updates from the SW for as long as it's open.
- Failed-transfer history is written through to `chrome.storage.local` (durable). That is the only thing that needs to survive.

### Android lifecycle

- **Foreground service** owns the WS + the authority. Already in place; no architectural change.
- **Doze mode**: OkHttp `pingInterval` (already configured) catches WS death; Rung 2 picks up. On wake, the next background ping cycle (or first user-tap pre-flight) revalidates peer health.
- **Network handover (wifi ↔ cellular)**: register a `ConnectivityManager.NetworkCallback`. On `onLost` → mark `selfState = RECONNECTING` immediately without waiting for ping timeout. On `onAvailable` → trigger Rung 2 proactively. This shaves ~30s off recovery during walks/commutes.
- **Force-stop / swipe**: not a use case we optimize, just one we don't *require*. Fresh start hits the same cold-boot path as Chrome SW.

## State persistence — minimal

| Thing | Persisted? | Where |
|---|---|---|
| Paired devices, crypto keys, K_AB rings | yes (already) | Room DB / `chrome.storage.local` |
| Failed transfer history | yes | `TransferHistoryDao` / `chrome.storage.local` |
| In-flight transfer outbox/inbox | **no** | in-memory only — process death = lost transfer (matches the C choice: user retries) |
| Peer health, self state | **no** | recomputed from scratch every boot |
| Recovery ladder progress | **no** | resets to idle on cold boot |

This is deliberately minimal. Persisting in-flight transport state would require a much bigger spec (resume protocol, integrity verification across sessions) — and we explicitly chose C, not A.

## Testing strategy

### Unit (high coverage, fast)

Pure state transitions, no relay or WS:

- `PeerHealth` state machine: drive with synthesized ping/pong/timeout events; assert each transition (`UNKNOWN → HEALTHY`, `HEALTHY → STALE`, `STALE → FAILED`, `FAILED → HEALTHY` after recovery).
- Recovery ladder: mock each rung's outcome; assert ladder reaches expected terminal state with correct timeouts and rung sequencing.
- `ensureSendable`: matrix of `(selfState × peerHealth × recent-traffic-elapsed)` → expected `SendGate` result.
- Backoff schedule: assert delays at attempts 1..N match the table.

### Integration (relay fixture, already exists at `extension/test/_helpers/relay-fixture.js`)

- Boot fixture relay; connect simulated Chrome SW + simulated Android client.
- Inject failures: kill WS server-side, drop pings selectively, simulate auth lapse.
- Assert: recovery ladder progresses correctly, pre-flight blocks sends when expected, peer health flows reach the right terminal state in bounded time.
- Verify wire compatibility: Chrome's authority can be pinged by an Android-shape pong and vice versa.

### Manual smoke checklist (run before each release)

1. Force-stop Android app — Chrome detects within ~5 min; subsequent send fails fast with a Retry card (no force-stop required to recover).
2. Disconnect Android wifi mid-transfer — sender shows "Failed — Retry?" within ~50s.
3. Phone sleeps in pocket for 10 min — opens to fully-healthy state without manual action.
4. Tap manual Reconnect — fresh session within 30s, peer goes green.
5. Drop 5 files in rapid succession — only one pre-flight ping fires (recent-traffic skip working).
6. Disable wifi entirely — top banner shows "Not connected — Reconnect"; tapping Reconnect after wifi is back recovers.

The unit + integration tier should be tight enough that the manual list is verification, not exploration.

## Implementation order

Each step ships testable; each leaves the app working. No big-bang merge.

1. **Wire protocol** — peer-ping/pong message types + relay allow-list (`server/src/protocol.js`).
2. **Authority skeleton** — state machine + flows on both sides; no recovery yet, no pre-flight; verify state observably tracks WS open/close.
3. **Recovery ladder rungs 1+2** — re-register rendezvous + WS reconnect, formalized.
4. **Send pre-flight** — `ensureSendable` in both languages; hook into all four send paths; remove mock-progress in popup.
5. **Recovery ladder rung 3** — full session reset (Android service kill+restart; Chrome full-cleanup + restart).
6. **Failed-transfer UX** — Failed card, Retry button, history write-through, "re-select file" prompt for persisted retry.
7. **Network-callback + lifecycle integrations** — Android `ConnectivityManager.NetworkCallback`; Chrome SW boot path.
8. **Manual smoke checklist run** — verify all six scenarios.

## Out of scope (explicitly deferred to future work)

- Auto-resume mid-transfer (requires persistent transfer state; user explicitly chose against in brainstorming)
- Persistent blob storage for retry-from-history (privacy + storage cost vs convenience)
- Encrypted peer-ping (no payload to protect; spoofing pong gains nothing exploitable)
- Multi-peer fan-out reachability (each pairing is independent; no group concept)
- True post-compromise forward secrecy on the connection layer (orthogonal — see Beam v2 §Key Rotation)
