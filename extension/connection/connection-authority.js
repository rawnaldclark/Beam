/**
 * @file connection-authority.js
 * @description Single source of truth for relay-connection and peer-health state.
 *
 * Composes the pure pieces (Observable + reducers + PeerPingTracker) into
 * the object the rest of the extension talks to. The wiring layer (Task 6)
 * calls the `notifyXxx` methods; the send-path (Task 9) calls `ensureSendable`;
 * the popup (Task 10) subscribes to `selfState` and `peerHealth`.
 *
 * As of Task 7 this file owns the **background peer-ping cadence**:
 *   - Each peer added to `peerHealth` is scheduled for a ping at
 *     `lastActivityAt + BG_PING_INTERVAL_MS`.
 *   - When the cadence fires, the authority issues a `peer-ping` via the
 *     PeerPingTracker and starts a `PING_TIMEOUT_MS` timeout.
 *   - On `notifyPongReceived(nonce)` the authority looks up the nonce in its
 *     own per-peer state, dispatches `pong-received` to the reducer, clears
 *     the timeout, and reschedules the next ping.
 *   - On timeout, the authority dispatches `ping-missed`; per the reducer
 *     UNKNOWN/HEALTHY → STALE → FAILED.
 *   - OFFLINE peers are skipped (the relay-peer-online event resurrects
 *     them through UNKNOWN before any ping is issued).
 *
 * As of Task 8 the authority also drives the **recovery ladder**:
 *   - When a peer transitions into FAILED, a {@link RecoveryLadder} is
 *     started (one at a time across the whole authority — concurrent
 *     failures share the in-flight ladder).
 *   - When `selfState` enters RECONNECTING (e.g. ws-closed from ONLINE),
 *     the same ladder is started if none is running.
 *   - Rungs 1 + 2 are wired here; Rung 3 is a stub that throws "TODO Rung 3"
 *     until Task 11.
 *
 * As of Task 9 the authority implements the full **send-time pre-flight**:
 *   - `ensureSendable(peerId)` returns the per-spec `{ok}` shape gating every
 *     `sendClipboardEncrypted` / `sendFileEncrypted` call.
 *   - Self-offline short-circuits to `SELF_OFFLINE`.
 *   - HEALTHY peers with traffic in the last 30s skip the probe.
 *   - Otherwise we issue a 5s peer-ping; on timeout we mark FAILED, kick the
 *     recovery ladder, await its result, and retry one ping on success.
 *
 * As of Task 11 the authority owns the **full recovery ladder**:
 *   - **Rung 3** ("full session reset"): calls `signalingHooks.forceFullReset`
 *     to tear down the WS, the v2 transport singleton, and inflight-connect
 *     bookkeeping, then waits up to {@link RUNG_3_BUDGET_MS} for selfState to
 *     return to ONLINE. Failure (timeout or hook missing) advances to Rung 4.
 *   - **Rung 4** ("surrender to user"): sets the `surrenderedToUser` flag
 *     so the popup banner shows "Connection failed — tap to reconnect" with
 *     no auto-retry text, dispatches `recovery-given-up`, and schedules an
 *     auto-retry via {@link BACKOFF_SCHEDULE_MS} (30s → 2m → 10m → 30m cap).
 *   - **Thrash guard**: two full Rung-3 failures within
 *     {@link RUNG_3_THRASH_WINDOW_MS} skip Rungs 1+2 and Rung 3 itself, going
 *     straight to Rung 4.
 *   - **`requestReconnect()`** (popup tap): cancels any in-flight ladder,
 *     clears the backoff timer + surrender flag, and kicks a fresh ladder
 *     that starts at Rung 3.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

import { Observable } from './observable.js';
import { PeerPingTracker } from './peer-ping.js';
import { PeerHealth, reducePeerHealth } from './peer-health.js';
import { SelfState, reduceSelfState } from './self-state.js';
import { RecoveryLadder, awaitObservableOrTimeout } from './recovery-ladder.js';
import {
  BG_PING_INTERVAL_MS,
  PING_TIMEOUT_MS,
  RECENT_TRAFFIC_WINDOW_MS,
  RUNG_1_BUDGET_MS,
  RUNG_2_BUDGET_MS,
  RUNG_3_BUDGET_MS,
  BACKOFF_SCHEDULE_MS,
} from './constants.js';

/**
 * Window over which Rung-3 attempts are counted toward the thrash guard.
 * Per spec §"Discipline rules": "Two full Rung-3 failures within 5 min →
 * promote to Rung 4 immediately." A "full Rung-3 failure" means the ladder
 * reached Rung 3, ran its 30s budget, and `selfState` did not become ONLINE.
 */
const RUNG_3_THRASH_WINDOW_MS = 5 * 60 * 1_000;
/** Failure-count threshold within {@link RUNG_3_THRASH_WINDOW_MS}. */
const RUNG_3_THRASH_THRESHOLD = 2;

/**
 * Per-ping deadline for the send-time pre-flight peer-ping. Distinct from the
 * background cadence's {@link PING_TIMEOUT_MS} (10s) — pre-flight is on the
 * hot path of a user-initiated send, so we surface "peer unreachable" faster
 * by racing the tracker promise against this 5s timer rather than waiting on
 * the tracker's own timeout.
 */
const PRE_FLIGHT_PING_TIMEOUT_MS = 5_000;

/**
 * The authoritative coordinator for connection + peer-health state.
 *
 * Construct once per extension lifetime. Subscribers (popup UI, send-path)
 * read state via the two Observable getters; producers (signaling client,
 * relay handlers) push events via the `notifyXxx` methods.
 *
 * Internally:
 *   - `_selfState`  : Observable<SelfState> driven by `reduceSelfState`.
 *   - `_peerHealth` : Observable<Map<DeviceId, PeerHealth>> driven by
 *                     `reducePeerHealth` per-peer.
 *   - `_pingTracker`: optional PeerPingTracker (created only when the hooks
 *                     supply `ownDeviceId` — Task 5 may run before pairing
 *                     installs an identity).
 *   - `_peerCadence`: Map<peerId, {pingTimer, timeoutTimer, pendingNonce,
 *                     lastActivityAt}> tracking per-peer cadence state.
 *   - `_nonceToPeer`: Map<nonce, peerId> so notifyPongReceived can map the
 *                     incoming pong back to the peer for the reducer.
 *
 * @example
 *   const auth = new ConnectionAuthority({ signalingHooks });
 *   auth.selfState.subscribe(state => console.log('self:', state));
 *   auth.peerHealth.subscribe(map => render(map));
 *   auth.notifyWsOpening();
 *   auth.notifyAuthComplete();
 */
export class ConnectionAuthority {
  /**
   * @param {object} args
   * @param {object} args.signalingHooks
   *   Bag of caller-injected hooks. Required: at minimum a `sendJson` function
   *   for outbound WS messages once a tracker is needed. Optional fields:
   *
   *   - `ownDeviceId`     : `string` — needed before any peer-ping can fire
   *                         (Task 7); skeleton-mode tests omit it.
   *   - `forceWsReconnect`: `() => void | Promise<void>` — called by the
   *                         recovery ladder's Rung 2 to tear down `pairingWs`
   *                         and trigger a fresh `_doConnect` from the wiring
   *                         layer (see `connection-authority-wiring.js`).
   *                         When omitted, Rung 2 still runs but its action
   *                         immediately surrenders (returns false), advancing
   *                         the ladder to Rung 3. The wiring-layer
   *                         implementation lands in a follow-up task; Task 8
   *                         only documents the contract so test mocks are
   *                         clear.
   *   - `register`        : `() => void | Promise<void>` — optional alternate
   *                         hook for issuing the `register-rendezvous` Rung 1
   *                         dispatch. When omitted, Rung 1 falls back to
   *                         `sendJson({type:'register-rendezvous', ...})`
   *                         using `ownDeviceId`.
   *
   * @param {object} [args.options]
   * @param {number} [args.options.pingTimeoutMs]
   *   Per-ping deadline in milliseconds, forwarded to PeerPingTracker.
   *   Defaults to {@link PING_TIMEOUT_MS}.
   * @param {number} [args.options.bgPingIntervalMs]
   *   Background ping cadence interval in milliseconds. Defaults to
   *   {@link BG_PING_INTERVAL_MS}. Mostly an injection seam for tests.
   * @param {object} [args.options.timerImpl]
   *   Injectable clock + timer surface for unit tests. Must expose
   *   `setTimeout`, `clearTimeout`, and `now()` (returning current ms).
   *   Defaults to `globalThis` for `setTimeout`/`clearTimeout` and
   *   `Date.now` for `now`. Also forwarded to the recovery ladder's
   *   budget-timer helpers so ladder timing is virtual under FakeClock.
   * @throws {TypeError} If `signalingHooks` is missing.
   */
  constructor({ signalingHooks, options = {} }) {
    if (!signalingHooks) throw new TypeError('ConnectionAuthority: signalingHooks required');

    this._hooks = signalingHooks;
    this._selfState = new Observable(SelfState.OFFLINE);
    /** @type {Observable<Map<string, string>>} */
    this._peerHealth = new Observable(new Map());

    /**
     * "We have given up; user action required" flag (Task 11 / spec §Rung 4).
     * Lifted via {@link Observable} so the popup broadcaster can re-render
     * the banner on every change. Lives on the authority (not in the
     * selfState reducer) per the existing reducer comment at
     * `self-state.js:120-122` — `recovery-given-up` keeps selfState in
     * RECONNECTING and the surrender flag is observable independently.
     *
     * @type {Observable<boolean>}
     */
    this._surrenderedToUser = new Observable(false);

    this._pingTimeoutMs = options.pingTimeoutMs ?? PING_TIMEOUT_MS;
    this._bgPingIntervalMs = options.bgPingIntervalMs ?? BG_PING_INTERVAL_MS;

    // Timer/clock injection: tests pass a FakeClock with manual tick(ms).
    // Production omits `timerImpl` and we fall back to globalThis.setTimeout
    // and Date.now. We bind setTimeout/clearTimeout to whatever object owns
    // them so tests get the FakeClock methods, not host globals.
    const t = options.timerImpl ?? null;
    this._setTimeout = t && t.setTimeout
      ? t.setTimeout.bind(t)
      : globalThis.setTimeout.bind(globalThis);
    this._clearTimeout = t && t.clearTimeout
      ? t.clearTimeout.bind(t)
      : globalThis.clearTimeout.bind(globalThis);
    this._now = t && typeof t.now === 'function'
      ? () => t.now()
      : () => Date.now();
    // Bundle for sub-systems (recovery ladder helpers) that want a
    // `{setTimeout, clearTimeout, now}` shaped object — we share the same
    // bindings so the FakeClock is the single source of virtual time.
    this._timerImpl = {
      setTimeout: this._setTimeout,
      clearTimeout: this._clearTimeout,
      now: this._now,
    };

    // Hooks must provide ownDeviceId before sendPing can fire. The tracker is
    // constructed lazily-by-presence: if the hook bag lacks an identity (e.g.
    // first-boot before pairing), we leave it null. The cadence loop is
    // gated on tracker presence — without an identity we never schedule a
    // ping (the wiring will recreate the authority once pairing installs an
    // identity).
    this._pingTracker = signalingHooks.ownDeviceId
      ? new PeerPingTracker({
          sendJson: signalingHooks.sendJson,
          ownDeviceId: signalingHooks.ownDeviceId,
          timeoutMs: this._pingTimeoutMs,
        })
      : null;

    /**
     * Per-peer cadence state. Created when a peer is first added to
     * `peerHealth`; torn down on `notifyPeerOffline` (or shutdown).
     *
     * @type {Map<string, {
     *   pingTimer: ReturnType<typeof setTimeout> | null,
     *   timeoutTimer: ReturnType<typeof setTimeout> | null,
     *   pendingNonce: string | null,
     *   lastActivityAt: number,
     * }>}
     */
    this._peerCadence = new Map();

    /**
     * Reverse lookup so `notifyPongReceived(nonce)` can find the peer it
     * belongs to. Cleared along with the cadence entry's `pendingNonce`.
     *
     * @type {Map<string, string>}
     */
    this._nonceToPeer = new Map();

    /**
     * The currently-running recovery ladder, or `null` when idle. The spec
     * mandates one-ladder-at-a-time per side: a peer going FAILED while a
     * ladder is already running is absorbed into that ladder's success
     * criterion (Rung 2's "any paired peer reaching HEALTHY"). Clearing this
     * back to `null` when the ladder settles is what allows the next failure
     * to start at Rung 1 again.
     *
     * @type {RecoveryLadder|null}
     */
    this._currentLadder = null;

    /**
     * Timestamps (virtual or real, depending on `_now()`) of recent Rung-3
     * failures. A "full Rung-3 failure" is recorded by {@link _kickLadder}
     * exactly when the ladder reached Rung 3, ran its full budget, and
     * `selfState` did not become ONLINE. Entries older than
     * {@link RUNG_3_THRASH_WINDOW_MS} are pruned at the next read.
     *
     * @type {number[]}
     */
    this._rung3FailureLog = [];

    /**
     * Auto-retry attempt counter for Rung 4 backoff. Indexes into
     * {@link BACKOFF_SCHEDULE_MS}. Reset to 0 every time recovery succeeds
     * (or `requestReconnect` succeeds). Capped at the last index (the spec's
     * 30m "stays at cap" rule).
     *
     * @type {number}
     */
    this._backoffAttempt = 0;

    /**
     * Pending Rung-4 auto-retry timer id. Set when {@link _scheduleBackoffRetry}
     * arms a timer; cleared when the timer fires, when `requestReconnect` is
     * called (manual tap always bypasses backoff), or on shutdown.
     *
     * @type {ReturnType<typeof setTimeout> | null}
     */
    this._backoffTimer = null;

    /**
     * "Recent traffic" timestamps consumed by {@link ensureSendable} to skip
     * the pre-flight peer-ping when proof-of-life is fresh. Updated on
     * `notifyFrameReceived` and `notifySendCompleted` only — pong arrivals
     * from the cadence loop are NOT recorded here (they are already
     * indirectly reflected in `peerHealth === HEALTHY`, but the spec's
     * "recent traffic" is real frame I/O, not a synthetic liveness probe).
     *
     * Maintained separately from `_peerCadence[id].lastActivityAt` because
     * cadence entries are torn down on `notifyPeerOffline` / `_stopCadence`,
     * which would lose the freshness signal between an OFFLINE flicker and
     * the very next send. The pre-flight algorithm wants to consult fresh
     * traffic regardless of cadence-engine bookkeeping.
     *
     * @type {Map<string, number>}
     */
    this._lastTrafficAt = new Map();

    /**
     * Per-peer in-flight `ensureSendable` promises. Concurrent calls for the
     * same peer share one promise so a clipboard burst (Task 10's "drag 5
     * files" scenario) doesn't fire five back-to-back peer-pings to the same
     * device. Cleared synchronously when the underlying promise settles.
     *
     * @type {Map<string, Promise<{ok:true} | {ok:false, reason:string}>>}
     */
    this._inflightPreflight = new Map();

    this._shutdown = false;
  }

  // ── Observable getters ──────────────────────────────────────────────────

  /** Subscribable self-connection state (SelfState enum value). */
  get selfState() { return this._selfState; }

  /** Subscribable Map<DeviceId, PeerHealth> snapshot. Map is replaced on each
   *  change; never mutated in place (subscribers can compare references). */
  get peerHealth() { return this._peerHealth; }

  /**
   * Subscribable boolean: `true` after the recovery ladder has surrendered
   * to the user (Rung 4 reached without success, OR the thrash guard
   * promoted us). Cleared when {@link requestReconnect} is invoked or when
   * the next ladder succeeds. The popup uses this to choose between the
   * "Reconnecting…" yellow banner and the "Connection failed — tap to
   * reconnect" red banner.
   */
  get surrenderedToUser() { return this._surrenderedToUser; }

  // ── Notify methods (called by wiring layer in Task 6) ───────────────────
  // These translate "things that happened on the wire" into reducer events.
  // They are pure dispatchers — no I/O, no timers — so the wiring layer can
  // call them freely without needing to know reducer semantics.

  /** WebSocket connect attempt has started. */
  notifyWsOpening()    { this._dispatchSelf({ type: 'start-connect' }); }
  /** Relay accepted our auth frame; we are ONLINE. */
  notifyAuthComplete() { this._dispatchSelf({ type: 'auth-complete' }); }
  /** WebSocket closed unexpectedly. */
  notifyWsClosed()     { this._dispatchSelf({ type: 'ws-closed' }); }

  /** Relay reports a peer's WS is open (weaker-than-pong evidence). */
  notifyPeerOnline(peerId) {
    this._dispatchPeer(peerId, { type: 'relay-peer-online' });
    // Either a brand-new peer (UNKNOWN seeded) or a resurrection from
    // OFFLINE → UNKNOWN: in both cases we need cadence to be running so the
    // next 120s tick produces a ping. _ensureCadence is idempotent.
    this._ensureCadence(peerId);
  }
  /** Relay reports a peer's WS is closed. */
  notifyPeerOffline(peerId) {
    this._dispatchPeer(peerId, { type: 'relay-peer-offline' });
    // OFFLINE owns the floor — no cadence work for this peer until the
    // relay tells us it is online again. Drop timers and any in-flight
    // nonce so we don't fire a stale ping after the peer comes back.
    this._stopCadence(peerId);
  }
  /** A real v2 frame was decoded from `peerId` — strong proof of life. */
  notifyFrameReceived(peerId) {
    this._dispatchPeer(peerId, { type: 'frame-received' });
    this._noteActivity(peerId);
    this._lastTrafficAt.set(peerId, this._now());
  }
  /** A frame send to `peerId` succeeded end-to-end — strong proof of life. */
  notifySendCompleted(peerId) {
    this._dispatchPeer(peerId, { type: 'send-completed' });
    this._noteActivity(peerId);
    this._lastTrafficAt.set(peerId, this._now());
  }

  /**
   * A peer-pong arrived. The authority tracks `nonce → peerId` itself so it
   * can dispatch `pong-received` into the right peer's reducer (the tracker
   * resolves the ping promise by nonce, but the reducer needs the peerId).
   *
   * On a known nonce: dispatch `pong-received`, clear the timeout, update
   * `lastActivityAt`, and reschedule the next ping. Also forwards to the
   * tracker so any ensureSendable pre-flight in Task 9 can resolve.
   *
   * On an unknown nonce (stale, duplicate, or after peer-offline cleared
   * the entry): no-op. The tracker call is still safe — it no-ops on
   * unknown nonces.
   *
   * @param {string} nonce
   */
  notifyPongReceived(nonce) {
    // Always feed the tracker — its bookkeeping is independent of the
    // cadence engine and Task 9 will await tracker promises directly.
    this._pingTracker?.recordPong(nonce);

    const peerId = this._nonceToPeer.get(nonce);
    if (!peerId) return;
    const entry = this._peerCadence.get(peerId);
    if (!entry || entry.pendingNonce !== nonce) {
      // Stale entry (cadence was torn down between sendPing and pong) —
      // tracker handled the resolution; nothing further to do.
      this._nonceToPeer.delete(nonce);
      return;
    }

    // Clear the in-flight bookkeeping before dispatching so any reducer-side
    // observer that introspects state sees a quiescent cadence.
    if (entry.timeoutTimer != null) {
      this._clearTimeout(entry.timeoutTimer);
      entry.timeoutTimer = null;
    }
    entry.pendingNonce = null;
    this._nonceToPeer.delete(nonce);

    this._dispatchPeer(peerId, { type: 'pong-received' });
    this._noteActivity(peerId);
  }

  // ── Public surface (stubs for Task 5; real impl in Tasks 7+9) ──────────

  /**
   * Pre-flight check before sending to `peerId`. Implements the full algorithm
   * from spec §"Send-time pre-flight":
   *
   *   1. selfState != ONLINE                          → FAIL_SELF_OFFLINE
   *   2. peerHealth = HEALTHY AND lastTrafficAt < 30s → OK (skip ping)
   *   3. send peer-ping (5s timeout)
   *        pong               → mark HEALTHY, OK
   *        timeout            → mark FAILED, kick ladder, await up to 50s
   *           ladder ok       → retry one ping; pong → OK
   *           ladder failure  → FAIL_PEER_UNREACHABLE
   *
   * Concurrent calls for the same peer are coalesced via
   * {@link _inflightPreflight} so a clipboard burst doesn't fire N back-to-back
   * peer-pings to the same device. Calls for different peers run in parallel
   * (no global lock).
   *
   * Skeleton-mode (no `_pingTracker` because no `ownDeviceId` was provided at
   * construction): returns `{ok:false, reason:"PEER_UNREACHABLE"}` — without
   * an identity we cannot probe the peer, so the safest signal is "not
   * sendable" rather than a false positive.
   *
   * @param {string} peerId
   * @returns {Promise<{ok: true} | {ok: false, reason: string}>}
   */
  async ensureSendable(peerId) {
    // Step 1: self-online gate. Cheap, synchronous, applies before any
    // per-peer coalescing — a self-offline check is the same answer for every
    // peer, no benefit to sharing the inflight slot.
    if (this._selfState.value !== SelfState.ONLINE) {
      return { ok: false, reason: 'SELF_OFFLINE' };
    }

    // Coalesce concurrent calls for the same peer. The first caller drives
    // the probe; the rest await the same outcome.
    const existing = this._inflightPreflight.get(peerId);
    if (existing) return existing;

    const promise = this._runEnsureSendable(peerId).finally(() => {
      // Clear only if the entry is still ours — defensive; in practice we
      // never replace it mid-flight.
      if (this._inflightPreflight.get(peerId) === promise) {
        this._inflightPreflight.delete(peerId);
      }
    });
    this._inflightPreflight.set(peerId, promise);
    return promise;
  }

  /**
   * Inner pre-flight body — separated so {@link ensureSendable} can wrap it
   * with the per-peer coalescing Map without nesting the algorithm.
   *
   * @param {string} peerId
   * @returns {Promise<{ok: true} | {ok: false, reason: string}>}
   * @private
   */
  async _runEnsureSendable(peerId) {
    // Step 2: HEALTHY + recent traffic skip.
    if (this._isHealthyWithRecentTraffic(peerId)) {
      return { ok: true };
    }

    // Step 3a: probe with a 5s peer-ping. Skeleton-mode (no tracker) cannot
    // probe; treat as unreachable rather than waving the send through.
    const firstProbe = await this._preFlightProbe(peerId);
    if (firstProbe.ok) return { ok: true };

    // Step 3b: probe failed. Mark FAILED (idempotent if already FAILED) and
    // ensure a recovery ladder is running. The reducer's `pre-flight-failed`
    // event drives any non-OFFLINE state directly to FAILED. The
    // `_dispatchPeer` post-hook kicks `_kickLadder` only on the OLD→FAILED
    // transition; if the peer was already FAILED we still need a ladder so
    // we explicitly call `_kickLadder` after the dispatch (idempotent: a
    // running ladder is reused).
    this._dispatchPeer(peerId, { type: 'pre-flight-failed' });
    this._kickLadder({ triggerPeerId: peerId, reason: 'pre-flight-failed' });

    // Step 3c: await the in-flight ladder. Spec budgets up to 50s
    // (Rung 1 = 5s + Rung 2 = 15s + Rung 3 = 30s). We don't impose a separate
    // timeout here — the ladder owns its own budget timers and resolves with
    // `ok:false` on exhaustion / cancellation. No ladder running (e.g.
    // skeleton-mode where _kickLadder bails because shutdown started)
    // is treated as a synchronous failure.
    const ladderResult = await this._awaitLadderResolved();
    if (!ladderResult.ok) {
      return { ok: false, reason: 'PEER_UNREACHABLE' };
    }

    // Step 3d: ladder succeeded. Re-probe one more time. The ladder's
    // success path already dispatched `recovery-succeeded` which dropped the
    // peer to UNKNOWN, so the HEALTHY-skip branch won't short-circuit;
    // we issue a fresh peer-ping to confirm the send path before the caller
    // commits to encoding frames.
    const retryProbe = await this._preFlightProbe(peerId);
    if (retryProbe.ok) return { ok: true };
    return { ok: false, reason: 'PEER_UNREACHABLE' };
  }

  /**
   * Step-2 helper: returns true iff the peer is HEALTHY AND a recent traffic
   * timestamp falls within {@link RECENT_TRAFFIC_WINDOW_MS}.
   *
   * @param {string} peerId
   * @returns {boolean}
   * @private
   */
  _isHealthyWithRecentTraffic(peerId) {
    if (this._peerHealth.value.get(peerId) !== PeerHealth.HEALTHY) return false;
    const last = this._lastTrafficAt.get(peerId);
    if (last == null) return false;
    return (this._now() - last) < RECENT_TRAFFIC_WINDOW_MS;
  }

  /**
   * Issue a single peer-ping racing the tracker's resolve against a 5s timer.
   *
   * Implementation note: the cadence-loop {@link _pingTracker} has its own
   * 10s `timeoutMs`. Reusing it for pre-flight is fine — we ignore the
   * tracker's longer timeout by resolving on whichever lands first
   * (pong, abort, or our 5s timer). A late pong after our timer fires is
   * still safe: the tracker cleans up its own pending entry on
   * `recordPong` / `sweepExpired`.
   *
   * Per Task 11 follow-up F: a successful pre-flight pong is real proof of
   * peer life and SHOULD promote peerHealth through the reducer. We
   * deliberately do NOT register the nonce in `_nonceToPeer` (that map is
   * the cadence engine's bookkeeping; mixing pre-flight nonces in would
   * complicate the cadence-engine invariants). Instead, we explicitly
   * dispatch `pong-received` directly when the tracker promise resolves
   * inside this function. This keeps the cadence Map clean while still
   * letting the reducer treat a successful pre-flight as strong evidence.
   *
   * Resource discipline: every code path clears the timer and, in shutdown
   * scenarios, leaves no dangling promise references — the tracker's own
   * cleanup handles the late-pong / late-sweep cases.
   *
   * @param {string} peerId
   * @returns {Promise<{ok: true} | {ok: false, reason: string}>}
   * @private
   */
  _preFlightProbe(peerId) {
    if (!this._pingTracker) {
      // Skeleton-mode — cannot probe; report unreachable.
      return Promise.resolve({ ok: false, reason: 'PEER_UNREACHABLE' });
    }
    if (this._shutdown) {
      return Promise.resolve({ ok: false, reason: 'PEER_UNREACHABLE' });
    }

    const { promise: pingPromise } = this._pingTracker.sendPing(peerId, this._now());

    return new Promise((resolve) => {
      let settled = false;
      let timerId = null;

      const cleanup = () => {
        if (timerId != null) {
          try { this._clearTimeout(timerId); } catch { /* swallow */ }
          timerId = null;
        }
      };
      const settle = (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      };

      timerId = this._setTimeout(
        () => settle({ ok: false, reason: 'timeout' }),
        PRE_FLIGHT_PING_TIMEOUT_MS,
      );
      // Unref-when-available so a test that doesn't drive the FakeClock
      // (real-clock fallback) can still exit cleanly. FakeClock returns a
      // plain number — the typeof guard makes this a no-op there.
      if (timerId && typeof timerId.unref === 'function') timerId.unref();

      pingPromise.then(
        () => {
          // Pong landed within our 5s window — promote the peer to HEALTHY
          // through the reducer. Per follow-up F: pre-flight liveness is
          // strong proof of life and should be reflected in peerHealth so
          // the popup dot stops being yellow (STALE) when the user has just
          // proven the peer is responsive.
          this._dispatchPeer(peerId, { type: 'pong-received' });
          settle({ ok: true });
        },
        // The tracker rejects with `{ok:false, reason:'timeout'}` when its
        // own (10s) sweep finds the entry expired. We may resolve via our
        // 5s timer first; if not, this rejection short-circuits us.
        () => settle({ ok: false, reason: 'timeout' }),
      );
    });
  }

  /**
   * Returns a promise that resolves when {@link _currentLadder} settles, or
   * resolves immediately with `{ok:false}` if no ladder is running.
   *
   * MUST be called AFTER `_kickLadder` has had a chance to install the
   * ladder — otherwise the synchronous `_currentLadder` snapshot is `null`
   * and the caller short-circuits to PEER_UNREACHABLE without actually
   * giving the ladder a chance to recover. (`ensureSendable`'s call site is
   * structured so the kick precedes the await; tests that bypass that
   * ordering will see `{ok:false}` for the wrong reason.)
   *
   * The {@link RecoveryLadder#run} method memoizes — calling `.run()` after
   * the ladder has already started returns the same promise, so observing it
   * post-kick is safe and side-effect-free.
   *
   * @returns {Promise<{ok: boolean}>}
   * @private
   */
  async _awaitLadderResolved() {
    const ladder = this._currentLadder;
    if (!ladder) return { ok: false };
    try {
      const result = await ladder.run();
      return { ok: !!(result && result.ok) };
    } catch {
      // _runInternal should not reject, but defend against it anyway.
      return { ok: false };
    }
  }

  /**
   * Manual reconnect entry point (popup "Reconnect now" button). Cancels any
   * in-flight ladder, clears the Rung-4 backoff timer, drops the
   * `surrenderedToUser` flag, and dispatches a fresh ladder that starts at
   * Rung 3 (skipping Rungs 1 + 2 — manual reconnect always implies the
   * lighter rungs already failed or the user knows they will).
   *
   * Per spec §"Discipline rules": "Manual tap always bypasses backoff." The
   * thrash guard is also reset (the user has manually intervened, so the
   * "we keep failing back-to-back" signal is no longer the source of truth).
   *
   * Resolves with `{ ok: true }` on a successful reconnect (Rung 3 succeeded
   * within budget) or `{ ok: false }` if Rung 3 failed and we surrendered
   * to Rung 4 again. The SW message router uses the boolean to pick a
   * response message for the popup.
   *
   * @returns {Promise<{ok: boolean}>}
   */
  async requestReconnect() {
    if (this._shutdown) return { ok: false };

    // 1) Cancel any in-flight ladder. Its run() promise resolves with
    // {ok:false, cancelled:true} once the in-flight rung settles in response
    // to the abort signal — which means the post-resolve thrash-counter
    // bookkeeping in _kickLadder DOES NOT fire (we check `cancelled`).
    if (this._currentLadder) {
      const cancelling = this._currentLadder;
      cancelling.cancel();
      this._currentLadder = null;
    }

    // 2) Cancel any pending Rung-4 backoff retry. Manual tap is the user
    // saying "don't wait, try now."
    this._cancelBackoffTimer();

    // 3) Clear the surrender flag so the popup shows "Reconnecting…" again
    // (yellow), not "Connection failed" (red).
    if (this._surrenderedToUser.value) {
      this._surrenderedToUser.next(false);
    }

    // 4) Reset the thrash log — the user has intervened, so "two recent
    // Rung-3 failures" is no longer the relevant signal.
    this._rung3FailureLog = [];

    // 5) Build the ladder + latch `_currentLadder` BEFORE dispatching
    // `recovery-began` (same ordering rationale as `_kickLadder`: the
    // selfState post-hook re-enters `_kickLadder`, which must hit the
    // "ladder owns the floor" guard rather than starting a second ladder).
    const ladder = this._buildRung3OnlyLadder();
    this._currentLadder = ladder;

    // 6) Ensure selfState is at least RECONNECTING so the popup banner shows
    // recovery-in-progress while we drive Rung 3.
    this._dispatchSelf({ type: 'recovery-began' });

    // eslint-disable-next-line no-console
    console.log('[CA] ladder: kicked reason=manual-reconnect');
    let result;
    try {
      result = await ladder.run();
    } catch {
      result = { ok: false };
    }
    // Settle the ladder slot and react to the outcome. We do this inline
    // (rather than via _kickLadder's .then) because the caller awaits us.
    if (this._currentLadder === ladder) this._currentLadder = null;
    this._handleLadderSettled(ladder, result, /*triggerPeerId*/ null);
    return { ok: !!(result && result.ok) };
  }

  // ── Internal dispatch helpers ──────────────────────────────────────────

  /**
   * Run an event through the selfState reducer; emit only if it produced a
   * different state. Identity check (===) is sufficient since the reducer
   * returns enum string constants.
   *
   * Side effect: when the transition crosses *into* `RECONNECTING` from any
   * other state, kick the recovery ladder (if no ladder is already running).
   * Per spec §"Recovery ladder", `selfState` going `RECONNECTING` is one of
   * the two ladder triggers; the other is `peerHealth[X] = FAILED`, handled
   * in {@link _dispatchPeer}.
   */
  _dispatchSelf(event) {
    const prev = this._selfState.value;
    const next = reduceSelfState(prev, event);
    if (next === prev) return;
    this._selfState.next(next);
    if (prev !== SelfState.RECONNECTING && next === SelfState.RECONNECTING) {
      this._kickLadder({ triggerPeerId: null, reason: 'self-reconnecting' });
    }
  }

  /**
   * Run an event through the peerHealth reducer for `peerId`; emit only if
   * it produced a different state OR the peer was not yet in the map. New
   * peers default to UNKNOWN; the first event a peer sees (typically
   * `relay-peer-online`) seeds the map entry even if the reducer's return
   * equals the implicit UNKNOWN default — that way the popup's "known
   * devices" view reflects presence as soon as the relay reports it. The
   * map is replaced (not mutated) on change so subscribers comparing
   * references see a fresh value.
   */
  _dispatchPeer(peerId, event) {
    const map = this._peerHealth.value;
    const had = map.has(peerId);
    const current = had ? map.get(peerId) : PeerHealth.UNKNOWN;
    const next = reducePeerHealth(current, event);
    // Skip emission only when the peer was already in the map AND the
    // reducer returned the same state. A first-sighting event must always
    // seed the map entry, even if the resulting state happens to be UNKNOWN.
    if (had && next === current) return;
    const newMap = new Map(map);
    newMap.set(peerId, next);
    this._peerHealth.next(newMap);
    // Recovery-ladder trigger: any peer crossing INTO FAILED kicks the
    // ladder if none is running. Concurrent failures share the in-flight
    // ladder — Rung 2's success criterion ("any paired peer HEALTHY")
    // covers them. See spec §"Recovery ladder", discipline rules.
    if (current !== PeerHealth.FAILED && next === PeerHealth.FAILED) {
      this._kickLadder({ triggerPeerId: peerId, reason: 'peer-failed' });
    }
  }

  // ── Cadence engine (Task 7) ─────────────────────────────────────────────

  /**
   * Ensure a peer has an active cadence entry. Idempotent: if the peer
   * already has a scheduled ping, this is a no-op. Called when a peer is
   * first observed (relay-peer-online) so the 120s clock starts ticking.
   *
   * No-op when no PeerPingTracker exists (no ownDeviceId at construction
   * time) — there's nothing to send. The wiring layer is expected to
   * reconstruct the authority once pairing installs an identity.
   *
   * @param {string} peerId
   */
  _ensureCadence(peerId) {
    if (this._shutdown) return;
    if (!this._pingTracker) return;
    if (this._peerCadence.has(peerId)) return;
    const entry = {
      pingTimer: null,
      timeoutTimer: null,
      pendingNonce: null,
      lastActivityAt: this._now(),
    };
    this._peerCadence.set(peerId, entry);
    this._schedulePing(peerId);
  }

  /**
   * Cancel any pending ping/timeout timers for `peerId` and forget the
   * cadence entry. Called on peer-offline and shutdown.
   *
   * @param {string} peerId
   */
  _stopCadence(peerId) {
    const entry = this._peerCadence.get(peerId);
    if (!entry) return;
    if (entry.pingTimer != null) this._clearTimeout(entry.pingTimer);
    if (entry.timeoutTimer != null) this._clearTimeout(entry.timeoutTimer);
    if (entry.pendingNonce != null) this._nonceToPeer.delete(entry.pendingNonce);
    this._peerCadence.delete(peerId);
  }

  /**
   * Update `lastActivityAt` for `peerId` and reschedule the next ping for
   * `lastActivityAt + bgPingIntervalMs`. Does NOT interrupt an in-flight
   * ping (i.e. one whose timeout has not fired yet) — recent inbound
   * activity proves liveness, so we let the in-flight pong settle naturally
   * and just push the next cadence cycle out.
   *
   * Called from notifyFrameReceived, notifySendCompleted, and the pong path
   * in notifyPongReceived.
   *
   * @param {string} peerId
   */
  _noteActivity(peerId) {
    const entry = this._peerCadence.get(peerId);
    if (!entry) return;
    entry.lastActivityAt = this._now();
    // If a ping is in flight (timeoutTimer set), don't disturb it; the next
    // cycle is rescheduled when the pong/timeout resolves.
    if (entry.timeoutTimer != null) return;
    if (entry.pingTimer != null) {
      this._clearTimeout(entry.pingTimer);
      entry.pingTimer = null;
    }
    this._schedulePing(peerId);
  }

  /**
   * Schedule the next ping for `peerId` at `lastActivityAt + bgPingIntervalMs`.
   * Uses the injected timer; the delay is computed against `_now()` so a
   * short delay (or even 0) is correct if activity is older than the
   * interval already.
   *
   * Precondition: the cadence entry exists and has no in-flight ping
   * (caller cleared `pingTimer` / `timeoutTimer`).
   *
   * @param {string} peerId
   */
  _schedulePing(peerId) {
    const entry = this._peerCadence.get(peerId);
    if (!entry) return;
    const dueAt = entry.lastActivityAt + this._bgPingIntervalMs;
    const delay = Math.max(0, dueAt - this._now());
    entry.pingTimer = this._setTimeout(() => this._fireCadenceTick(peerId), delay);
    // Unref the real-clock variant so a test that doesn't inject a FakeClock
    // (and so doesn't drive the cadence loop deterministically) still lets
    // the process exit cleanly. FakeClock returns a plain number — the typeof
    // guard makes this a no-op there. Note: this does NOT change cadence
    // semantics in production: in the SW the event loop is kept alive by the
    // WebSocket / message handlers, not by ping timers.
    if (entry.pingTimer && typeof entry.pingTimer.unref === 'function') entry.pingTimer.unref();
  }

  /**
   * Cadence-timer callback: actually issue the peer-ping (or skip it for
   * an OFFLINE peer) and start the timeout.
   *
   * @param {string} peerId
   */
  _fireCadenceTick(peerId) {
    if (this._shutdown) return;
    const entry = this._peerCadence.get(peerId);
    if (!entry) return;
    entry.pingTimer = null;

    // Skip pings to known-OFFLINE peers. relay-peer-online resurrects them
    // through UNKNOWN before any ping is issued; pinging an OFFLINE peer
    // would just produce a guaranteed timeout and a misleading FAILED state.
    const currentHealth = this._peerHealth.value.get(peerId);
    if (currentHealth === PeerHealth.OFFLINE) return;

    if (!this._pingTracker) return;

    const { nonce, promise: trackerPromise } = this._pingTracker.sendPing(peerId, this._now());
    // The cadence loop owns its own timeout via `_handlePingTimeout`; the
    // tracker's internal promise is not awaited by us. Attach a no-op
    // catch so a tracker `sweepExpired` (e.g. follow-up E's per-kick GC)
    // doesn't surface as an unhandled rejection. The .then(()=>{}) on the
    // resolve side is harmless — `notifyPongReceived` already forwards
    // pongs into the reducer through the cadence's `_nonceToPeer` map.
    if (trackerPromise && typeof trackerPromise.then === 'function') {
      trackerPromise.then(() => {}, () => {});
    }
    entry.pendingNonce = nonce;
    this._nonceToPeer.set(nonce, peerId);

    entry.timeoutTimer = this._setTimeout(
      () => this._handlePingTimeout(peerId, nonce),
      this._pingTimeoutMs,
    );
    // See _schedulePing for rationale on unref-when-available.
    if (entry.timeoutTimer && typeof entry.timeoutTimer.unref === 'function') entry.timeoutTimer.unref();
  }

  /**
   * Timeout-timer callback: the pong did not arrive within PING_TIMEOUT_MS.
   * Dispatch `ping-missed` (reducer escalates UNKNOWN/HEALTHY → STALE →
   * FAILED) and schedule the next cadence cycle from now.
   *
   * Guarded by nonce match: if a pong landed in the same tick and cleared
   * `pendingNonce`, the timeout is a stale callback and we skip it.
   *
   * @param {string} peerId
   * @param {string} nonce  The nonce the timeout was scheduled for.
   */
  _handlePingTimeout(peerId, nonce) {
    if (this._shutdown) return;
    const entry = this._peerCadence.get(peerId);
    if (!entry) return;
    if (entry.pendingNonce !== nonce) return; // stale (pong already cleared)
    entry.pendingNonce = null;
    entry.timeoutTimer = null;
    this._nonceToPeer.delete(nonce);

    this._dispatchPeer(peerId, { type: 'ping-missed' });

    // Reschedule the next cycle from now — the spec budgets two consecutive
    // misses (240s) before FAILED, so the second cycle starts immediately.
    entry.lastActivityAt = this._now();
    this._schedulePing(peerId);
  }

  /**
   * Tear-down hook. Clears every per-peer ping/timeout timer and forgets all
   * nonce mappings. Also cancels any in-flight recovery ladder so its
   * pending budget timers / observable subscriptions are released, and the
   * Rung-4 backoff retry timer if armed. After shutdown, further notify
   * calls are still safe but no new cadence cycles or ladder kicks will
   * run.
   *
   * Per follow-up H: in-flight `ensureSendable` calls that are awaiting a
   * ladder result resolve to `{ok:false, reason:'PEER_UNREACHABLE'}` after
   * shutdown — `_awaitLadderResolved` reads `this._currentLadder` after the
   * shutdown clears it, returns `{ok:false}`, and the caller surfaces
   * PEER_UNREACHABLE. The pre-flight probe timer is unref'd so it does not
   * keep the process alive past shutdown.
   */
  shutdown() {
    this._shutdown = true;
    for (const peerId of Array.from(this._peerCadence.keys())) {
      this._stopCadence(peerId);
    }
    this._nonceToPeer.clear();
    if (this._currentLadder) {
      this._currentLadder.cancel();
      this._currentLadder = null;
    }
    this._cancelBackoffTimer();
  }

  // ── Recovery ladder (Task 8) ────────────────────────────────────────────

  /**
   * Start the recovery ladder if none is currently running. Idempotent:
   * concurrent failures (multiple peers FAILED in the same tick, or
   * `selfState = RECONNECTING` while a peer-FAILED ladder is in flight)
   * are absorbed into the existing ladder rather than starting a second.
   *
   * Resets `_currentLadder = null` once the ladder resolves (success,
   * surrender, or cancellation), so the next failure starts at Rung 1
   * again — matching the spec's discipline rule "A rung that succeeds
   * resets the ladder to idle."
   *
   * @param {{ triggerPeerId: string|null, reason: string }} args
   * @private
   */
  _kickLadder({ triggerPeerId, reason }) {
    if (this._shutdown) return;
    if (this._currentLadder) return; // ladder owns the floor

    // Follow-up E: opportunistic tracker GC. The pre-flight probe (Task 9)
    // intentionally does NOT register its nonce in the cadence engine, which
    // means the tracker's `_pending` map can accumulate entries on a busy
    // sender. Sweeping at every ladder kick is cheap and bounded — ladder
    // kicks are the proven "something is wrong" signal that justifies the
    // sweep without having to add a dedicated periodic timer.
    if (this._pingTracker && typeof this._pingTracker.sweepExpired === 'function') {
      try { this._pingTracker.sweepExpired(this._now()); } catch { /* swallow */ }
    }

    const thrash = this._thrashGuardActive();
    const ladder = thrash ? this._buildSurrenderLadder() : this._buildLadder(triggerPeerId);
    // CRITICAL ordering: latch `_currentLadder` BEFORE dispatching
    // `recovery-began`. The selfState reducer's RECONNECTING transition
    // post-hook in `_dispatchSelf` re-enters `_kickLadder`; latching first
    // makes the re-entry hit the "ladder owns the floor" guard cleanly so
    // we never run two concurrent ladders.
    this._currentLadder = ladder;

    // Per follow-up A (Task 11 review): dispatch `recovery-began` so the
    // popup banner shows "Reconnecting…" immediately on a peer-FAILED kick,
    // not just on a self-RECONNECTING ws-closed.
    this._dispatchSelf({ type: 'recovery-began' });

    // eslint-disable-next-line no-console
    console.log(`[CA] ladder: kicked reason=${reason} triggerPeer=${triggerPeerId ?? 'none'}`
      + (thrash ? ' thrash=YES' : ''));
    ladder.run().then(
      (result) => {
        if (this._currentLadder === ladder) this._currentLadder = null;
        this._handleLadderSettled(ladder, result, triggerPeerId);
      },
      (err) => {
        // _runInternal() should never reject — we treat thrown actions as
        // failures internally — but be defensive.
        if (this._currentLadder === ladder) this._currentLadder = null;
        // eslint-disable-next-line no-console
        console.log(`[CA] ladder: unexpected rejection ${err && err.message}`);
        this._handleLadderSettled(ladder, { ok: false }, triggerPeerId);
      },
    );
  }

  /**
   * Common settlement handler shared by `_kickLadder` (auto-recovery path)
   * and `requestReconnect` (manual path). Lifts state on success, records
   * Rung-3 failures toward the thrash counter, and promotes to Rung 4
   * when the ladder gave up.
   *
   * @param {RecoveryLadder} ladder  The ladder whose result we are reacting to.
   * @param {{ok:boolean, rung?:string, exhausted?:boolean, cancelled?:boolean}} result
   * @param {string|null} triggerPeerId
   *   The peer that crossed into FAILED, or `null` for self-RECONNECTING /
   *   manual-reconnect kicks.
   * @private
   */
  _handleLadderSettled(ladder, result, triggerPeerId) {
    if (this._shutdown) return;
    if (result && result.cancelled) {
      // Cancelled by `requestReconnect` mid-ladder. The new ladder owns the
      // recovery state machine from here; do nothing — in particular do NOT
      // promote to Rung 4 on a cancelled run.
      return;
    }
    if (result && result.ok) {
      // Spec §"Discipline rules": "A rung that succeeds resets the ladder
      // to idle." Reset the thrash counter and the backoff attempt count.
      this._rung3FailureLog = [];
      this._backoffAttempt = 0;
      // Drop the surrender flag if it was up — we're back online.
      if (this._surrenderedToUser.value) this._surrenderedToUser.next(false);
      // Lift selfState (RECONNECTING → ONLINE) and the trigger peer
      // (FAILED → UNKNOWN). The reducers are no-ops if already there.
      this._dispatchSelf({ type: 'recovery-succeeded' });
      if (triggerPeerId) {
        this._dispatchPeer(triggerPeerId, { type: 'recovery-succeeded' });
      }
      return;
    }
    // Failure path. Determine whether Rung 3 actually got to run — if yes,
    // count it toward the thrash guard. The ladder sets `exhausted: true`
    // only after the for-loop ran every rung; for both the 3-rung and the
    // Rung-3-only requestReconnect ladder, that's equivalent to "Rung 3
    // ran and failed." A surrender ladder (thrash guard already promoted
    // us) is tagged so we don't double-count.
    const reachedRung3 = !!(result && result.exhausted);
    if (reachedRung3 && !ladder._isSurrenderLadder) {
      this._recordRung3Failure();
    }
    this._promoteToRung4();
  }

  /**
   * Build the three-rung ladder for the given trigger. The rung actions
   * close over `this` so they can subscribe to the live observables. They
   * use the same FakeClock-aware `_timerImpl` the cadence engine uses, so
   * tests can drive ladder budget timers via `clock.tick(...)`.
   *
   * @param {string|null} triggerPeerId
   *   The peer that crossed into FAILED, or `null` for self-RECONNECTING.
   * @returns {RecoveryLadder}
   * @private
   */
  _buildLadder(triggerPeerId) {
    return new RecoveryLadder({
      rungs: [
        {
          name: 'rung1',
          budgetMs: RUNG_1_BUDGET_MS,
          action: ({ signal }) => this._rung1Action(triggerPeerId, signal),
        },
        {
          name: 'rung2',
          budgetMs: RUNG_2_BUDGET_MS,
          action: ({ signal }) => this._rung2Action(signal),
        },
        {
          name: 'rung3',
          budgetMs: RUNG_3_BUDGET_MS,
          action: ({ signal }) => this._rung3Action(signal),
        },
      ],
      timerImpl: this._timerImpl,
    });
  }

  /**
   * Build a single-rung ladder that runs ONLY Rung 3. Used by
   * {@link requestReconnect} — manual tap always goes straight to a full
   * session reset (Rungs 1 + 2 are useful for "keep the existing transport,
   * just nudge it" scenarios; manual reconnect implies the user has decided
   * the lighter rungs aren't worth trying).
   *
   * @returns {RecoveryLadder}
   * @private
   */
  _buildRung3OnlyLadder() {
    return new RecoveryLadder({
      rungs: [
        {
          name: 'rung3',
          budgetMs: RUNG_3_BUDGET_MS,
          action: ({ signal }) => this._rung3Action(signal),
        },
      ],
      timerImpl: this._timerImpl,
    });
  }

  /**
   * Build a "ladder" that's really a one-rung surrender — used when the
   * thrash guard fires (≥ {@link RUNG_3_THRASH_THRESHOLD} Rung-3 failures
   * within {@link RUNG_3_THRASH_WINDOW_MS}). The single rung returns false
   * synchronously, which sends us straight through `_handleLadderSettled`'s
   * failure path → {@link _promoteToRung4}.
   *
   * The instance is tagged with `_isSurrenderLadder = true` so the settle
   * handler doesn't double-count it toward the thrash log (the failures
   * that triggered it are already counted).
   *
   * @returns {RecoveryLadder}
   * @private
   */
  _buildSurrenderLadder() {
    const ladder = new RecoveryLadder({
      rungs: [
        {
          name: 'thrash-surrender',
          budgetMs: 0,
          // eslint-disable-next-line no-unused-vars
          action: async ({ signal: _signal }) => false,
        },
      ],
      timerImpl: this._timerImpl,
    });
    ladder._isSurrenderLadder = true;
    return ladder;
  }

  /**
   * Rung 1: re-register rendezvous + wait for success indicator.
   *
   * Action: dispatch `register-rendezvous` over the existing `sendJson`
   * hook (relay may have GC'd our session). Success indicator: any path to
   * `peerHealth[triggerPeerId] === HEALTHY` (relay-peer-online → frame-
   * received → pong-received) within {@link RUNG_1_BUDGET_MS}.
   *
   * For self-RECONNECTING triggers (no specific peer) the criterion is
   * `selfState === ONLINE` AND any peer in `peerHealth` is HEALTHY — that
   * is, the same composite predicate Rung 2 uses. (Per Task 8 review
   * follow-up C: a Rung 1 fired by self-RECONNECTING really should require
   * self-online, not just "some peer eventually became HEALTHY" — the
   * latter could read as a success while we're still stuck CONNECTING.)
   *
   * @param {string|null} triggerPeerId
   * @param {AbortSignal} signal
   * @returns {Promise<boolean>}
   * @private
   */
  async _rung1Action(triggerPeerId, signal) {
    // If the ladder was cancelled before this rung even started, don't
    // bother dispatching the register frame — it would just hit a relay
    // we're about to tear down anyway. Symmetric with _rung2Action.
    if (signal.aborted) return false;

    // Best-effort dispatch. A throwing sendJson (e.g. WS already closed)
    // shouldn't crash the ladder — it just means Rung 1 cannot recover and
    // we'll time out and advance to Rung 2.
    try {
      if (typeof this._hooks.register === 'function') {
        await this._hooks.register();
      } else if (typeof this._hooks.sendJson === 'function' && this._hooks.ownDeviceId) {
        this._hooks.sendJson({
          type: 'register-rendezvous',
          rendezvousId: this._hooks.ownDeviceId,
        });
      }
    } catch {
      // Intentional swallow — see comment above.
    }

    if (triggerPeerId) {
      // Peer-specific trigger: success when the failed peer becomes HEALTHY.
      return awaitObservableOrTimeout(
        this._peerHealth,
        (map) => map.get(triggerPeerId) === PeerHealth.HEALTHY,
        RUNG_1_BUDGET_MS,
        signal,
        this._timerImpl,
      );
    }

    // Self-trigger: success requires selfState ONLINE AND any peer HEALTHY.
    // The two observables can't be ANDed atomically with the helper, so we
    // subscribe directly here (mirrors `_rung2Action`'s composite predicate).
    return new Promise((resolve) => {
      if (signal && signal.aborted) { resolve(false); return; }

      let settled = false;
      let unsubSelf = null;
      let unsubPeer = null;
      let timerId = null;
      let onAbort = null;

      const cleanup = () => {
        if (unsubSelf) { try { unsubSelf(); } catch { /* swallow */ } unsubSelf = null; }
        if (unsubPeer) { try { unsubPeer(); } catch { /* swallow */ } unsubPeer = null; }
        if (timerId != null) { try { this._clearTimeout(timerId); } catch { /* swallow */ } timerId = null; }
        if (signal && onAbort) { try { signal.removeEventListener('abort', onAbort); } catch { /* swallow */ } onAbort = null; }
      };
      const settle = (v) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(v);
      };

      let selfOnline = this._selfState.value === SelfState.ONLINE;
      let anyPeerHealthy = peerMapHasHealthy(this._peerHealth.value);
      const tryFire = () => { if (selfOnline && anyPeerHealthy) settle(true); };

      timerId = this._setTimeout(() => settle(false), RUNG_1_BUDGET_MS);
      if (timerId && typeof timerId.unref === 'function') timerId.unref();

      if (signal) {
        onAbort = () => settle(false);
        signal.addEventListener('abort', onAbort, { once: true });
      }

      unsubSelf = this._selfState.subscribe((s) => {
        selfOnline = s === SelfState.ONLINE;
        tryFire();
      });
      unsubPeer = this._peerHealth.subscribe((m) => {
        anyPeerHealthy = peerMapHasHealthy(m);
        tryFire();
      });
    });
  }

  /**
   * Rung 2: tear down the WS and reconnect via `hooks.forceWsReconnect`.
   *
   * Success indicator: `selfState === ONLINE` AND at least one paired peer
   * is HEALTHY, both within {@link RUNG_2_BUDGET_MS}. The two conditions
   * are tracked via separate observable subscriptions whose results we AND
   * together in a small composite check.
   *
   * If `forceWsReconnect` is missing from the hook bag (skeleton-mode test
   * harnesses), we surrender Rung 2 immediately: there's no transport to
   * tear down and the ladder advances to Rung 3.
   *
   * @param {AbortSignal} signal
   * @returns {Promise<boolean>}
   * @private
   */
  async _rung2Action(signal) {
    const force = this._hooks.forceWsReconnect;
    if (typeof force !== 'function') {
      // No transport-tear-down hook wired — skip the rung.
      return false;
    }
    try {
      await force();
    } catch {
      // forceWsReconnect failed synchronously / asynchronously — give the
      // budget a chance to observe success-by-other-path before surrendering.
    }

    // The composite predicate fires when BOTH selfState is ONLINE AND any
    // paired peer is HEALTHY. We can't AND two observables atomically with
    // the helper, so we subscribe directly here and short-circuit settle.
    return new Promise((resolve) => {
      if (signal && signal.aborted) { resolve(false); return; }

      let settled = false;
      let unsubSelf = null;
      let unsubPeer = null;
      let timerId = null;
      let onAbort = null;

      const cleanup = () => {
        if (unsubSelf)  { try { unsubSelf();  } catch { /* swallow */ } unsubSelf  = null; }
        if (unsubPeer)  { try { unsubPeer();  } catch { /* swallow */ } unsubPeer  = null; }
        if (timerId != null) { try { this._clearTimeout(timerId); } catch { /* swallow */ } timerId = null; }
        if (signal && onAbort) { try { signal.removeEventListener('abort', onAbort); } catch { /* swallow */ } onAbort = null; }
      };
      const settle = (v) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(v);
      };

      let selfOnline = this._selfState.value === SelfState.ONLINE;
      let anyPeerHealthy = peerMapHasHealthy(this._peerHealth.value);

      const tryFire = () => { if (selfOnline && anyPeerHealthy) settle(true); };

      timerId = this._setTimeout(() => settle(false), RUNG_2_BUDGET_MS);
      // Unref-when-available — see comment in awaitObservableOrTimeout. Keeps
      // the process from hanging when a ladder is kicked from a test that
      // doesn't await its full lifecycle.
      if (timerId && typeof timerId.unref === 'function') timerId.unref();

      if (signal) {
        onAbort = () => settle(false);
        signal.addEventListener('abort', onAbort, { once: true });
      }

      unsubSelf = this._selfState.subscribe((s) => {
        selfOnline = s === SelfState.ONLINE;
        tryFire();
      });
      unsubPeer = this._peerHealth.subscribe((m) => {
        anyPeerHealthy = peerMapHasHealthy(m);
        tryFire();
      });

      // The two subscribes above replay current values synchronously;
      // tryFire was invoked inside each. If both were already true, settle
      // already fired and cleanup torn everything down. Otherwise we wait.
    });
  }

  /**
   * Rung 3: full session reset. Calls `hooks.forceFullReset()` (which tears
   * down the WS, clears the v2 transport singleton, and re-enters the SW boot
   * path), then waits up to {@link RUNG_3_BUDGET_MS} for `selfState` to
   * return to `ONLINE`.
   *
   * Spec mapping (Chrome steps 1-5 from §"Rung 3 — Full session reset"):
   *   1. `stopPairingListener()` — handled inside `forceFullReset`.
   *   2. Null `pairingWs`, `_inflightConnect`, `_inflightDeviceId` — likewise.
   *   3. `_resetTransportSingleton()` — likewise.
   *   4. `autoStartRelayIfPaired()` — invoked via the `restartFn` arg the
   *      wiring layer supplies to `forceFullReset`.
   *   5. Wait up to 30s for `selfState=ONLINE` — implemented here.
   *
   * If `forceFullReset` is missing from the hook bag (skeleton-mode tests),
   * the rung surrenders synchronously: there's nothing to reset and the
   * ladder advances to Rung 4.
   *
   * @param {AbortSignal} signal
   * @returns {Promise<boolean>}
   * @private
   */
  async _rung3Action(signal) {
    if (signal && signal.aborted) return false;
    const reset = this._hooks.forceFullReset;
    if (typeof reset !== 'function') {
      // No full-reset hook wired — skeleton mode.
      return false;
    }
    try {
      await reset();
    } catch {
      // Reset hook threw — let the budget-timer race observe success-by-other-
      // path before surrendering. (Production's `forceFullReset` swallows
      // restart errors internally; this is belt-and-braces.)
    }
    if (signal && signal.aborted) return false;

    return awaitObservableOrTimeout(
      this._selfState,
      (s) => s === SelfState.ONLINE,
      RUNG_3_BUDGET_MS,
      signal,
      this._timerImpl,
    );
  }

  // ── Rung 3 thrash guard + Rung 4 backoff ─────────────────────────────────

  /**
   * Returns `true` iff the thrash guard should pre-empt the next ladder
   * kick by going straight to surrender. Prunes entries older than
   * {@link RUNG_3_THRASH_WINDOW_MS} as a side effect.
   *
   * @returns {boolean}
   * @private
   */
  _thrashGuardActive() {
    const now = this._now();
    const cutoff = now - RUNG_3_THRASH_WINDOW_MS;
    if (this._rung3FailureLog.length > 0) {
      this._rung3FailureLog = this._rung3FailureLog.filter((t) => t >= cutoff);
    }
    return this._rung3FailureLog.length >= RUNG_3_THRASH_THRESHOLD;
  }

  /**
   * Append the current timestamp to the Rung-3 failure log. Called by
   * {@link _handleLadderSettled} when a ladder reached Rung 3 and Rung 3 did
   * not lift selfState to ONLINE within budget.
   *
   * @private
   */
  _recordRung3Failure() {
    this._rung3FailureLog.push(this._now());
    // eslint-disable-next-line no-console
    console.log(`[CA] ladder: rung3 failure recorded (count=${this._rung3FailureLog.length})`);
  }

  /**
   * Rung 4: surrender to the user and schedule the next auto-retry.
   *
   * Per spec §"Rung 4 — Surface to user":
   *   - `selfState` stays in RECONNECTING (the reducer's `recovery-given-up`
   *     handler is a no-op outside RECONNECTING — so we make sure we're at
   *     least in RECONNECTING first via `recovery-began`).
   *   - The `surrenderedToUser` flag flips to `true` so the popup banner
   *     switches to the red "Connection failed — tap to reconnect" UI.
   *   - `recovery-given-up` is dispatched into both reducers so any FAILED
   *     peer state observers can react if they want to (the peerHealth
   *     reducer's handler is informational; the selfState handler is
   *     informational too).
   *   - An exponential-backoff timer is armed for the next auto-attempt.
   *
   * @private
   */
  _promoteToRung4() {
    if (this._shutdown) return;
    // Make sure we're at least in RECONNECTING so the popup banner stays up.
    // (We could also be in OFFLINE, e.g. if a stop event raced — in which
    // case the user is no longer paired and the surrender flag is moot.)
    this._dispatchSelf({ type: 'recovery-began' });
    this._dispatchSelf({ type: 'recovery-given-up' });
    if (!this._surrenderedToUser.value) {
      this._surrenderedToUser.next(true);
    }
    // eslint-disable-next-line no-console
    console.log('[CA] ladder: surrendered to user (Rung 4)');
    this._scheduleBackoffRetry();
  }

  /**
   * Arm the next auto-retry timer per {@link BACKOFF_SCHEDULE_MS}. The
   * `_backoffAttempt` index advances after each scheduling so the next
   * retry uses a longer delay (capped at the last entry in the schedule).
   *
   * If a backoff timer is already armed, this is a no-op (idempotent —
   * a second `_promoteToRung4` while we're waiting must not stack timers).
   *
   * @private
   */
  _scheduleBackoffRetry() {
    if (this._shutdown) return;
    if (this._backoffTimer != null) return; // already armed
    const idx = Math.min(this._backoffAttempt, BACKOFF_SCHEDULE_MS.length - 1);
    const delay = BACKOFF_SCHEDULE_MS[idx];
    this._backoffAttempt += 1;
    // eslint-disable-next-line no-console
    console.log(`[CA] ladder: backoff retry scheduled in ${delay}ms (attempt #${idx + 1})`);
    this._backoffTimer = this._setTimeout(() => {
      this._backoffTimer = null;
      this._fireBackoffRetry();
    }, delay);
    // Unref so a test that doesn't tick the FakeClock isn't held open by
    // the real-clock fallback. FakeClock returns a number — typeof guard.
    if (this._backoffTimer && typeof this._backoffTimer.unref === 'function') {
      this._backoffTimer.unref();
    }
  }

  /**
   * Cancel any pending Rung-4 auto-retry timer. Called by
   * {@link requestReconnect} (manual tap bypasses backoff) and
   * {@link shutdown}.
   *
   * @private
   */
  _cancelBackoffTimer() {
    if (this._backoffTimer != null) {
      try { this._clearTimeout(this._backoffTimer); } catch { /* swallow */ }
      this._backoffTimer = null;
    }
  }

  /**
   * Backoff-timer callback: the auto-retry interval has elapsed. We reset
   * the surrender flag (we're trying again) and kick a fresh full ladder.
   * Note we kick a FULL ladder (Rungs 1 + 2 + 3), not just Rung 3 — the
   * thrash counter is still in scope and will short-circuit to Rung 4 again
   * if Rungs 1+2 don't quietly recover us.
   *
   * @private
   */
  _fireBackoffRetry() {
    if (this._shutdown) return;
    if (this._currentLadder) return; // a manual reconnect raced us
    // Drop the surrender flag — we're actively trying again. The popup
    // banner switches back to the yellow "Reconnecting…" UI.
    if (this._surrenderedToUser.value) this._surrenderedToUser.next(false);
    this._kickLadder({ triggerPeerId: null, reason: 'backoff-retry' });
  }
}

/**
 * Predicate helper for Rung 2's "any peer HEALTHY" criterion. Pulled out so
 * it can be unit-tested via the ladder integration tests without monkey-
 * patching the class.
 *
 * @param {Map<string, string>} map
 * @returns {boolean}
 */
function peerMapHasHealthy(map) {
  for (const v of map.values()) if (v === PeerHealth.HEALTHY) return true;
  return false;
}
