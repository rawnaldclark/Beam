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
 * Subsequent tasks layer on:
 *   - Task 11: Rung 3 (full session reset), Rung 4 backoff + surrender.
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
} from './constants.js';

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
   * `recordPong` / `sweepExpired`, and a subsequent stray
   * `notifyPongReceived` no-ops because the cadence-side `_nonceToPeer`
   * never recorded this nonce. (We deliberately do NOT register the
   * pre-flight nonce in `_nonceToPeer` — pre-flight liveness should not
   * accidentally promote peerHealth via the cadence pong path, which is
   * what the Task 7 test "does NOT promote peer health when nonce came
   * from outside the cadence engine" already guarantees.)
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
        () => settle({ ok: true }),
        // The tracker rejects with `{ok:false, reason:'timeout'}` when its
        // own (10s) sweep finds the entry expired. We may resolve via our
        // 5s timer first; if not, this rejection short-circuits us.
        () => settle({ ok: false, reason: 'timeout' }),
      );
    });
  }

  /**
   * Returns a promise that resolves when {@link _currentLadder} settles, or
   * resolves immediately if no ladder is running. Used by `ensureSendable` to
   * await a ladder kicked by a `pre-flight-failed` dispatch.
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
   * Manual reconnect entry point (popup "Reconnect now" button). Stub for
   * Task 5 — Task 11 implements the recovery-ladder kickoff.
   */
  async requestReconnect() { /* stub — Task 11 */ }

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

    const { nonce } = this._pingTracker.sendPing(peerId, this._now());
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
   * pending budget timers / observable subscriptions are released. After
   * shutdown, further notify calls are still safe but no new cadence cycles
   * or ladder kicks will run.
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
    const ladder = this._buildLadder(triggerPeerId);
    this._currentLadder = ladder;
    // eslint-disable-next-line no-console
    console.log(`[CA] ladder: kicked reason=${reason} triggerPeer=${triggerPeerId ?? 'none'}`);
    ladder.run().then(
      (result) => {
        // Only release the slot if this ladder is still the current one.
        // (`requestReconnect` mid-ladder will swap in a new ladder in
        // Task 11; here we just unlatch our reference.)
        if (this._currentLadder === ladder) this._currentLadder = null;
        if (result.ok) {
          // The reducer is the source of truth for the resulting state — we
          // dispatch `recovery-succeeded` to drop FAILED peers back to
          // UNKNOWN and lift selfState from RECONNECTING (where applicable).
          this._dispatchSelf({ type: 'recovery-succeeded' });
          if (triggerPeerId) {
            this._dispatchPeer(triggerPeerId, { type: 'recovery-succeeded' });
          }
        }
        // ok=false: leave reducer state alone. Rung 4 (Task 11) will surface
        // surrender to the user.
      },
      (err) => {
        // _runInternal() should never reject — we treat thrown actions as
        // failures internally — but be defensive.
        if (this._currentLadder === ladder) this._currentLadder = null;
        // eslint-disable-next-line no-console
        console.log(`[CA] ladder: unexpected rejection ${err && err.message}`);
      },
    );
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
          // eslint-disable-next-line no-unused-vars
          action: async ({ signal: _signal }) => {
            // Stub — Task 11 implements full session reset.
            throw new Error('TODO Rung 3');
          },
        },
      ],
      timerImpl: this._timerImpl,
    });
  }

  /**
   * Rung 1: re-register rendezvous + wait for success indicator.
   *
   * Action: dispatch `register-rendezvous` over the existing `sendJson`
   * hook (relay may have GC'd our session). Success indicator: any path to
   * `peerHealth[triggerPeerId] === HEALTHY` (relay-peer-online → frame-
   * received → pong-received) within {@link RUNG_1_BUDGET_MS}. For self-
   * RECONNECTING triggers (no specific peer) the criterion degrades to
   * "any peer in `peerHealth` is HEALTHY" — equivalent to Rung 2's
   * second clause without the `selfState === ONLINE` precondition.
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

    const predicate = triggerPeerId
      ? (map) => map.get(triggerPeerId) === PeerHealth.HEALTHY
      : (map) => {
        for (const v of map.values()) if (v === PeerHealth.HEALTHY) return true;
        return false;
      };

    return awaitObservableOrTimeout(
      this._peerHealth,
      predicate,
      RUNG_1_BUDGET_MS,
      signal,
      this._timerImpl,
    );
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
