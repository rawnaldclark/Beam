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
 * Subsequent tasks layer on:
 *   - Task 8/11: recovery ladder rungs.
 *   - Task 9: real ensureSendable pre-flight (channel-open, presence, peer-ping probe).
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

import { Observable } from './observable.js';
import { PeerPingTracker } from './peer-ping.js';
import { PeerHealth, reducePeerHealth } from './peer-health.js';
import { SelfState, reduceSelfState } from './self-state.js';
import { BG_PING_INTERVAL_MS, PING_TIMEOUT_MS } from './constants.js';

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
   *   for outbound WS messages once a tracker is needed. `ownDeviceId` is
   *   needed before any peer-ping can fire (Task 7); skeleton does not require it.
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
   *   `Date.now` for `now`.
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
  }
  /** A frame send to `peerId` succeeded end-to-end — strong proof of life. */
  notifySendCompleted(peerId) {
    this._dispatchPeer(peerId, { type: 'send-completed' });
    this._noteActivity(peerId);
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
   * Pre-flight check before sending to `peerId`. Returns whether the send
   * path is currently usable. Skeleton always returns ok; Task 9 swaps in
   * real channel-open / presence / peer-ping checks.
   *
   * @param {string} _peerId
   * @returns {Promise<{ok: true} | {ok: false, reason: string}>}
   */
  // eslint-disable-next-line no-unused-vars
  async ensureSendable(_peerId) { return { ok: true }; }

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
   */
  _dispatchSelf(event) {
    const next = reduceSelfState(this._selfState.value, event);
    if (next !== this._selfState.value) this._selfState.next(next);
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
   * nonce mappings. After shutdown, further notify calls are still safe but
   * no new cadence cycles will be scheduled.
   */
  shutdown() {
    this._shutdown = true;
    for (const peerId of Array.from(this._peerCadence.keys())) {
      this._stopCadence(peerId);
    }
    this._nonceToPeer.clear();
  }
}
