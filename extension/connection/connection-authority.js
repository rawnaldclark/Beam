/**
 * @file connection-authority.js
 * @description Single source of truth for relay-connection and peer-health state.
 *
 * Composes the pure pieces (Observable + reducers + PeerPingTracker) into
 * the object the rest of the extension talks to. The wiring layer (Task 6)
 * calls the `notifyXxx` methods; the send-path (Task 9) calls `ensureSendable`;
 * the popup (Task 10) subscribes to `selfState` and `peerHealth`.
 *
 * This file is the **skeleton**. It implements the minimum required by
 * Task 5 of the plan:
 *   - Observable selfState + peerHealth.
 *   - Notify methods that dispatch into the pure reducers.
 *   - A stub `ensureSendable` that returns {ok: true}.
 *   - A stub `requestReconnect` that does nothing yet.
 *
 * Subsequent tasks layer on:
 *   - Task 7: ping cadence + miss-handling using the PeerPingTracker.
 *   - Task 9: real ensureSendable pre-flight (channel-open, presence, peer-ping probe).
 *   - Task 11: recovery ladder rungs 3+4 + manual reconnect.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

import { Observable } from './observable.js';
import { PeerPingTracker } from './peer-ping.js';
import { PeerHealth, reducePeerHealth } from './peer-health.js';
import { SelfState, reduceSelfState } from './self-state.js';

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
   * @param {number} [args.options.pingTimeoutMs=10000]
   *   Per-ping deadline in milliseconds, forwarded to PeerPingTracker.
   * @throws {TypeError} If `signalingHooks` is missing.
   */
  constructor({ signalingHooks, options = {} }) {
    if (!signalingHooks) throw new TypeError('ConnectionAuthority: signalingHooks required');

    this._hooks = signalingHooks;
    this._selfState = new Observable(SelfState.OFFLINE);
    /** @type {Observable<Map<string, string>>} */
    this._peerHealth = new Observable(new Map());

    // Hooks must provide ownDeviceId before sendPing can fire. The tracker is
    // constructed lazily-by-presence: if the hook bag lacks an identity (e.g.
    // first-boot before pairing), we leave it null and Task 7 will swap one
    // in. Skeleton just records pongs into the tracker if it exists.
    this._pingTracker = signalingHooks.ownDeviceId
      ? new PeerPingTracker({
          sendJson: signalingHooks.sendJson,
          ownDeviceId: signalingHooks.ownDeviceId,
          timeoutMs: options.pingTimeoutMs ?? 10_000,
        })
      : null;
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
  notifyPeerOnline(peerId)   { this._dispatchPeer(peerId, { type: 'relay-peer-online' }); }
  /** Relay reports a peer's WS is closed. */
  notifyPeerOffline(peerId)  { this._dispatchPeer(peerId, { type: 'relay-peer-offline' }); }
  /** A real v2 frame was decoded from `peerId` — strong proof of life. */
  notifyFrameReceived(peerId) { this._dispatchPeer(peerId, { type: 'frame-received' }); }
  /** A frame send to `peerId` succeeded end-to-end — strong proof of life. */
  notifySendCompleted(peerId) { this._dispatchPeer(peerId, { type: 'send-completed' }); }

  /**
   * A peer-pong arrived. Forwards the nonce to the ping tracker so the
   * matching `sendPing` promise resolves. Note: this does NOT directly
   * promote peer health — the spec lists three strong proof-of-life signals
   * (pong, frame, send-completed) all of which promote, but the tracker
   * resolves by nonce while the *authority* needs the peerId. Task 7 will
   * either dispatch a `pong-received` event from the tracker callback or
   * map nonce -> peerId here. For the skeleton: trust the next frame /
   * send-completed to promote the peer.
   *
   * @param {string} nonce
   */
  notifyPongReceived(nonce) { this._pingTracker?.recordPong(nonce); }

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

  /**
   * Tear-down hook. Skeleton has no timers to clear; Task 7+ adds the ping
   * cadence interval which must be cleared here.
   */
  shutdown() { /* clear timers in Task 7+ */ }
}
