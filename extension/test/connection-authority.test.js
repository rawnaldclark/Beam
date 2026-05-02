/**
 * @file connection-authority.test.js
 * @description Unit coverage for the ConnectionAuthority (Tasks 5 + 7).
 *
 * Run:  node --test test/connection-authority.test.js
 *
 * Verifies:
 *   - Constructor guards (missing signalingHooks throws TypeError).
 *   - Notify methods drive the selfState reducer end-to-end:
 *       OFFLINE -> CONNECTING -> ONLINE -> RECONNECTING.
 *   - Notify methods drive the peerHealth reducer per-peer:
 *       new peer -> UNKNOWN, frame-received -> HEALTHY,
 *       relay-peer-offline -> OFFLINE, send-completed -> HEALTHY.
 *   - Stub ensureSendable returns {ok: true}.
 *   - Observable subscriptions replay current state and fire on change.
 *   - _dispatchPeer is silent (no spurious emission) when the reducer
 *     produces the same state for an already-known peer.
 *   - Background ping cadence (Task 7):
 *     - Ping issued at lastActivity + 120s.
 *     - Pong within 10s -> HEALTHY, next ping rescheduled.
 *     - Two consecutive misses -> STALE -> FAILED.
 *     - OFFLINE peers are skipped.
 *     - Recent traffic resets the cadence.
 *     - Shutdown clears every timer.
 *
 * Cadence tests use a minimal in-file FakeClock (no library) so timer
 * semantics are deterministic and the test doesn't sleep on real wall time.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ConnectionAuthority } from '../connection/connection-authority.js';
import { SelfState } from '../connection/self-state.js';
import { PeerHealth } from '../connection/peer-health.js';
import { BG_PING_INTERVAL_MS, PING_TIMEOUT_MS } from '../connection/constants.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

/** Minimal hooks bag with no ownDeviceId — tracker is null in this mode. */
function makeHooks() {
  return { sendJson: () => {} };
}

/** Hooks bag including an ownDeviceId so the tracker is constructed. */
function makeHooksWithIdentity() {
  const sent = [];
  return {
    sent,
    hooks: { sendJson: (m) => sent.push(m), ownDeviceId: 'self-device-id' },
  };
}

// ─── constructor ─────────────────────────────────────────────────────────────

describe('ConnectionAuthority constructor', () => {
  it('throws TypeError when signalingHooks is missing', () => {
    assert.throws(
      () => new ConnectionAuthority({}),
      (err) => err instanceof TypeError && /signalingHooks/.test(err.message),
      'missing signalingHooks must throw TypeError mentioning signalingHooks',
    );
  });

  it('throws TypeError when signalingHooks is null', () => {
    assert.throws(
      () => new ConnectionAuthority({ signalingHooks: null }),
      (err) => err instanceof TypeError && /signalingHooks/.test(err.message),
    );
  });

  it('starts in OFFLINE selfState and an empty peerHealth map', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    assert.equal(auth.selfState.value, SelfState.OFFLINE);
    assert.ok(auth.peerHealth.value instanceof Map);
    assert.equal(auth.peerHealth.value.size, 0);
  });

  it('does not construct a PeerPingTracker without ownDeviceId (skeleton-mode hooks)', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    // notifyPongReceived should be a no-op (no tracker to forward to).
    assert.doesNotThrow(() => auth.notifyPongReceived('any-nonce'));
  });

  it('constructs a PeerPingTracker when ownDeviceId is supplied', () => {
    const { hooks } = makeHooksWithIdentity();
    const auth = new ConnectionAuthority({ signalingHooks: hooks });
    // The tracker is private; exercise it via notifyPongReceived (a no-op for
    // unknown nonces, but must not throw — proves the tracker exists).
    assert.doesNotThrow(() => auth.notifyPongReceived('unknown-nonce'));
  });
});

// ─── selfState transitions ───────────────────────────────────────────────────

describe('ConnectionAuthority: selfState transitions', () => {
  it('notifyWsOpening flips OFFLINE -> CONNECTING', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyWsOpening();
    assert.equal(auth.selfState.value, SelfState.CONNECTING);
  });

  it('notifyAuthComplete after notifyWsOpening flips CONNECTING -> ONLINE', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyWsOpening();
    auth.notifyAuthComplete();
    assert.equal(auth.selfState.value, SelfState.ONLINE);
  });

  it('notifyWsClosed from ONLINE flips to RECONNECTING', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyWsOpening();
    auth.notifyAuthComplete();
    assert.equal(auth.selfState.value, SelfState.ONLINE);
    auth.notifyWsClosed();
    assert.equal(auth.selfState.value, SelfState.RECONNECTING);
  });

  it('notifyWsClosed from CONNECTING also flips to RECONNECTING (auth never completed)', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyWsOpening();
    auth.notifyWsClosed();
    assert.equal(auth.selfState.value, SelfState.RECONNECTING);
  });
});

// ─── peerHealth transitions ──────────────────────────────────────────────────

describe('ConnectionAuthority: peerHealth transitions', () => {
  it('notifyPeerOnline("X") seeds peer X in the map as UNKNOWN', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyPeerOnline('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.UNKNOWN);
  });

  it('notifyFrameReceived("X") promotes X to HEALTHY', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyPeerOnline('X');
    auth.notifyFrameReceived('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);
  });

  it('notifySendCompleted("X") promotes X to HEALTHY', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyPeerOnline('X');
    auth.notifySendCompleted('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);
  });

  it('notifyPeerOffline("X") flips X to OFFLINE', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyPeerOnline('X');
    auth.notifyFrameReceived('X');
    auth.notifyPeerOffline('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.OFFLINE);
  });

  it('multiple peers are tracked independently', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    auth.notifyPeerOnline('X');
    auth.notifyPeerOnline('Y');
    auth.notifyFrameReceived('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);
    assert.equal(auth.peerHealth.value.get('Y'), PeerHealth.UNKNOWN);
  });
});

// ─── ensureSendable stub ─────────────────────────────────────────────────────

describe('ConnectionAuthority: ensureSendable (stub)', () => {
  it('always returns {ok: true} in skeleton mode', async () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    const result = await auth.ensureSendable('any-peer-id');
    assert.deepEqual(result, { ok: true });
  });
});

// ─── requestReconnect stub ───────────────────────────────────────────────────

describe('ConnectionAuthority: requestReconnect (stub)', () => {
  it('resolves without throwing in skeleton mode', async () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    await assert.doesNotReject(() => auth.requestReconnect());
  });
});

// ─── Observable subscriptions ────────────────────────────────────────────────

describe('ConnectionAuthority: Observable subscriptions', () => {
  it('selfState.subscribe replays current value and fires on change', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    const calls = [];
    auth.selfState.subscribe((v) => calls.push(v));
    assert.deepEqual(calls, [SelfState.OFFLINE], 'initial replay must be OFFLINE');
    auth.notifyWsOpening();
    auth.notifyAuthComplete();
    assert.deepEqual(calls, [SelfState.OFFLINE, SelfState.CONNECTING, SelfState.ONLINE]);
  });

  it('peerHealth.subscribe replays the current map and fires on change', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    const calls = [];
    auth.peerHealth.subscribe((m) => calls.push(m));
    assert.equal(calls.length, 1, 'replay must happen once on subscribe');
    assert.equal(calls[0].size, 0, 'initial map is empty');

    auth.notifyPeerOnline('X');
    assert.equal(calls.length, 2, 'first peer-online must emit');
    assert.equal(calls[1].get('X'), PeerHealth.UNKNOWN);

    auth.notifyFrameReceived('X');
    assert.equal(calls.length, 3, 'frame-received must emit');
    assert.equal(calls[2].get('X'), PeerHealth.HEALTHY);
  });

  it('peerHealth emits a fresh Map on each change (subscribers can compare references)', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    const seen = [];
    auth.peerHealth.subscribe((m) => seen.push(m));
    auth.notifyPeerOnline('X');
    auth.notifyFrameReceived('X');
    // Three deliveries: replay, peer-online, frame-received. Each Map identity
    // must be distinct so a popup can use shallow reference comparison.
    assert.equal(seen.length, 3);
    assert.notEqual(seen[0], seen[1]);
    assert.notEqual(seen[1], seen[2]);
  });

  it('does not emit when _dispatchPeer reducer returns the same state for a known peer', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    // Seed peer X as HEALTHY.
    auth.notifyPeerOnline('X');
    auth.notifyFrameReceived('X');

    const calls = [];
    auth.peerHealth.subscribe((m) => calls.push(m));
    // Replay only — state is HEALTHY.
    assert.equal(calls.length, 1);

    // frame-received again on a HEALTHY peer is a reducer no-op.
    auth.notifyFrameReceived('X');
    assert.equal(calls.length, 1, 'no spurious emission on reducer no-op');

    // send-completed on a HEALTHY peer is also a reducer no-op.
    auth.notifySendCompleted('X');
    assert.equal(calls.length, 1, 'still no spurious emission');

    // But a real change (peer goes offline) should emit.
    auth.notifyPeerOffline('X');
    assert.equal(calls.length, 2);
    assert.equal(calls[1].get('X'), PeerHealth.OFFLINE);
  });

  it('does not emit on selfState reducer no-ops', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    const calls = [];
    auth.selfState.subscribe((v) => calls.push(v));
    // OFFLINE + ws-closed is a reducer no-op (no socket existed).
    auth.notifyWsClosed();
    assert.deepEqual(calls, [SelfState.OFFLINE], 'no spurious emission on reducer no-op');
  });
});

// ─── notifyPongReceived forwards to tracker ──────────────────────────────────

describe('ConnectionAuthority: notifyPongReceived', () => {
  it('is a silent no-op when no tracker exists (no ownDeviceId)', () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    assert.doesNotThrow(() => auth.notifyPongReceived('any'));
  });

  it('forwards the nonce to the tracker so a sendPing promise resolves', async () => {
    const { hooks } = makeHooksWithIdentity();
    const auth = new ConnectionAuthority({ signalingHooks: hooks });
    // Reach into the private tracker to issue a ping (Task 7 will do this
    // through cadence; for skeleton coverage we just need to prove the
    // forwarding path works).
    const tracker = auth._pingTracker;
    assert.ok(tracker, 'tracker must exist when ownDeviceId is supplied');
    const { nonce, promise } = tracker.sendPing('peer-X');
    auth.notifyPongReceived(nonce);
    const result = await promise;
    assert.equal(result.ok, true);
  });

  it('does NOT promote peer health when nonce came from outside the cadence engine', () => {
    // Task 7: notifyPongReceived only dispatches `pong-received` for nonces
    // the cadence engine itself recorded. A direct tracker.sendPing (used
    // by Task 9 ensureSendable pre-flight, not by the cadence loop) is not
    // tracked by the authority — peer health stays UNKNOWN, the next frame
    // / send-completed promotes it.
    const { hooks } = makeHooksWithIdentity();
    const auth = new ConnectionAuthority({ signalingHooks: hooks });
    auth.notifyPeerOnline('peer-X'); // X is now UNKNOWN.
    const { nonce } = auth._pingTracker.sendPing('peer-X');
    auth.notifyPongReceived(nonce);
    assert.equal(
      auth.peerHealth.value.get('peer-X'),
      PeerHealth.UNKNOWN,
      'pong for an off-cadence nonce must not promote peer health',
    );
  });
});

// ─── Task 7: background ping cadence ─────────────────────────────────────────

/**
 * Minimal manual-tick fake clock for cadence tests.
 *
 * `tick(ms)` advances the virtual clock and fires every timer whose deadline
 * has been crossed, in deadline order. Inserting a new timer during a fired
 * callback is supported (the new timer is included in subsequent ticks).
 *
 * We do NOT implement setInterval / clearInterval — the authority only uses
 * setTimeout for cadence (see _schedulePing / _fireCadenceTick).
 */
class FakeClock {
  constructor(startMs = 0) {
    this._now = startMs;
    this._nextId = 1;
    /** @type {Map<number, {dueAt:number, fn:() => void}>} */
    this._timers = new Map();
  }
  now() { return this._now; }
  setTimeout(fn, delay) {
    const id = this._nextId++;
    this._timers.set(id, { dueAt: this._now + Math.max(0, delay), fn });
    return id;
  }
  clearTimeout(id) {
    if (id == null) return;
    this._timers.delete(id);
  }
  /** Advance the clock by `ms`, firing every timer whose deadline is now reached. */
  tick(ms) {
    const target = this._now + ms;
    // Loop fires timers in due-at order. New timers scheduled inside a
    // callback are picked up because we re-scan on each iteration.
    while (true) {
      let nextId = null;
      let nextDue = Infinity;
      for (const [id, t] of this._timers) {
        if (t.dueAt <= target && t.dueAt < nextDue) {
          nextDue = t.dueAt;
          nextId = id;
        }
      }
      if (nextId == null) break;
      const t = this._timers.get(nextId);
      this._timers.delete(nextId);
      this._now = t.dueAt;
      t.fn();
    }
    this._now = target;
  }
  /** Number of currently-armed timers — for shutdown assertions. */
  get pending() { return this._timers.size; }
}

/**
 * Build an authority with a FakeClock-backed timer surface. Returns the
 * authority, the clock, and the captured-sent-message array so tests can
 * inspect outbound peer-pings.
 */
function makeCadenceAuthority({ clockStart = 1_000_000 } = {}) {
  const clock = new FakeClock(clockStart);
  const sent = [];
  const hooks = {
    sendJson: (m) => sent.push(m),
    ownDeviceId: 'self-device-id',
  };
  const auth = new ConnectionAuthority({
    signalingHooks: hooks,
    options: { timerImpl: clock },
  });
  return { auth, clock, sent };
}

describe('ConnectionAuthority: background ping cadence', () => {
  it('schedules a ping at lastActivity + 120s when a peer comes online', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');

    // Just before 120s: no ping yet.
    clock.tick(BG_PING_INTERVAL_MS - 1);
    assert.equal(sent.length, 0, 'no ping before 120s');

    // At 120s: peer-ping is sent for X.
    clock.tick(1);
    assert.equal(sent.length, 1, 'ping fires at 120s');
    assert.equal(sent[0].type, 'peer-ping');
    assert.equal(sent[0].targetDeviceId, 'X');
    assert.equal(sent[0].rendezvousId, 'self-device-id');
    assert.equal(typeof sent[0].nonce, 'string');
  });

  it('promotes the peer to HEALTHY when the pong arrives within 10s', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    clock.tick(BG_PING_INTERVAL_MS); // ping fires
    assert.equal(sent.length, 1);
    const nonce = sent[0].nonce;

    // Pong arrives 5s later (well inside the 10s timeout).
    clock.tick(5_000);
    auth.notifyPongReceived(nonce);
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);

    // Next ping is scheduled for now + 120s. Tick to just before, then to it.
    clock.tick(BG_PING_INTERVAL_MS - 1);
    assert.equal(sent.length, 1, 'no second ping until 120s after pong');
    clock.tick(1);
    assert.equal(sent.length, 2, 'second ping fires 120s after pong');
    assert.equal(sent[1].targetDeviceId, 'X');
  });

  it('escalates UNKNOWN -> STALE -> FAILED on two consecutive missed pings', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.UNKNOWN);

    // First ping at t=120s, no pong, timeout at t=130s -> STALE.
    clock.tick(BG_PING_INTERVAL_MS);
    assert.equal(sent.length, 1, 'first ping fires');
    clock.tick(PING_TIMEOUT_MS);
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.STALE);

    // Second cycle: next ping at t=250s, timeout at t=260s -> FAILED.
    clock.tick(BG_PING_INTERVAL_MS);
    assert.equal(sent.length, 2, 'second ping fires');
    clock.tick(PING_TIMEOUT_MS);
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.FAILED);
  });

  it('does not send pings to OFFLINE peers', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    auth.notifyPeerOffline('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.OFFLINE);

    // Advance well past the cadence interval. Stopping cadence on offline
    // means no pending timer at all — but even if a tick fires, OFFLINE
    // peers are skipped.
    clock.tick(BG_PING_INTERVAL_MS * 3);
    assert.equal(sent.length, 0, 'no ping issued to OFFLINE peer');
  });

  it('resets the cadence when a frame is received within the recent-traffic window', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');

    // At t=100s a real frame arrives — reschedule for 100 + 120 = 220s.
    clock.tick(100_000);
    auth.notifyFrameReceived('X');

    // At t=120s (the original schedule) no ping should fire.
    clock.tick(20_000);
    assert.equal(sent.length, 0, 'frame at t=100 must push ping past t=120');

    // At t=220s the rescheduled ping fires.
    clock.tick(99_999);
    assert.equal(sent.length, 0, 'no ping just before t=220');
    clock.tick(1);
    assert.equal(sent.length, 1, 'ping fires at t=220 (reset by frame)');
  });

  it('treats notifySendCompleted the same as notifyFrameReceived for cadence reset', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');

    clock.tick(60_000);
    auth.notifySendCompleted('X');

    // Original schedule was t=120s; new schedule is t=60+120 = 180s.
    clock.tick(60_000); // now t=120s
    assert.equal(sent.length, 0, 'send-completed at t=60 must reschedule past t=120');

    clock.tick(60_000); // now t=180s
    assert.equal(sent.length, 1, 'ping fires at t=180 (60s + 120s)');
  });

  it('does not interrupt an in-flight ping when activity arrives mid-window', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');

    clock.tick(BG_PING_INTERVAL_MS); // first ping
    assert.equal(sent.length, 1);
    const nonce = sent[0].nonce;

    // 5s into the timeout, a frame arrives. We must NOT cancel the timeout
    // (would leak a tracker entry); the in-flight ping settles via pong or
    // timeout. The frame still promotes the peer through the reducer.
    clock.tick(5_000);
    auth.notifyFrameReceived('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);

    // Pong within deadline still works.
    clock.tick(4_000);
    auth.notifyPongReceived(nonce);
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);
  });

  it('clears all timers on shutdown', () => {
    const { auth, clock } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    auth.notifyPeerOnline('Y');
    // Each peer has one armed pingTimer.
    assert.equal(clock.pending, 2, 'two ping timers armed');

    auth.shutdown();
    assert.equal(clock.pending, 0, 'shutdown clears every timer');

    // Post-shutdown ticks must not throw or schedule new work.
    clock.tick(BG_PING_INTERVAL_MS * 5);
    assert.equal(clock.pending, 0, 'no timers re-armed after shutdown');
  });

  it('clears in-flight ping + timeout timers on shutdown', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    clock.tick(BG_PING_INTERVAL_MS); // ping fires; timeout is armed
    assert.equal(sent.length, 1);
    assert.equal(clock.pending, 1, 'timeout timer armed (no ping timer until next cycle)');

    auth.shutdown();
    assert.equal(clock.pending, 0, 'shutdown clears the in-flight timeout');
  });

  it('OFFLINE -> UNKNOWN via relay-peer-online restarts cadence', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    auth.notifyPeerOffline('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.OFFLINE);

    auth.notifyPeerOnline('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.UNKNOWN);

    clock.tick(BG_PING_INTERVAL_MS);
    assert.equal(sent.length, 1, 'cadence resumes after relay-peer-online resurrects peer');
    assert.equal(sent[0].targetDeviceId, 'X');
  });

  it('an unknown / stale nonce in notifyPongReceived is a silent no-op', () => {
    const { auth } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    // No ping in flight yet — pong with a fabricated nonce is ignored.
    assert.doesNotThrow(() => auth.notifyPongReceived('fabricated-nonce'));
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.UNKNOWN);
  });

  it('multiple peers run independent cadence loops', () => {
    const { auth, clock, sent } = makeCadenceAuthority();
    auth.notifyPeerOnline('X');
    clock.tick(30_000);          // t=30
    auth.notifyPeerOnline('Y');  // Y's lastActivityAt = 30, due at 150

    clock.tick(90_000);          // t=120 — X due now
    assert.equal(sent.length, 1, 'X fires at t=120');
    assert.equal(sent[0].targetDeviceId, 'X');

    clock.tick(30_000);          // t=150 — Y due now
    assert.equal(sent.length, 2, 'Y fires at t=150 (30 + 120)');
    assert.equal(sent[1].targetDeviceId, 'Y');
  });

  it('does not fire cadence when the authority has no PeerPingTracker (no ownDeviceId)', () => {
    const sent = [];
    const clock = new FakeClock();
    const auth = new ConnectionAuthority({
      signalingHooks: { sendJson: (m) => sent.push(m) },
      options: { timerImpl: clock },
    });
    auth.notifyPeerOnline('X');
    clock.tick(BG_PING_INTERVAL_MS * 3);
    assert.equal(sent.length, 0, 'no tracker => no pings, even with peers online');
    assert.equal(clock.pending, 0, 'no cadence timers armed without a tracker');
  });
});
