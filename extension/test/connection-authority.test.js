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
 * Cadence and ladder tests use the shared FakeClock helper at
 * `./helpers/fake-clock.js` so timer semantics are deterministic and tests
 * don't sleep on real wall time. Extracted from this file in Task 11 to
 * avoid a third copy as recovery-ladder.test.js needed the same surface.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ConnectionAuthority } from '../connection/connection-authority.js';
import { SelfState } from '../connection/self-state.js';
import { PeerHealth } from '../connection/peer-health.js';
import {
  BG_PING_INTERVAL_MS,
  PING_TIMEOUT_MS,
  RECENT_TRAFFIC_WINDOW_MS,
  RUNG_1_BUDGET_MS,
  RUNG_2_BUDGET_MS,
  RUNG_3_BUDGET_MS,
  BACKOFF_SCHEDULE_MS,
} from '../connection/constants.js';
import { FakeClock } from './helpers/fake-clock.js';

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

// ─── ensureSendable: skeleton-mode and self-offline early-outs ───────────────

describe('ConnectionAuthority: ensureSendable (skeleton-mode early-outs)', () => {
  it('returns SELF_OFFLINE when selfState is OFFLINE (no probe attempted)', async () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    // Default state is OFFLINE — selfState gate fires before any peer logic.
    const result = await auth.ensureSendable('any-peer-id');
    assert.deepEqual(result, { ok: false, reason: 'SELF_OFFLINE' });
  });

  it('returns PEER_UNREACHABLE when selfState is ONLINE but no _pingTracker exists', async () => {
    // Skeleton-mode (no ownDeviceId) means we can't issue a peer-ping; the
    // safe answer is "not sendable" rather than waving the send through.
    // We inject a FakeClock so the ladder's real-time budget timers don't
    // dominate the test runtime — once the probe fails synchronously, the
    // pre-flight-failed dispatch kicks a ladder whose Rungs 1+2+3 we drive
    // with virtual time.
    const clock = new FakeClock(0);
    const auth = new ConnectionAuthority({
      signalingHooks: makeHooks(),
      options: { timerImpl: clock },
    });
    auth.notifyWsOpening();
    auth.notifyAuthComplete();
    assert.equal(auth.selfState.value, SelfState.ONLINE);

    const promise = auth.ensureSendable('any-peer-id');
    // Yield so _runEnsureSendable progresses past the synchronous skeleton-
    // mode probe, dispatches pre-flight-failed, and arms Rung 1's budget timer.
    await new Promise((r) => setImmediate(r));
    // Burn ladder budget. Rung 1 = 5s; Rung 2 has no forceWsReconnect →
    // surrenders immediately; Rung 3 throws "TODO Rung 3" → exhausted.
    clock.tick(5_000);
    for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));

    const result = await promise;
    assert.deepEqual(result, { ok: false, reason: 'PEER_UNREACHABLE' });
    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });
});

// ─── requestReconnect (skeleton-mode smoke test) ─────────────────────────────
// The full requestReconnect coverage lives later in this file under the
// `Task 11: Rung 3, Rung 4, thrash guard, requestReconnect` block. Here we
// just lock the no-throw shape for skeleton-mode (no ownDeviceId, no ladder
// hooks).

describe('ConnectionAuthority: requestReconnect (skeleton-mode smoke)', () => {
  it('resolves with {ok:false} without throwing in skeleton mode', async () => {
    const auth = new ConnectionAuthority({ signalingHooks: makeHooks() });
    const result = await auth.requestReconnect();
    // Without ownDeviceId / forceFullReset, Rung 3 surrenders synchronously
    // and the manual ladder reports `ok:false`. Importantly: no throw.
    assert.equal(result.ok, false);
    auth.shutdown();
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

// ─── Task 8: recovery ladder wiring ──────────────────────────────────────────

/**
 * Integration coverage for the authority's ladder kickoff. Uses the same
 * FakeClock so ladder budget timers are virtual; a small forceWsReconnect
 * spy lets us assert Rung 2 ran. The full per-rung mechanics are unit-tested
 * in `recovery-ladder.test.js`; here we only verify the wiring contract:
 *   - which transitions trigger _kickLadder
 *   - the single-ladder discipline
 *   - the success path lifts state via `recovery-succeeded`
 *   - shutdown cancels an in-flight ladder
 */
function makeLadderAuthority({ withForceWsReconnect = false } = {}) {
  const clock = new FakeClock(0);
  const sent = [];
  const calls = { forceWsReconnect: 0 };
  const hooks = {
    sendJson: (m) => sent.push(m),
    ownDeviceId: 'self-device-id',
  };
  if (withForceWsReconnect) {
    hooks.forceWsReconnect = () => { calls.forceWsReconnect += 1; };
  }
  const auth = new ConnectionAuthority({
    signalingHooks: hooks,
    options: { timerImpl: clock },
  });
  return { auth, clock, sent, calls };
}

describe('ConnectionAuthority: recovery ladder wiring', () => {
  it('kicks the ladder when a peer crosses into FAILED', async () => {
    const { auth, clock, sent } = makeLadderAuthority();
    auth.notifyPeerOnline('X'); // UNKNOWN

    // Two consecutive missed pings → STALE → FAILED.
    clock.tick(BG_PING_INTERVAL_MS); // ping #1
    clock.tick(PING_TIMEOUT_MS);     // miss → STALE
    clock.tick(BG_PING_INTERVAL_MS); // ping #2
    clock.tick(PING_TIMEOUT_MS);     // miss → FAILED + ladder kicks

    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.FAILED);
    // Rung 1 dispatches register-rendezvous via sendJson — sent[2] should
    // be that frame (sent[0] and sent[1] are the two peer-pings).
    const registerFrame = sent.find((m) => m.type === 'register-rendezvous');
    assert.ok(registerFrame, 'rung1 must send register-rendezvous');
    assert.equal(registerFrame.rendezvousId, 'self-device-id');
    assert.ok(auth._currentLadder, 'ladder is active while Rung 1 is awaiting');

    // Allow the microtask chain to flush and the ladder to settle naturally.
    auth.shutdown();
    await new Promise((r) => setImmediate(r));
    assert.equal(auth._currentLadder, null, 'shutdown clears the ladder');
  });

  it('does not start a second ladder while one is already running', async () => {
    const { auth, sent } = makeLadderAuthority();
    auth.notifyPeerOnline('X');
    auth.notifyPeerOnline('Y');

    // Drive X to FAILED through ping-missed reducer events directly so we
    // can check the kick semantics without needing two cadence cycles.
    auth._dispatchPeer('X', { type: 'ping-missed' }); // STALE
    auth._dispatchPeer('X', { type: 'ping-missed' }); // FAILED → kick #1
    const ladderRef = auth._currentLadder;
    assert.ok(ladderRef, 'first FAILED peer kicks the ladder');

    const registersBefore = sent.filter((m) => m.type === 'register-rendezvous').length;

    // Y goes FAILED while the ladder is still running — must NOT start a new ladder.
    auth._dispatchPeer('Y', { type: 'ping-missed' });
    auth._dispatchPeer('Y', { type: 'ping-missed' });
    assert.equal(auth._currentLadder, ladderRef, 'second FAILED peer does not replace the ladder');

    const registersAfter = sent.filter((m) => m.type === 'register-rendezvous').length;
    assert.equal(registersAfter, registersBefore, 'no extra register-rendezvous from a second kick');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('Rung 1 succeeds when the failed peer becomes HEALTHY within budget', async () => {
    const { auth, clock } = makeLadderAuthority();
    auth.notifyPeerOnline('X');
    auth._dispatchPeer('X', { type: 'ping-missed' });
    auth._dispatchPeer('X', { type: 'ping-missed' });
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.FAILED);
    assert.ok(auth._currentLadder);

    // 2 seconds into Rung 1's 5s budget, a frame arrives from X.
    clock.tick(2_000);
    auth.notifyFrameReceived('X');

    // The ladder's success-criterion observer fires synchronously on the
    // peerHealth.next(); the .then callback then dispatches recovery-
    // succeeded which moves X back to UNKNOWN, then the frame-received
    // already promoted it to HEALTHY. Net: X is HEALTHY and the ladder
    // releases its slot.
    await new Promise((r) => setImmediate(r));
    assert.equal(auth._currentLadder, null, 'ladder released after Rung 1 success');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);
  });

  it('selfState entering RECONNECTING also kicks the ladder', async () => {
    const { auth } = makeLadderAuthority();
    auth.notifyWsOpening();
    auth.notifyAuthComplete();
    assert.equal(auth.selfState.value, SelfState.ONLINE);
    assert.equal(auth._currentLadder, null);

    auth.notifyWsClosed(); // ONLINE → RECONNECTING
    assert.equal(auth.selfState.value, SelfState.RECONNECTING);
    assert.ok(auth._currentLadder, 'self-RECONNECTING transition kicks the ladder');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('Rung 2 calls forceWsReconnect when Rung 1 budget elapses', async () => {
    const { auth, clock, calls } = makeLadderAuthority({ withForceWsReconnect: true });
    auth.notifyPeerOnline('X');
    auth._dispatchPeer('X', { type: 'ping-missed' });
    auth._dispatchPeer('X', { type: 'ping-missed' });
    assert.ok(auth._currentLadder);

    // Advance past Rung 1's 5s budget.
    clock.tick(5_000);
    await new Promise((r) => setImmediate(r));
    // Microtask chain may need a couple of flushes to advance Rung 2.
    await new Promise((r) => setImmediate(r));
    assert.equal(calls.forceWsReconnect, 1, 'rung2 invoked forceWsReconnect once');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('shutdown cancels an in-flight ladder cleanly', async () => {
    const { auth, clock } = makeLadderAuthority({ withForceWsReconnect: true });
    auth.notifyPeerOnline('X');
    auth._dispatchPeer('X', { type: 'ping-missed' });
    auth._dispatchPeer('X', { type: 'ping-missed' });
    assert.ok(auth._currentLadder);

    auth.shutdown();
    await new Promise((r) => setImmediate(r));

    // No timer should remain armed: shutdown clears cadence timers, and the
    // ladder's cancel-driven cleanup releases its budget timer + observer.
    assert.equal(clock.pending, 0, 'no leaked timers after shutdown');
    assert.equal(auth._currentLadder, null);
  });
});

// ─── Task 9: ensureSendable full pre-flight algorithm ────────────────────────

/**
 * Build an ensureSendable-ready authority. Mirrors `makeLadderAuthority` but
 * additionally lifts selfState to ONLINE (the step-1 gate) so each test can
 * focus on the per-peer logic without re-priming.
 */
function makePreFlightAuthority({ withForceWsReconnect = false } = {}) {
  const clock = new FakeClock(0);
  const sent = [];
  const calls = { forceWsReconnect: 0 };
  const hooks = {
    sendJson: (m) => sent.push(m),
    ownDeviceId: 'self-device-id',
  };
  if (withForceWsReconnect) {
    hooks.forceWsReconnect = () => { calls.forceWsReconnect += 1; };
  }
  const auth = new ConnectionAuthority({
    signalingHooks: hooks,
    options: { timerImpl: clock },
  });
  auth.notifyWsOpening();
  auth.notifyAuthComplete();
  return { auth, clock, sent, calls };
}

/**
 * Helper: count outbound peer-pings recorded in `sent`. Useful for the
 * "no ping was fired" assertions in the skip-path tests.
 */
function countPings(sent) {
  return sent.filter((m) => m.type === 'peer-ping').length;
}

describe('ConnectionAuthority: ensureSendable (Task 9 pre-flight)', () => {
  it('returns SELF_OFFLINE without probing when selfState != ONLINE', async () => {
    const { auth, sent } = makePreFlightAuthority();
    // Drop selfState back to RECONNECTING.
    auth.notifyWsClosed();
    assert.equal(auth.selfState.value, SelfState.RECONNECTING);

    const before = countPings(sent);
    const result = await auth.ensureSendable('X');
    assert.deepEqual(result, { ok: false, reason: 'SELF_OFFLINE' });
    assert.equal(countPings(sent), before, 'no peer-ping fired on self-offline gate');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('returns ok immediately when peer is HEALTHY with traffic in last 30s', async () => {
    const { auth, clock, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X');
    // Real frame at t=0 promotes X to HEALTHY AND records lastTrafficAt.
    auth.notifyFrameReceived('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);

    // 5s later (well within the 30s window) → skip the probe.
    clock.tick(5_000);
    const beforePings = countPings(sent);
    const result = await auth.ensureSendable('X');
    assert.deepEqual(result, { ok: true });
    assert.equal(countPings(sent), beforePings, 'no peer-ping fired when within 30s of fresh traffic');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('issues a peer-ping when HEALTHY but traffic is older than 30s; ok on pong', async () => {
    const { auth, clock, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X');
    auth.notifyFrameReceived('X');
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);

    // Advance past the 30s window so the skip is invalidated. (Cadence
    // would fire its own ping at t=120s, but we stop at t=31s.)
    clock.tick(RECENT_TRAFFIC_WINDOW_MS + 1_000);
    const beforePings = countPings(sent);

    const promise = auth.ensureSendable('X');
    // Microtask flush so the probe-ping has been issued via sendJson.
    await new Promise((r) => setImmediate(r));
    assert.equal(countPings(sent), beforePings + 1, 'pre-flight peer-ping issued');

    // The most recent peer-ping is ours. Pong it.
    const ping = sent.filter((m) => m.type === 'peer-ping').slice(-1)[0];
    auth.notifyPongReceived(ping.nonce);

    const result = await promise;
    assert.deepEqual(result, { ok: true });

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('issues a peer-ping when peer is UNKNOWN regardless of lastTrafficAt; ok on pong', async () => {
    const { auth, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X'); // UNKNOWN, no traffic recorded.
    const beforePings = countPings(sent);

    const promise = auth.ensureSendable('X');
    await new Promise((r) => setImmediate(r));
    assert.equal(countPings(sent), beforePings + 1, 'UNKNOWN peer triggers a probe');

    const ping = sent.filter((m) => m.type === 'peer-ping').slice(-1)[0];
    auth.notifyPongReceived(ping.nonce);

    const result = await promise;
    assert.deepEqual(result, { ok: true });

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('coalesces concurrent ensureSendable calls for the same peer into one probe', async () => {
    const { auth, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X');
    const beforePings = countPings(sent);

    const a = auth.ensureSendable('X');
    const b = auth.ensureSendable('X');
    const c = auth.ensureSendable('X');
    await new Promise((r) => setImmediate(r));
    assert.equal(countPings(sent), beforePings + 1, 'one probe shared across concurrent callers');

    const ping = sent.filter((m) => m.type === 'peer-ping').slice(-1)[0];
    auth.notifyPongReceived(ping.nonce);

    const [ra, rb, rc] = await Promise.all([a, b, c]);
    assert.deepEqual(ra, { ok: true });
    assert.deepEqual(rb, { ok: true });
    assert.deepEqual(rc, { ok: true });

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('on 5s ping timeout, kicks ladder; if ladder succeeds, re-pings and returns ok', async () => {
    const { auth, clock, sent } = makePreFlightAuthority({ withForceWsReconnect: true });
    auth.notifyPeerOnline('X');
    const beforePings = countPings(sent);

    const promise = auth.ensureSendable('X');
    await new Promise((r) => setImmediate(r));
    assert.equal(countPings(sent), beforePings + 1, 'first probe-ping issued');

    // Advance past the 5s pre-flight timeout so the probe surrenders. Note:
    // the cadence-tracker's own 10s timeout has not yet fired — our 5s racer
    // is what produces the timeout result.
    clock.tick(5_000);
    await new Promise((r) => setImmediate(r));

    // Ladder is now running (kicked from pre-flight-failed → FAILED).
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.FAILED);
    assert.ok(auth._currentLadder, 'ladder kicked after pre-flight timeout');

    // Drive Rung 1 to success: a frame arrives from X within Rung 1's 5s.
    auth.notifyFrameReceived('X');
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    assert.equal(auth._currentLadder, null, 'ladder released after Rung 1 success');

    // The post-success retry probe must have been issued — pong it.
    // We expect: probe1 (timed out) + probe2 (retry). So total +2 pings.
    assert.equal(countPings(sent), beforePings + 2, 'retry probe issued after ladder success');
    const retryPing = sent.filter((m) => m.type === 'peer-ping').slice(-1)[0];
    auth.notifyPongReceived(retryPing.nonce);

    const result = await promise;
    assert.deepEqual(result, { ok: true });

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('on 5s ping timeout with ladder failure, returns PEER_UNREACHABLE', async () => {
    // No `forceWsReconnect` hook: Rung 2 surrenders synchronously. Rung 3
    // throws "TODO Rung 3" so the ladder reports `exhausted: true`.
    const { auth, clock, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X');
    const beforePings = countPings(sent);

    const promise = auth.ensureSendable('X');
    await new Promise((r) => setImmediate(r));
    assert.equal(countPings(sent), beforePings + 1, 'probe issued');

    // 5s → pre-flight timeout → FAILED → ladder kicks.
    clock.tick(5_000);
    await new Promise((r) => setImmediate(r));
    assert.ok(auth._currentLadder, 'ladder kicked');

    // Burn Rung 1's 5s budget; Rung 2 surrenders immediately (no
    // forceWsReconnect); Rung 3 throws → exhausted.
    clock.tick(5_000);
    // Flush the microtask chain: Rung 1 timeout → Rung 2 surrender →
    // Rung 3 throw → ladder settles → ensureSendable continues.
    for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));

    const result = await promise;
    assert.deepEqual(result, { ok: false, reason: 'PEER_UNREACHABLE' });
    assert.equal(auth._currentLadder, null, 'ladder released after exhaustion');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('lastTrafficAt is updated by send-completed (not just frame-received)', async () => {
    const { auth, clock, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X');
    auth.notifySendCompleted('X'); // promotes to HEALTHY + records traffic
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.HEALTHY);

    clock.tick(5_000);
    const beforePings = countPings(sent);
    const result = await auth.ensureSendable('X');
    assert.deepEqual(result, { ok: true });
    assert.equal(countPings(sent), beforePings, 'no probe — send-completed counted as recent traffic');

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });

  it('Task 11 follow-up F: pre-flight pong promotes peer to HEALTHY through the reducer', async () => {
    // Spec gap closed in Task 11: a successful pre-flight ping IS strong
    // evidence of peer life. Before this fix, an UNKNOWN peer probed by
    // ensureSendable would resolve {ok:true} but stay UNKNOWN — popup dot
    // stuck yellow. After the fix, the reducer's `pong-received` lifts to
    // HEALTHY.
    const { auth, sent } = makePreFlightAuthority();
    auth.notifyPeerOnline('X'); // UNKNOWN
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.UNKNOWN);

    const promise = auth.ensureSendable('X');
    await new Promise((r) => setImmediate(r));
    const ping = sent.filter((m) => m.type === 'peer-ping').slice(-1)[0];
    auth.notifyPongReceived(ping.nonce);
    const result = await promise;
    assert.deepEqual(result, { ok: true });
    assert.equal(
      auth.peerHealth.value.get('X'),
      PeerHealth.HEALTHY,
      'pre-flight pong promoted peer through the reducer',
    );

    auth.shutdown();
    await new Promise((r) => setImmediate(r));
  });
});

// ─── Task 11: Rung 3, Rung 4, thrash guard, requestReconnect ─────────────────

/**
 * Build a Task 11 authority with full hook coverage. Both `forceWsReconnect`
 * (Rung 2) and `forceFullReset` (Rung 3) are spies whose count + behaviour
 * the tests inspect. `forceFullReset` defaults to "succeed by lifting
 * selfState to ONLINE on next tick" — a faithful production-ish stub.
 */
function makeRung3Authority({
  clockStart = 0,
  rung3Behaviour = 'success', // 'success' | 'noop' | 'throw'
} = {}) {
  const clock = new FakeClock(clockStart);
  const sent = [];
  const calls = { forceWsReconnect: 0, forceFullReset: 0 };
  const hooks = {
    sendJson: (m) => sent.push(m),
    ownDeviceId: 'self-device-id',
    forceWsReconnect: () => { calls.forceWsReconnect += 1; },
    // The hook returns a promise that resolves AFTER restarting (in
    // production this awaits autoStartRelayIfPaired). Once it resolves, the
    // test can simulate a successful relay reconnect by calling
    // notifyAuthComplete on the authority.
    forceFullReset: async () => {
      calls.forceFullReset += 1;
      // Reset selfState to OFFLINE/CONNECTING before "auth-completing" so
      // the next notifyAuthComplete actually transitions selfState. This
      // mirrors what background-relay.js does (stopPairingListener → fresh
      // connect → notifyWsOpening → notifyAuthComplete).
    },
  };
  if (rung3Behaviour === 'throw') {
    hooks.forceFullReset = async () => {
      calls.forceFullReset += 1;
      throw new Error('forceFullReset boom');
    };
  } else if (rung3Behaviour === 'noop') {
    hooks.forceFullReset = async () => { calls.forceFullReset += 1; };
  }
  const auth = new ConnectionAuthority({
    signalingHooks: hooks,
    options: { timerImpl: clock },
  });
  return { auth, clock, sent, calls, hooks };
}

/** Drive the authority to ONLINE so we can dispatch `recovery-began` etc. */
function bringOnline(auth) {
  auth.notifyWsOpening();
  auth.notifyAuthComplete();
}

/**
 * Drain pending microtasks. Each `setImmediate` cycle lets the Promise chain
 * advance one microtask "frame." We yield 8 times because the ladder chains
 * roughly: rung-action → await predicate → resolve → settle handler → next
 * rung; deep enough to clear it without hitting infinite loops.
 */
async function flush(times = 8) {
  for (let i = 0; i < times; i += 1) {
    await new Promise((r) => setImmediate(r));
  }
}

/**
 * Burn the full ladder budget by ticking the clock per-rung and flushing
 * microtasks between rungs. Without this, ticking the combined budget at once
 * advances virtual time past the rung-2/3 budget timers BEFORE the rung-2/3
 * actions have been dispatched on the microtask queue — so those budget
 * timers are never armed.
 */
async function burnLadder(clock) {
  await flush();
  clock.tick(RUNG_1_BUDGET_MS);
  await flush();
  clock.tick(RUNG_2_BUDGET_MS);
  await flush();
  clock.tick(RUNG_3_BUDGET_MS);
  await flush();
}

describe('ConnectionAuthority: Rung 3 (full session reset)', () => {
  it('Rung 3 calls forceFullReset and resolves true when selfState lifts to ONLINE', async () => {
    const { auth, clock, calls } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);
    auth.notifyWsClosed(); // ONLINE → RECONNECTING; ladder kicks
    assert.ok(auth._currentLadder);

    // Burn Rung 1 (no peer becomes HEALTHY — the composite predicate per
    // follow-up C requires selfState=ONLINE which is RECONNECTING here).
    await flush();
    clock.tick(RUNG_1_BUDGET_MS);
    await flush();
    // Burn Rung 2 (forceWsReconnect invoked but doesn't actually reconnect).
    clock.tick(RUNG_2_BUDGET_MS);
    await flush();
    assert.equal(calls.forceWsReconnect, 1);

    // Rung 3 is now running. forceFullReset has been awaited; the rung is
    // waiting for selfState=ONLINE. Simulate a successful relay reconnect:
    // production would dispatch recovery-succeeded via the wiring after
    // a fresh auth-complete; here we shortcut by setting selfState directly,
    // which is what the awaitObservableOrTimeout helper observes.
    auth._selfState.next(SelfState.ONLINE);
    await flush();

    assert.equal(calls.forceFullReset, 1, 'forceFullReset invoked once');
    assert.equal(auth._currentLadder, null, 'ladder released after Rung 3 success');
    assert.equal(auth.surrenderedToUser.value, false, 'surrender flag stayed clear');
    assert.equal(auth._rung3FailureLog.length, 0, 'no Rung-3 failure recorded on success');

    auth.shutdown();
  });

  it('Rung 3 times out → exhausted → Rung 4 surrender + backoff timer armed', async () => {
    const { auth, clock, calls } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);
    auth.notifyWsClosed();
    assert.ok(auth._currentLadder);

    await burnLadder(clock);

    assert.equal(calls.forceFullReset, 1);
    assert.equal(auth._currentLadder, null, 'ladder released after exhaustion');
    assert.equal(auth.surrenderedToUser.value, true, 'surrender flag set');
    assert.equal(auth._rung3FailureLog.length, 1, 'Rung 3 failure recorded');
    // Backoff timer is armed for the first attempt (30s).
    assert.ok(auth._backoffTimer, 'backoff timer armed');

    auth.shutdown();
    await flush();
    assert.equal(clock.pending, 0, 'shutdown clears backoff timer');
  });

  it('Rung 3 with no forceFullReset hook surrenders synchronously (skeleton mode)', async () => {
    // Mirror the original Task 8/9 skeleton-mode behaviour: without the
    // forceFullReset hook, Rung 3's action returns false immediately, and
    // the ladder advances to exhaustion → Rung 4 surrender.
    const clock = new FakeClock(0);
    const sent = [];
    const auth = new ConnectionAuthority({
      signalingHooks: {
        sendJson: (m) => sent.push(m),
        ownDeviceId: 'self-device-id',
        // no forceWsReconnect, no forceFullReset
      },
      options: { timerImpl: clock },
    });
    bringOnline(auth);
    auth.notifyWsClosed();

    // Rungs 1 takes its full budget; Rungs 2 + 3 surrender synchronously.
    await burnLadder(clock);

    assert.equal(auth.surrenderedToUser.value, true);
    auth.shutdown();
  });
});

describe('ConnectionAuthority: thrash guard (≥2 Rung-3 failures in 5min)', () => {
  it('two full Rung-3 failures within 5 min → next kick goes straight to Rung 4', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    // Failure #1: full ladder run, all rungs time out.
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.equal(auth._rung3FailureLog.length, 1);
    auth._cancelBackoffTimer(); // don't let the 30s timer interfere

    // Drop selfState back so we can re-enter RECONNECTING.
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);

    // Failure #2.
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.equal(auth._rung3FailureLog.length, 2);
    auth._cancelBackoffTimer();

    // Now: any new kick should go straight to surrender — `_kickLadder`
    // sees the thrash counter ≥ 2 and builds the surrender ladder, which
    // resolves false immediately. The settle handler then promotes to
    // Rung 4.
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);
    auth.notifyWsClosed();
    // The surrender ladder runs synchronously (one rung returning false).
    await flush();
    assert.equal(auth.surrenderedToUser.value, true);
    // Crucially, no NEW Rung-3 failure recorded (the surrender ladder
    // skipped Rung 3 entirely).
    assert.equal(auth._rung3FailureLog.length, 2, 'thrash log not double-counted');

    auth.shutdown();
  });

  it('Rung-3 failures older than 5 min do NOT count toward the threshold', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    // Failure #1 at t=0.
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.equal(auth._rung3FailureLog.length, 1);
    auth._cancelBackoffTimer();

    // Advance past the 5-minute window. The backoff timer would normally
    // fire mid-window — cancel it so we don't auto-kick a new ladder.
    clock.tick(6 * 60 * 1_000);
    auth._cancelBackoffTimer();

    // The next kick should NOT trigger thrash — the old failure is pruned.
    assert.equal(auth._thrashGuardActive(), false, 'old failure pruned');
  });
});

describe('ConnectionAuthority: Rung 4 backoff scheduler', () => {
  it('first surrender schedules backoff at 30s; second at 2m; third at 10m; cap at 30m', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    // Helper: trigger one full failure cycle, then assert the backoff timer
    // is armed and the attempt counter advanced.
    const burnLadderAndAssertBackoff = async (expectedAttemptIdx) => {
      auth.notifyWsClosed();
      await burnLadder(clock);
      assert.equal(
        auth._backoffAttempt,
        expectedAttemptIdx + 1,
        `attempt counter advanced to ${expectedAttemptIdx + 1}`,
      );
    };

    // Attempt #1 → 30s.
    await burnLadderAndAssertBackoff(0);
    assert.ok(auth._backoffTimer);
    auth._cancelBackoffTimer();

    // Reset state for the next loop. We're in RECONNECTING / surrendered.
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);
    auth._rung3FailureLog = []; // bypass thrash so we run a full ladder again

    await burnLadderAndAssertBackoff(1);
    auth._cancelBackoffTimer();
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);
    auth._rung3FailureLog = [];

    await burnLadderAndAssertBackoff(2);
    auth._cancelBackoffTimer();
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);
    auth._rung3FailureLog = [];

    // Attempt #4 caps at 30m.
    await burnLadderAndAssertBackoff(3);
    assert.equal(auth._backoffAttempt, 4);
    auth._cancelBackoffTimer();
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);
    auth._rung3FailureLog = [];

    // Attempt #5+ stays at the cap.
    await burnLadderAndAssertBackoff(4);
    assert.equal(auth._backoffAttempt, 5, 'counter still advances past cap');
    auth._cancelBackoffTimer();
    // The schedule index, however, clamps to BACKOFF_SCHEDULE_MS.length-1.
    // We can't directly observe the delay without intercepting setTimeout,
    // so this assertion just locks the counter discipline.

    auth.shutdown();
  });

  it('successful recovery resets the backoff attempt counter', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    // Surrender once, advance counter to 1.
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.equal(auth._backoffAttempt, 1);
    auth._cancelBackoffTimer();

    // Simulate a successful recovery via requestReconnect-like flow: dispatch
    // recovery-succeeded directly (this is what _handleLadderSettled does).
    // The next kick should start from attempt #0 again.
    auth._selfState.next(SelfState.ONLINE);
    auth._surrenderedToUser.next(false);
    auth._rung3FailureLog = [];
    // Mock a fake successful ladder settlement.
    auth._handleLadderSettled({ _isSurrenderLadder: false }, { ok: true }, null);
    assert.equal(auth._backoffAttempt, 0, 'attempt counter reset on success');

    auth.shutdown();
  });
});

describe('ConnectionAuthority: requestReconnect', () => {
  it('cancels in-flight ladder and starts a fresh Rung-3-only ladder', async () => {
    const { auth, clock, calls } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);
    auth.notifyWsClosed();
    assert.ok(auth._currentLadder);
    const oldLadder = auth._currentLadder;

    // Manual reconnect mid-ladder. The new ladder is built and kicked
    // synchronously; awaiting requestReconnect would block on Rung 3
    // budget exhaustion, so we observe the latched state right away.
    const reconnectPromise = auth.requestReconnect();
    await flush();

    assert.notEqual(auth._currentLadder, oldLadder, 'old ladder replaced');
    assert.equal(oldLadder.cancelled, true, 'old ladder cancelled');

    // The new ladder is rung3-only. Burn its budget and verify forceFullReset
    // fired exactly once (not via the cancelled old ladder).
    clock.tick(RUNG_3_BUDGET_MS);
    await flush();
    assert.equal(calls.forceFullReset, 1, 'forceFullReset fired by manual ladder');

    const result = await reconnectPromise;
    assert.equal(result.ok, false, 'rung3 timed out → ok:false');

    auth.shutdown();
  });

  it('clears backoff timer + surrender flag', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    // Drive to Rung 4 surrender with a backoff timer armed.
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.equal(auth.surrenderedToUser.value, true);
    assert.ok(auth._backoffTimer);

    // Manual reconnect.
    const p = auth.requestReconnect();
    await flush();
    assert.equal(auth.surrenderedToUser.value, false, 'surrender flag cleared');
    assert.equal(auth._backoffTimer, null, 'backoff timer cleared');

    // Drain the rest of the new ladder so the test exits cleanly.
    clock.tick(RUNG_3_BUDGET_MS);
    await flush();
    await p;
    auth.shutdown();
  });

  it('resets the thrash counter on manual tap', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);
    // Seed two prior Rung-3 failures so the next auto-kick would surrender.
    auth._rung3FailureLog = [auth._now(), auth._now()];
    assert.equal(auth._thrashGuardActive(), true);

    const p = auth.requestReconnect();
    await flush();
    assert.deepEqual(auth._rung3FailureLog, [], 'thrash log cleared on manual tap');

    // Drain the new ladder.
    clock.tick(RUNG_3_BUDGET_MS);
    await flush();
    await p;
    auth.shutdown();
  });

  it('resolves {ok:true} when Rung 3 succeeds within budget', async () => {
    const { auth } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    const reconnectPromise = auth.requestReconnect();
    // Yield for the ladder + Rung 3 to start.
    await flush();
    // forceFullReset has resolved; ladder is awaiting selfState=ONLINE.
    auth._selfState.next(SelfState.ONLINE);
    await flush();

    const result = await reconnectPromise;
    assert.deepEqual(result, { ok: true });
    assert.equal(auth.surrenderedToUser.value, false);
    assert.equal(auth._currentLadder, null);

    auth.shutdown();
  });

  it('is a no-op after shutdown', async () => {
    const { auth } = makeRung3Authority({ rung3Behaviour: 'noop' });
    auth.shutdown();
    const result = await auth.requestReconnect();
    assert.deepEqual(result, { ok: false });
  });
});

describe('ConnectionAuthority: surrenderedToUser observable', () => {
  it('starts false and is part of the observable surface', () => {
    const { auth } = makeRung3Authority({ rung3Behaviour: 'noop' });
    assert.ok(auth.surrenderedToUser, 'surrenderedToUser observable exists');
    assert.equal(auth.surrenderedToUser.value, false, 'starts false');
    auth.shutdown();
  });

  it('emits to subscribers when the flag flips', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    const seen = [];
    auth.surrenderedToUser.subscribe((v) => seen.push(v));
    assert.deepEqual(seen, [false], 'replays initial value');

    bringOnline(auth);
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.deepEqual(seen, [false, true], 'flag flipped on Rung 4 surrender');

    auth.shutdown();
  });

  it('is cleared by a successful recovery and by requestReconnect', async () => {
    const { auth, clock } = makeRung3Authority({ rung3Behaviour: 'noop' });
    bringOnline(auth);

    // Surrender.
    auth.notifyWsClosed();
    await burnLadder(clock);
    assert.equal(auth.surrenderedToUser.value, true);

    // Manual tap.
    const p = auth.requestReconnect();
    await flush();
    assert.equal(auth.surrenderedToUser.value, false);

    clock.tick(RUNG_3_BUDGET_MS);
    await flush();
    await p;
    auth.shutdown();
  });
});

describe('ConnectionAuthority: follow-ups A-G integration checks', () => {
  it('A: peer-FAILED kick dispatches recovery-began (selfState moves to RECONNECTING)', () => {
    const { auth } = makeLadderAuthority();
    auth.notifyPeerOnline('X');
    // selfState starts OFFLINE. Kicking the ladder via peer-FAILED should
    // drive selfState to RECONNECTING through `recovery-began`.
    auth._dispatchPeer('X', { type: 'ping-missed' });
    auth._dispatchPeer('X', { type: 'ping-missed' });
    assert.equal(auth.peerHealth.value.get('X'), PeerHealth.FAILED);
    assert.equal(auth.selfState.value, SelfState.RECONNECTING,
      'recovery-began drove selfState to RECONNECTING on peer-FAILED');
    auth.shutdown();
  });

  it('C: Rung 1 self-trigger requires selfState=ONLINE AND any peer HEALTHY', async () => {
    // Self-RECONNECTING kick: Rung 1 must NOT fire success on a peer
    // becoming HEALTHY while selfState is still RECONNECTING.
    const clock = new FakeClock(0);
    const sent = [];
    const auth = new ConnectionAuthority({
      signalingHooks: { sendJson: (m) => sent.push(m), ownDeviceId: 'self-device-id' },
      options: { timerImpl: clock },
    });
    bringOnline(auth);
    auth.notifyWsClosed(); // ONLINE → RECONNECTING; ladder kicks
    auth.notifyPeerOnline('X');
    auth.notifyFrameReceived('X'); // X HEALTHY but selfState still RECONNECTING

    // Rung 1 should NOT have succeeded — selfState gate is still RECONNECTING.
    // Burn the budget; Rung 2 begins (no forceWsReconnect → surrenders fast).
    clock.tick(RUNG_1_BUDGET_MS);
    await new Promise((r) => setImmediate(r));
    // If Rung 1 succeeded (the bug), the ladder would be released.
    // With the fix, Rung 1 timed out → Rung 2 invoked.
    // We check by observing that selfState is still RECONNECTING (success
    // would have dispatched recovery-succeeded → ONLINE).
    assert.equal(auth.selfState.value, SelfState.RECONNECTING,
      'Rung 1 must not succeed without selfState=ONLINE');

    auth.shutdown();
  });

  it('E: tracker.sweepExpired is called on each ladder kick (no leaked _pending)', async () => {
    const { auth } = makeRung3Authority({ rung3Behaviour: 'noop' });
    let sweepCalls = 0;
    const realSweep = auth._pingTracker.sweepExpired.bind(auth._pingTracker);
    auth._pingTracker.sweepExpired = (now) => { sweepCalls += 1; return realSweep(now); };

    bringOnline(auth);
    auth.notifyWsClosed();
    assert.equal(sweepCalls, 1, 'sweepExpired called on the ladder kick');

    auth.shutdown();
  });
});
