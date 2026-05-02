/**
 * @file connection-authority.test.js
 * @description Unit coverage for the ConnectionAuthority skeleton (Task 5).
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
 *
 * The skeleton tests do NOT exercise:
 *   - Ping cadence / sweepExpired (Task 7).
 *   - Recovery ladder (Tasks 8 / 11).
 *   - Real ensureSendable pre-flight (Task 9).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ConnectionAuthority } from '../connection/connection-authority.js';
import { SelfState } from '../connection/self-state.js';
import { PeerHealth } from '../connection/peer-health.js';

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

  it('does NOT directly promote peer health to HEALTHY (per spec note in Task 5)', () => {
    // The skeleton trusts the next frame-received / send-completed to promote
    // the peer; the tracker resolves by nonce, not peerId.
    const { hooks } = makeHooksWithIdentity();
    const auth = new ConnectionAuthority({ signalingHooks: hooks });
    auth.notifyPeerOnline('peer-X'); // X is now UNKNOWN.
    const { nonce } = auth._pingTracker.sendPing('peer-X');
    auth.notifyPongReceived(nonce);
    assert.equal(
      auth.peerHealth.value.get('peer-X'),
      PeerHealth.UNKNOWN,
      'skeleton must NOT promote on pong; only frame/send-completed promote',
    );
  });
});
