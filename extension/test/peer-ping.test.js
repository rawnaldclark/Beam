/**
 * @file peer-ping.test.js
 * @description Unit coverage for PeerPingTracker.
 *
 * Run:  node --test test/peer-ping.test.js
 *
 * Tests verify:
 *   - sendPing returns a {nonce, promise}; promise is pending; calls sendJson once with correct shape.
 *   - recordPong resolves the matching ping to {ok:true, rttMs:N}.
 *   - recordPong("unknown") is a no-op and does not throw.
 *   - sweepExpired after deadline rejects promise with {ok:false, reason:"timeout"} and removes the entry.
 *   - Each nonce is 16 random bytes, b64url-encoded, no padding, unique across calls.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { PeerPingTracker } from '../connection/peer-ping.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

/** Returns a promise that resolves/rejects with the settled value of p, or
 *  resolves to the sentinel PENDING if p is still unresolved after one microtask. */
const PENDING = Symbol('PENDING');
async function settleSoon(p) {
  return Promise.race([p, Promise.resolve(PENDING)]);
}

// ─── sendPing ─────────────────────────────────────────────────────────────────

describe('PeerPingTracker.sendPing', () => {
  it('returns {nonce, promise} and calls sendJson once with the correct shape', async () => {
    const sent = [];
    const tracker = new PeerPingTracker({
      sendJson: (msg) => sent.push(msg),
      timeoutMs: 5000,
      ownDeviceId: 'device-self',
    });

    const peerId = 'peer-device-abc';
    const result = tracker.sendPing(peerId);

    assert.ok(result, 'sendPing must return a value');
    assert.equal(typeof result.nonce, 'string', 'result.nonce must be a string');
    assert.ok(result.promise instanceof Promise, 'result.promise must be a Promise');

    // sendJson called exactly once
    assert.equal(sent.length, 1, 'sendJson should have been called once');
    const msg = sent[0];
    assert.equal(msg.type, 'peer-ping', 'type must be "peer-ping"');
    assert.equal(msg.nonce, result.nonce, 'msg.nonce must match result.nonce');
    assert.equal(msg.targetDeviceId, peerId, 'targetDeviceId must be peerId');
    assert.equal(msg.rendezvousId, 'device-self', 'rendezvousId must be ownDeviceId, NOT peerId');

    // promise is still pending
    const settled = await settleSoon(result.promise);
    assert.equal(settled, PENDING, 'promise should still be pending after sendPing');
  });

  it('rendezvousId is the injected ownDeviceId, not the peerId', () => {
    const sent = [];
    const tracker = new PeerPingTracker({
      sendJson: (msg) => sent.push(msg),
      timeoutMs: 5000,
      ownDeviceId: 'chrome-own-id-xyz',
    });

    const peerId = 'android-peer-id-123';
    tracker.sendPing(peerId);

    assert.equal(sent.length, 1, 'sendJson should have been called once');
    const msg = sent[0];
    assert.equal(msg.targetDeviceId, peerId, 'targetDeviceId must be peerId');
    assert.equal(msg.rendezvousId, 'chrome-own-id-xyz', 'rendezvousId must equal ownDeviceId');
    assert.notEqual(msg.rendezvousId, peerId, 'rendezvousId must NOT equal peerId');
  });

  it('nonce is 16-byte b64url without padding, unique across calls', () => {
    const tracker = new PeerPingTracker({
      sendJson: () => {},
      timeoutMs: 5000,
      ownDeviceId: 'device-self',
    });

    const nonces = new Set();
    for (let i = 0; i < 20; i++) {
      const { nonce } = tracker.sendPing('peer-' + i);
      // b64url of 16 bytes = ceil(16 * 4/3) = 22 chars (no padding)
      assert.equal(nonce.length, 22, `nonce length must be 22, got ${nonce.length}`);
      assert.match(nonce, /^[A-Za-z0-9\-_]+$/, 'nonce must be b64url characters only');
      assert.ok(!nonce.includes('='), 'nonce must have no padding');
      nonces.add(nonce);
    }
    assert.equal(nonces.size, 20, 'all 20 nonces must be unique');
  });
});

// ─── recordPong ──────────────────────────────────────────────────────────────

describe('PeerPingTracker.recordPong', () => {
  it('resolves the matching promise to {ok:true, rttMs:N}', async () => {
    const tracker = new PeerPingTracker({
      sendJson: () => {},
      timeoutMs: 5000,
      ownDeviceId: 'device-self',
    });

    const t0 = 1000;
    const { nonce, promise } = tracker.sendPing('peer-x', t0);

    const tPong = 1042;
    tracker.recordPong(nonce, tPong);

    const result = await promise;
    assert.deepEqual(result, { ok: true, rttMs: 42 });
  });

  it('recordPong("unknown") is a no-op and does not throw', () => {
    const tracker = new PeerPingTracker({
      sendJson: () => {},
      timeoutMs: 5000,
      ownDeviceId: 'device-self',
    });
    assert.doesNotThrow(() => tracker.recordPong('completely-unknown-nonce'));
  });
});

// ─── sweepExpired ─────────────────────────────────────────────────────────────

describe('PeerPingTracker.sweepExpired', () => {
  it('after deadline: rejects promise with {ok:false,reason:"timeout"} and returns [{nonce,peerId}]', async () => {
    const tracker = new PeerPingTracker({
      sendJson: () => {},
      timeoutMs: 3000,
      ownDeviceId: 'device-self',
    });

    const t0 = 5000;
    const peerId = 'peer-timeout-test';
    const { nonce, promise } = tracker.sendPing(peerId, t0);

    // Sweep before deadline — should be empty
    const earlyExpired = tracker.sweepExpired(t0 + 2999);
    assert.deepEqual(earlyExpired, [], 'no entries should expire before the deadline');

    // promise still pending
    const stillPending = await settleSoon(promise);
    assert.equal(stillPending, PENDING, 'promise must still be pending before deadline');

    // Sweep at/after deadline
    const expired = tracker.sweepExpired(t0 + 3000);
    assert.equal(expired.length, 1, 'one entry should expire');
    assert.equal(expired[0].nonce, nonce);
    assert.equal(expired[0].peerId, peerId);

    // Promise must reject
    await assert.rejects(promise, (err) => {
      assert.deepEqual(err, { ok: false, reason: 'timeout' });
      return true;
    });
  });

  it('after sweep, a subsequent sweep does not re-return the same entry', async () => {
    const tracker = new PeerPingTracker({
      sendJson: () => {},
      timeoutMs: 1000,
      ownDeviceId: 'device-self',
    });

    const t0 = 0;
    const { promise } = tracker.sendPing('peer-sweep-once', t0);
    // Suppress the unhandled rejection — we just want to test sweep returns empty.
    promise.catch(() => {});

    tracker.sweepExpired(t0 + 1000); // first sweep removes it
    const second = tracker.sweepExpired(t0 + 2000);
    assert.deepEqual(second, [], 'entry must not appear in second sweep');
  });

  it('non-expired pings are left in-flight while expired ones are removed', async () => {
    const tracker = new PeerPingTracker({
      sendJson: () => {},
      timeoutMs: 5000,
      ownDeviceId: 'device-self',
    });

    const t0 = 0;
    const { nonce: n1, promise: p1 } = tracker.sendPing('peer-1', t0);
    const { nonce: n2, promise: p2 } = tracker.sendPing('peer-2', t0 + 3000); // sent later, deadline later

    // Sweep at t0+5000: n1 expires (sent at t0, deadline t0+5000), n2 does not (deadline t0+8000)
    const expired = tracker.sweepExpired(t0 + 5000);
    assert.equal(expired.length, 1, 'only the first ping should expire');
    assert.equal(expired[0].nonce, n1);

    // p1 rejected
    await assert.rejects(p1, (e) => { assert.deepEqual(e, { ok: false, reason: 'timeout' }); return true; });

    // p2 still pending
    const p2state = await settleSoon(p2);
    assert.equal(p2state, PENDING, 'second ping must still be pending');
  });
});
