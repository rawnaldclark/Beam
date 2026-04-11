/**
 * presence.test.js — TDD tests for the Presence system.
 *
 * Uses a mock gateway (no real WebSocket needed) to isolate the Presence class
 * from network I/O. The mock captures outbound messages in a `sent` array and
 * provides a minimal on/emit EventEmitter interface so Presence can listen for
 * gateway disconnect events.
 *
 * Test plan:
 *   1. register() stores device and rendezvousIds, isOnline() returns true
 *   2. register() notifies existing rendezvous peers with PEER_ONLINE
 *   3. unregister() notifies peers with PEER_OFFLINE, isOnline() returns false
 *   4. heartbeat() updates lastSeen timestamp
 *   5. Silence timeout marks stale devices offline (checkIntervalMs=50, silenceTimeoutMs=100)
 *   6. getRendezvousPeers() returns correct sets for multiple rendezvous IDs
 *   7. Re-registration replaces old rendezvous IDs with new ones
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { Presence } from '../src/presence.js';

// ---------------------------------------------------------------------------
// Mock gateway factory
// ---------------------------------------------------------------------------

/**
 * Creates a minimal mock gateway suitable for testing Presence in isolation.
 *
 * The `sent` array accumulates every { deviceId, msg } pair pushed via send().
 * Event handlers registered via on() are stored and fired via emit(), which
 * mirrors the EventEmitter contract that Presence expects from the real Gateway.
 *
 * @returns {{ devices: Map, send: Function, on: Function, emit: Function, sent: Array }}
 */
function createMockGateway() {
  const sent = [];
  const handlers = {};

  const gateway = {
    devices: new Map(),

    /**
     * Captures an outbound message for later assertion.
     * @param {string} deviceId
     * @param {object} msg
     * @returns {boolean} true (mirrors real gateway return value)
     */
    send(deviceId, msg) {
      sent.push({ deviceId, msg });
      return true;
    },

    /**
     * Registers an event handler (mirrors EventEmitter.on).
     * @param {string} event
     * @param {Function} handler
     */
    on(event, handler) {
      if (!handlers[event]) handlers[event] = [];
      handlers[event].push(handler);
    },

    /**
     * Fires all registered handlers for the given event.
     * @param {string} event
     * @param {...any} args
     */
    emit(event, ...args) {
      if (handlers[event]) {
        for (const h of handlers[event]) h(...args);
      }
    },

    /** Accumulated outbound messages — inspected by tests. */
    sent,
  };

  return gateway;
}

/**
 * Helper: returns all messages sent to a specific device.
 * @param {Array} sent - gateway.sent array
 * @param {string} deviceId
 * @returns {object[]}
 */
function messagesTo(sent, deviceId) {
  return sent.filter((e) => e.deviceId === deviceId).map((e) => e.msg);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Presence', () => {
  /** @type {ReturnType<createMockGateway>} */
  let gateway;

  /** @type {Presence} */
  let presence;

  beforeEach(() => {
    gateway = createMockGateway();
    // Disable the reconnect grace period by default so existing tests
    // that expect synchronous unregister semantics continue to work.
    // The grace behaviour has dedicated tests later in this suite.
    presence = new Presence({ gateway, reconnectGraceMs: 0 });
  });

  afterEach(() => {
    // Ensure any background interval is cleaned up between tests
    if (presence && typeof presence.destroy === 'function') {
      presence.destroy();
    }
  });

  // -------------------------------------------------------------------------
  // Test 1 — register() stores device, isOnline() returns true
  // -------------------------------------------------------------------------
  it('register() stores the device and isOnline() returns true', () => {
    presence.register('device-A', ['rv1', 'rv2']);

    assert.ok(presence.isOnline('device-A'), 'device-A should be online after register');
    assert.ok(!presence.isOnline('device-X'), 'unknown device should not be online');
  });

  // -------------------------------------------------------------------------
  // Test 2 — register() notifies existing peers with PEER_ONLINE
  // -------------------------------------------------------------------------
  it('register() sends PEER_ONLINE to existing rendezvous peers', () => {
    // device-B is already registered on rendezvous 'rv1'
    presence.register('device-B', ['rv1']);

    // device-A joins rv1 — device-B must be notified, and device-A must also
    // receive a PEER_ONLINE for device-B (bidirectional notification)
    gateway.sent.length = 0; // reset captured messages

    presence.register('device-A', ['rv1']);

    const toB = messagesTo(gateway.sent, 'device-B');
    const toA = messagesTo(gateway.sent, 'device-A');

    // device-B should receive PEER_ONLINE for device-A
    assert.ok(
      toB.some((m) => m.type === 'peer-online' && m.deviceId === 'device-A'),
      'device-B should receive peer-online for device-A',
    );

    // device-A should receive PEER_ONLINE for device-B (already online)
    assert.ok(
      toA.some((m) => m.type === 'peer-online' && m.deviceId === 'device-B'),
      'device-A should receive peer-online for device-B',
    );
  });

  // -------------------------------------------------------------------------
  // Test 3 — unregister() notifies peers with PEER_OFFLINE, isOnline() false
  // -------------------------------------------------------------------------
  it('unregister() sends PEER_OFFLINE to peers and isOnline() returns false', () => {
    presence.register('device-A', ['rv1']);
    presence.register('device-B', ['rv1']);
    gateway.sent.length = 0;

    presence.unregister('device-A');

    assert.ok(!presence.isOnline('device-A'), 'device-A should be offline after unregister');

    const toB = messagesTo(gateway.sent, 'device-B');
    assert.ok(
      toB.some((m) => m.type === 'peer-offline' && m.deviceId === 'device-A'),
      'device-B should receive peer-offline for device-A',
    );
  });

  // -------------------------------------------------------------------------
  // Test 4 — heartbeat() updates lastSeen timestamp
  // -------------------------------------------------------------------------
  it('heartbeat() updates the lastSeen timestamp', async () => {
    presence.register('device-A', ['rv1']);

    const before = presence.lastSeen('device-A');

    // Wait a tick so timestamps differ
    await new Promise((r) => setTimeout(r, 5));

    presence.heartbeat('device-A');

    const after = presence.lastSeen('device-A');
    assert.ok(after > before, `lastSeen should increase after heartbeat (before=${before}, after=${after})`);
  });

  // -------------------------------------------------------------------------
  // Test 5 — Silence timeout: devices marked offline after silenceTimeoutMs
  // -------------------------------------------------------------------------
  it('startSilenceChecker() unregisters devices silent longer than silenceTimeoutMs', async () => {
    // Use a very short timeout for deterministic testing. Keep grace at 0
    // so the silence checker's teardown is observable within this test.
    presence = new Presence({ gateway, silenceTimeoutMs: 100, checkIntervalMs: 50, reconnectGraceMs: 0 });

    presence.register('device-A', ['rv1']);
    presence.register('device-B', ['rv1']);
    gateway.sent.length = 0;

    presence.startSilenceChecker();

    // Wait longer than silenceTimeoutMs — both devices should go offline
    await new Promise((r) => setTimeout(r, 250));

    assert.ok(!presence.isOnline('device-A'), 'device-A should be offline after silence timeout');
    assert.ok(!presence.isOnline('device-B'), 'device-B should be offline after silence timeout');
  });

  // -------------------------------------------------------------------------
  // Test 6 — getRendezvousPeers() returns correct Set of peer device IDs
  // -------------------------------------------------------------------------
  it('getRendezvousPeers() returns the correct set of device IDs for a rendezvous ID', () => {
    presence.register('device-A', ['rv1', 'rv2']);
    presence.register('device-B', ['rv1']);
    presence.register('device-C', ['rv2']);

    const peersRv1 = presence.getRendezvousPeers('rv1');
    assert.ok(peersRv1 instanceof Set, 'getRendezvousPeers should return a Set');
    assert.ok(peersRv1.has('device-A'), 'rv1 should include device-A');
    assert.ok(peersRv1.has('device-B'), 'rv1 should include device-B');
    assert.ok(!peersRv1.has('device-C'), 'rv1 should not include device-C');

    const peersRv2 = presence.getRendezvousPeers('rv2');
    assert.ok(peersRv2.has('device-A'), 'rv2 should include device-A');
    assert.ok(peersRv2.has('device-C'), 'rv2 should include device-C');
    assert.ok(!peersRv2.has('device-B'), 'rv2 should not include device-B');

    // Unknown rendezvous ID should return an empty Set (not throw)
    const peersUnknown = presence.getRendezvousPeers('rv-unknown');
    assert.ok(peersUnknown instanceof Set, 'unknown rendezvous ID should return an empty Set');
    assert.equal(peersUnknown.size, 0, 'unknown rendezvous ID Set should be empty');
  });

  // -------------------------------------------------------------------------
  // Test 7 — Re-registration replaces old rendezvous IDs with new ones
  // -------------------------------------------------------------------------
  it('re-registration replaces old rendezvous IDs with new ones', () => {
    presence.register('device-B', ['rv1']);
    presence.register('device-A', ['rv1']); // device-A initially on rv1

    // Verify device-A is in rv1
    assert.ok(presence.getRendezvousPeers('rv1').has('device-A'), 'device-A should be in rv1 initially');

    gateway.sent.length = 0;

    // Re-register device-A on rv2 only (drops rv1 membership)
    presence.register('device-A', ['rv2']);

    // device-A should no longer be in rv1
    assert.ok(!presence.getRendezvousPeers('rv1').has('device-A'), 'device-A should no longer be in rv1 after re-registration');

    // device-A should be in rv2
    assert.ok(presence.getRendezvousPeers('rv2').has('device-A'), 'device-A should now be in rv2');

    // device-B (still on rv1) should have received PEER_OFFLINE for device-A
    // (since device-A left rv1) and NOT a spurious PEER_ONLINE for the re-registration
    // on rv2 (device-B is not on rv2).
    const toB = messagesTo(gateway.sent, 'device-B');
    assert.ok(
      toB.some((m) => m.type === 'peer-offline' && m.deviceId === 'device-A'),
      'device-B should receive peer-offline when device-A leaves rv1',
    );
  });

  // -------------------------------------------------------------------------
  // Test 8 — Reconnect grace: unregister + re-register within grace window
  //           does NOT emit PEER_OFFLINE to peers.
  // -------------------------------------------------------------------------
  it('reconnect grace period absorbs a quick unregister + register cycle', async () => {
    const gracePresence = new Presence({ gateway, reconnectGraceMs: 100 });
    try {
      gracePresence.register('device-B', ['rv1']);
      gracePresence.register('device-A', ['rv1']);
      gateway.sent.length = 0;

      // Simulate a flaky disconnect + immediate reconnect for device-A.
      gracePresence.unregister('device-A');
      // During the grace window, device-A is still tracked as online so
      // signaling can keep routing.
      assert.ok(
        gracePresence.isOnline('device-A'),
        'device-A should still be online during the grace window',
      );

      // Reconnect with the same rendezvous IDs BEFORE the grace expires.
      gracePresence.register('device-A', ['rv1']);

      // Wait past the grace window to confirm the pending teardown was
      // cancelled and no offline message ever fires.
      await new Promise((r) => setTimeout(r, 200));

      const toB = messagesTo(gateway.sent, 'device-B');
      assert.ok(
        !toB.some((m) => m.type === 'peer-offline'),
        'device-B should NOT receive peer-offline for device-A across the grace window',
      );
      assert.ok(
        gracePresence.isOnline('device-A'),
        'device-A should still be online after the grace window',
      );
    } finally {
      gracePresence.destroy();
    }
  });

  // -------------------------------------------------------------------------
  // Test 9 — Reconnect grace: if the device never comes back, PEER_OFFLINE
  //           is delivered after the grace window expires.
  // -------------------------------------------------------------------------
  it('reconnect grace: genuine disconnect still fires PEER_OFFLINE after window', async () => {
    const gracePresence = new Presence({ gateway, reconnectGraceMs: 50 });
    try {
      gracePresence.register('device-B', ['rv1']);
      gracePresence.register('device-A', ['rv1']);
      gateway.sent.length = 0;

      gracePresence.unregister('device-A');
      // Wait well past the grace window.
      await new Promise((r) => setTimeout(r, 150));

      const toB = messagesTo(gateway.sent, 'device-B');
      assert.ok(
        toB.some((m) => m.type === 'peer-offline' && m.deviceId === 'device-A'),
        'device-B should receive peer-offline for device-A after the grace window',
      );
      assert.ok(
        !gracePresence.isOnline('device-A'),
        'device-A should be offline after the grace window',
      );
    } finally {
      gracePresence.destroy();
    }
  });
});
