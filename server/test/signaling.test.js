/**
 * signaling.test.js — TDD tests for the Signaling module.
 *
 * Uses mock gateway and mock presence — no real WebSocket connections are
 * needed. The mocks are intentionally minimal, capturing only what the
 * Signaling class needs to operate.
 *
 * Test plan:
 *   1. Relays SDP offer to target — target gets msg with fromDeviceId added
 *   2. Relays SDP answer to target
 *   3. Relays ICE candidate to target
 *   4. Rejects when sender not in rendezvous — sends ERROR with "not.*rendezvous"
 *   5. Rejects when target not in rendezvous — sends ERROR
 *   6. Returns false for unknown message types (not a signaling type)
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Signaling } from '../src/signaling.js';

// ---------------------------------------------------------------------------
// Mock gateway factory
// ---------------------------------------------------------------------------

/**
 * Creates a minimal mock gateway suitable for testing Signaling in isolation.
 *
 * `sent` accumulates every { deviceId, msg } pair from send().
 * `sentTo` accumulates every { ws, msg } pair from sendTo().
 *
 * @returns {{ send: Function, sendTo: Function, sent: Array, sentTo: Array }}
 */
function createMockGateway() {
  const sent = [];
  const sentTo = [];

  return {
    /**
     * Captures an outbound message addressed to a device ID.
     * @param {string} deviceId
     * @param {object} msg
     * @returns {boolean}
     */
    send(deviceId, msg) {
      sent.push({ deviceId, msg });
      return true;
    },

    /**
     * Captures an outbound message sent directly to a WebSocket instance.
     * @param {object} ws - WebSocket (mock object in tests)
     * @param {object} msg
     */
    sendTo(ws, msg) {
      sentTo.push({ ws, msg });
    },

    /** Messages sent via send(deviceId, msg). */
    sent,

    /** Messages sent via sendTo(ws, msg). */
    sentTo,
  };
}

// ---------------------------------------------------------------------------
// Mock presence factory
// ---------------------------------------------------------------------------

/**
 * Creates a minimal mock presence suitable for testing Signaling in isolation.
 *
 * Internally backed by a Map<rendezvousId, Set<deviceId>>.
 * Use `_setRendezvous(rendezvousId, [...deviceIds])` to configure state.
 *
 * @returns {{ getRendezvousPeers: Function, _setRendezvous: Function }}
 */
function createMockPresence() {
  /** @type {Map<string, Set<string>>} */
  const rendezvousMap = new Map();

  return {
    /**
     * Returns the Set of device IDs registered for a given rendezvous ID.
     * Returns an empty Set for unknown IDs (mirrors real Presence behaviour).
     *
     * @param {string} rendezvousId
     * @returns {Set<string>}
     */
    getRendezvousPeers(rendezvousId) {
      return rendezvousMap.get(rendezvousId) ?? new Set();
    },

    /**
     * Test helper: populates the rendezvous map for a given rendezvous ID.
     *
     * @param {string}   rendezvousId
     * @param {string[]} deviceIds
     */
    _setRendezvous(rendezvousId, deviceIds) {
      rendezvousMap.set(rendezvousId, new Set(deviceIds));
    },
  };
}

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

/** Minimal mock WebSocket object — only needs identity for sentTo assertions. */
const MOCK_WS = { id: 'mock-ws-sender' };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Signaling', () => {
  /** @type {ReturnType<createMockGateway>} */
  let gateway;

  /** @type {ReturnType<createMockPresence>} */
  let presence;

  /** @type {Signaling} */
  let signaling;

  beforeEach(() => {
    gateway = createMockGateway();
    presence = createMockPresence();
    signaling = new Signaling(gateway, presence);
  });

  // -------------------------------------------------------------------------
  // Test 1 — Relays SDP offer to target with fromDeviceId added
  // -------------------------------------------------------------------------
  it('relays SDP offer to the target device with fromDeviceId added', () => {
    presence._setRendezvous('rv1', ['device-sender', 'device-target']);

    const msg = {
      type: 'sdp-offer',
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      sdp: 'v=0...',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);

    assert.equal(handled, true, 'handleMessage should return true for sdp-offer');

    // The target should have received exactly one message
    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 1, 'target should receive exactly one message');

    const relayed = toTarget[0].msg;

    // fromDeviceId must be added
    assert.equal(relayed.fromDeviceId, 'device-sender', 'relayed message must include fromDeviceId');

    // targetDeviceId must be stripped from the outbound message
    assert.ok(!Object.prototype.hasOwnProperty.call(relayed, 'targetDeviceId'),
      'relayed message must not contain targetDeviceId');

    // SDP payload must be preserved
    assert.equal(relayed.sdp, 'v=0...', 'relayed message must preserve the sdp field');
    assert.equal(relayed.type, 'sdp-offer', 'relayed message must preserve the type field');
  });

  // -------------------------------------------------------------------------
  // Test 2 — Relays SDP answer to target
  // -------------------------------------------------------------------------
  it('relays SDP answer to the target device', () => {
    presence._setRendezvous('rv1', ['device-sender', 'device-target']);

    const msg = {
      type: 'sdp-answer',
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      sdp: 'v=0 answer...',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);

    assert.equal(handled, true, 'handleMessage should return true for sdp-answer');

    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 1, 'target should receive exactly one message');
    assert.equal(toTarget[0].msg.type, 'sdp-answer', 'relayed type must be sdp-answer');
    assert.equal(toTarget[0].msg.fromDeviceId, 'device-sender', 'relayed message must include fromDeviceId');
  });

  // -------------------------------------------------------------------------
  // Test 3 — Relays ICE candidate to target
  // -------------------------------------------------------------------------
  it('relays ICE candidate to the target device', () => {
    presence._setRendezvous('rv1', ['device-sender', 'device-target']);

    const msg = {
      type: 'ice-candidate',
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      candidate: { candidate: 'candidate:0 1 UDP 123 192.168.1.1 5000 typ host', sdpMid: '0' },
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);

    assert.equal(handled, true, 'handleMessage should return true for ice-candidate');

    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 1, 'target should receive exactly one message');

    const relayed = toTarget[0].msg;
    assert.equal(relayed.type, 'ice-candidate', 'relayed type must be ice-candidate');
    assert.equal(relayed.fromDeviceId, 'device-sender', 'relayed message must include fromDeviceId');
    assert.deepEqual(relayed.candidate, msg.candidate, 'candidate object must be preserved');
    assert.ok(!Object.prototype.hasOwnProperty.call(relayed, 'targetDeviceId'),
      'relayed message must not contain targetDeviceId');
  });

  // -------------------------------------------------------------------------
  // Test 4 — Rejects when sender not in rendezvous
  // -------------------------------------------------------------------------
  it('sends ERROR when sender is not in the rendezvous', () => {
    // Only device-target is in the rendezvous — sender is not
    presence._setRendezvous('rv1', ['device-target']);

    const msg = {
      type: 'sdp-offer',
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      sdp: 'v=0...',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);

    assert.equal(handled, true, 'handleMessage should return true (handled, even though rejected)');

    // No message should have been relayed to the target
    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 0, 'no message should be relayed to target on sender rejection');

    // An ERROR must have been sent back to the sender via sendTo(ws, ...)
    assert.equal(gateway.sentTo.length, 1, 'one error message should be sent back via sendTo');
    const errorMsg = gateway.sentTo[0].msg;
    assert.equal(errorMsg.type, 'error', 'error message type must be "error"');
    assert.ok(gateway.sentTo[0].ws === MOCK_WS, 'error must be sent to the sender ws');

    // Error message must mention "rendezvous"
    assert.match(errorMsg.message, /not.*rendezvous/i,
      'error message must indicate sender is not in the rendezvous');
  });

  // -------------------------------------------------------------------------
  // Test 5 — Rejects when target not in rendezvous
  // -------------------------------------------------------------------------
  it('sends ERROR when target is not in the rendezvous', () => {
    // Only device-sender is in the rendezvous — target is absent
    presence._setRendezvous('rv1', ['device-sender']);

    const msg = {
      type: 'sdp-offer',
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      sdp: 'v=0...',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);

    assert.equal(handled, true, 'handleMessage should return true (handled, even though rejected)');

    // No message should have been relayed to the target
    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 0, 'no message should be relayed to target on target rejection');

    // An ERROR must be sent back via sendTo(ws, ...)
    assert.equal(gateway.sentTo.length, 1, 'one error message should be sent back via sendTo');
    const errorMsg = gateway.sentTo[0].msg;
    assert.equal(errorMsg.type, 'error', 'error message type must be "error"');
  });

  // -------------------------------------------------------------------------
  // Test 6 — Returns false for non-signaling message types
  // -------------------------------------------------------------------------
  it('returns false for message types that are not signaling types', () => {
    const nonSignalingTypes = [
      { type: 'auth', deviceId: 'd', publicKey: 'k', signature: 's', timestamp: 1 },
      { type: 'register-rendezvous', rendezvousIds: ['rv1'] },
      { type: 'relay-bind', transferId: 't', targetDeviceId: 'd', rendezvousId: 'rv1' },
      { type: 'ping' },
    ];

    for (const msg of nonSignalingTypes) {
      const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);
      assert.equal(handled, false, `handleMessage should return false for type "${msg.type}"`);
    }

    // No messages should have been sent for any non-signaling type
    assert.equal(gateway.sent.length, 0, 'no messages should be sent for non-signaling types');
    assert.equal(gateway.sentTo.length, 0, 'no error messages should be sent for non-signaling types');
  });

  // -------------------------------------------------------------------------
  // Test 7 — Relays Beam transfer-init, transfer-accept, transfer-reject
  // -------------------------------------------------------------------------
  it('relays transfer-init (Beam E2E handshake) to the target', () => {
    presence._setRendezvous('rv1', ['device-sender', 'device-target']);

    const msg = {
      type: 'transfer-init',
      v: 1,
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      transferId: 'abc123',
      kind: 'clipboard',
      ephPkA: 'pk-a-b64url',
      salt: 'salt-b64url',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);
    assert.equal(handled, true);

    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 1);
    const relayed = toTarget[0].msg;
    assert.equal(relayed.type, 'transfer-init');
    assert.equal(relayed.fromDeviceId, 'device-sender');
    assert.equal(relayed.transferId, 'abc123');
    assert.equal(relayed.kind, 'clipboard');
    assert.equal(relayed.ephPkA, 'pk-a-b64url');
    assert.equal(relayed.salt, 'salt-b64url');
    assert.ok(!Object.prototype.hasOwnProperty.call(relayed, 'targetDeviceId'));
  });

  it('relays transfer-accept (Beam E2E handshake) to the target', () => {
    presence._setRendezvous('rv1', ['device-sender', 'device-target']);

    const msg = {
      type: 'transfer-accept',
      v: 1,
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      transferId: 'abc123',
      ephPkB: 'pk-b-b64url',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);
    assert.equal(handled, true);

    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 1);
    const relayed = toTarget[0].msg;
    assert.equal(relayed.type, 'transfer-accept');
    assert.equal(relayed.fromDeviceId, 'device-sender');
    assert.equal(relayed.ephPkB, 'pk-b-b64url');
  });

  it('relays transfer-reject with errorCode preserved', () => {
    presence._setRendezvous('rv1', ['device-sender', 'device-target']);

    const msg = {
      type: 'transfer-reject',
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      transferId: 'abc123',
      errorCode: 'TIMEOUT',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);
    assert.equal(handled, true);

    const toTarget = gateway.sent.filter((e) => e.deviceId === 'device-target');
    assert.equal(toTarget.length, 1);
    assert.equal(toTarget[0].msg.errorCode, 'TIMEOUT');
  });

  it('rejects transfer-init when sender is not in rendezvous', () => {
    presence._setRendezvous('rv1', ['device-target']);

    const msg = {
      type: 'transfer-init',
      v: 1,
      rendezvousId: 'rv1',
      targetDeviceId: 'device-target',
      transferId: 'abc123',
      kind: 'file',
      ephPkA: 'pk-a',
      salt: 'salt',
    };

    const handled = signaling.handleMessage('device-sender', msg, MOCK_WS);
    assert.equal(handled, true);
    assert.equal(gateway.sent.length, 0, 'no relay when sender not in rendezvous');
    assert.equal(gateway.sentTo.length, 1, 'error sent back to sender');
    assert.equal(gateway.sentTo[0].msg.type, 'error');
  });
});
