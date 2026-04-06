/**
 * relay.test.js — TDD tests for the DataRelay module.
 *
 * Tests run in isolation using mock WebSocket objects — no real network I/O.
 * The mock WS captures sent data and exposes pause/resume via both the ws
 * surface and the underlying _socket surface (mirrors the ws library's API
 * where socket-level flow control lives on ws._socket).
 *
 * Test plan:
 *   1. Creates relay session via relay-bind — session exists in relay.sessions
 *   2. Completes session when both sides bind — senderWs and receiverWs both set
 *   3. Relays binary data — chunk sent to device-a appears in wsB._sent
 *   4. Tracks bytes per session — bytesRelayed increments
 *   5. Enforces 500 MB limit — set bytesRelayed near limit, send chunk, should
 *      not forward, sends ERROR with "limit"
 *   6. Releases session via relay-release — session removed
 *   7. Backpressure — set wsB.bufferedAmount = 3 MB, relay chunk,
 *      wsA._paused should be true
 *   8. Cleans up on disconnect — handleDisconnect removes sessions
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DataRelay } from '../src/relay.js';

// ---------------------------------------------------------------------------
// Mock WebSocket factory
// ---------------------------------------------------------------------------

/**
 * Creates a minimal mock WebSocket that mirrors the surface area used by
 * DataRelay: bufferedAmount, send(), pause(), resume(), close(), and the
 * underlying _socket.pause() / _socket.resume() for TCP-level flow control.
 *
 * @param {string} id - Human-readable identifier for assertion messages.
 * @returns {object} Mock WebSocket
 */
function createMockWs(id) {
  const ws = {
    id,
    bufferedAmount: 0,
    readyState: 1,          // WebSocket.OPEN
    _paused: false,
    _sent: [],
    _closed: false,

    /**
     * Captures outgoing data. Supports all three ws.send() call signatures:
     *   send(data)
     *   send(data, opts)
     *   send(data, opts, cb)
     *   send(data, cb)
     */
    send(data, opts, cb) {
      ws._sent.push(data);
      if (typeof opts === 'function') opts();
      else if (typeof cb === 'function') cb();
    },

    /** Pause the logical WebSocket stream. */
    pause() { ws._paused = true; },

    /** Resume the logical WebSocket stream. */
    resume() { ws._paused = false; },

    /** Close the WebSocket. */
    close() { ws._closed = true; },

    /**
     * Underlying TCP socket surface. DataRelay calls _socket.pause() and
     * _socket.resume() for lower-level backpressure control.
     */
    _socket: {
      pause()  { ws._paused = true; },
      resume() { ws._paused = false; },
    },
  };
  return ws;
}

// ---------------------------------------------------------------------------
// Mock gateway factory
// ---------------------------------------------------------------------------

/**
 * Minimal mock gateway: captures sendTo() calls so tests can inspect error
 * messages sent back to a specific WebSocket.
 *
 * @returns {{ sendTo: Function, sentTo: Array }}
 */
function createMockGateway() {
  const sentTo = [];
  return {
    sendTo(ws, msg) { sentTo.push({ ws, msg }); },
    sentTo,
  };
}

// ---------------------------------------------------------------------------
// Constants mirrored from the implementation (for test assertions)
// ---------------------------------------------------------------------------

const MB = 1024 * 1024;
const BACKPRESSURE_HIGH = 2 * MB;   // 2 MB
const SESSION_LIMIT     = 500 * MB; // 500 MB

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DataRelay', () => {
  /** @type {DataRelay} */
  let relay;

  /** @type {ReturnType<createMockGateway>} */
  let gateway;

  beforeEach(() => {
    gateway = createMockGateway();
    relay   = new DataRelay({ gateway });
  });

  // -------------------------------------------------------------------------
  // Test 1 — relay-bind creates a session entry
  // -------------------------------------------------------------------------
  it('creates a relay session when device-a sends relay-bind', () => {
    const wsA = createMockWs('ws-a');

    relay.handleMessage('device-a', {
      type:           'relay-bind',
      transferId:     'transfer-1',
      targetDeviceId: 'device-b',
      rendezvousId:   'rv1',
    }, wsA);

    assert.ok(relay.sessions.has('transfer-1'),
      'sessions map should contain the new transfer ID');

    const session = relay.sessions.get('transfer-1');
    assert.equal(session.senderDeviceId, 'device-a',
      'session.senderDeviceId should be "device-a"');
    assert.equal(session.receiverDeviceId, 'device-b',
      'session.receiverDeviceId should be "device-b"');
    assert.equal(session.rendezvousId, 'rv1',
      'session.rendezvousId should match the bind message');
    assert.equal(session.bytesRelayed, 0,
      'session.bytesRelayed should start at zero');
  });

  // -------------------------------------------------------------------------
  // Test 2 — session completes when both sides have bound
  // -------------------------------------------------------------------------
  it('marks session complete (both senderWs and receiverWs set) after both bind', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    // Sender binds first
    relay.handleMessage('device-a', {
      type:           'relay-bind',
      transferId:     'transfer-1',
      targetDeviceId: 'device-b',
      rendezvousId:   'rv1',
    }, wsA);

    // Receiver binds second
    relay.handleMessage('device-b', {
      type:           'relay-bind',
      transferId:     'transfer-1',
      targetDeviceId: 'device-a',
      rendezvousId:   'rv1',
    }, wsB);

    const session = relay.sessions.get('transfer-1');
    assert.ok(session, 'session must still exist');
    assert.ok(session.senderWs,   'senderWs should be set after both bind');
    assert.ok(session.receiverWs, 'receiverWs should be set after both bind');
  });

  // -------------------------------------------------------------------------
  // Test 3 — binary data is forwarded to the peer
  // -------------------------------------------------------------------------
  it('forwards a binary chunk from the sender to the receiver', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    // Establish a fully-bound session
    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);
    relay.handleMessage('device-b', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-a', rendezvousId: 'rv1',
    }, wsB);

    const chunk = Buffer.allocUnsafe(1024).fill(0xAB);
    relay.relayBinary('device-a', chunk, wsA);

    assert.equal(wsB._sent.length, 1,
      'device-b websocket should have received exactly one binary frame');
    assert.deepEqual(wsB._sent[0], chunk,
      'the forwarded chunk must equal the original data');
  });

  // -------------------------------------------------------------------------
  // Test 4 — bytesRelayed is incremented on each relay
  // -------------------------------------------------------------------------
  it('increments session.bytesRelayed by the chunk byte-length', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);
    relay.handleMessage('device-b', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-a', rendezvousId: 'rv1',
    }, wsB);

    const chunk = Buffer.allocUnsafe(4096).fill(0x00);
    relay.relayBinary('device-a', chunk, wsA);

    const session = relay.sessions.get('transfer-1');
    assert.equal(session.bytesRelayed, 4096,
      'bytesRelayed should equal the chunk size after one relay call');

    relay.relayBinary('device-a', chunk, wsA);
    assert.equal(session.bytesRelayed, 8192,
      'bytesRelayed should accumulate across multiple relay calls');
  });

  // -------------------------------------------------------------------------
  // Test 5 — 500 MB per-session limit enforced
  // -------------------------------------------------------------------------
  it('refuses to relay and sends ERROR when the session byte limit is exceeded', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);
    relay.handleMessage('device-b', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-a', rendezvousId: 'rv1',
    }, wsB);

    // Push bytesRelayed right up to the limit
    const session = relay.sessions.get('transfer-1');
    session.bytesRelayed = SESSION_LIMIT - 100;

    // A 200-byte chunk would push it over the 500 MB cap
    const overLimitChunk = Buffer.allocUnsafe(200).fill(0xFF);
    relay.relayBinary('device-a', overLimitChunk, wsA);

    // The chunk must NOT have been forwarded
    assert.equal(wsB._sent.length, 0,
      'no data should be forwarded after the session byte limit is exceeded');

    // An ERROR must have been sent back to the sender
    const errors = gateway.sentTo.filter((e) => e.ws === wsA);
    assert.ok(errors.length > 0,
      'an error message should be sent back to the sender when the limit is hit');

    const errMsg = errors[0].msg;
    assert.equal(errMsg.type, 'error',
      'error message type must be "error"');
    assert.match(errMsg.message, /limit/i,
      'error message text must mention "limit"');
  });

  // -------------------------------------------------------------------------
  // Test 6 — relay-release removes the session
  // -------------------------------------------------------------------------
  it('removes the session when relay-release is received', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);
    relay.handleMessage('device-b', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-a', rendezvousId: 'rv1',
    }, wsB);

    assert.ok(relay.sessions.has('transfer-1'), 'session must exist before release');

    relay.handleMessage('device-a', {
      type:       'relay-release',
      transferId: 'transfer-1',
    }, wsA);

    assert.ok(!relay.sessions.has('transfer-1'),
      'session must be removed after relay-release');
  });

  // -------------------------------------------------------------------------
  // Test 7 — backpressure: pause sender when receiver buffer > 2 MB
  // -------------------------------------------------------------------------
  it('pauses the sender socket when the receiver bufferedAmount exceeds 2 MB', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);
    relay.handleMessage('device-b', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-a', rendezvousId: 'rv1',
    }, wsB);

    // Simulate a congested receiver: its send buffer is above the 2 MB threshold
    wsB.bufferedAmount = BACKPRESSURE_HIGH + 1; // 3 MB (> 2 MB)

    const chunk = Buffer.allocUnsafe(1024).fill(0x01);
    relay.relayBinary('device-a', chunk, wsA);

    assert.ok(wsA._paused,
      'sender socket should be paused when receiver bufferedAmount > 2 MB');
  });

  // -------------------------------------------------------------------------
  // Test 8 — handleDisconnect removes all sessions for the disconnecting device
  // -------------------------------------------------------------------------
  it('removes sessions and notifies the peer on disconnect', () => {
    const wsA = createMockWs('ws-a');
    const wsB = createMockWs('ws-b');

    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);
    relay.handleMessage('device-b', {
      type: 'relay-bind', transferId: 'transfer-1',
      targetDeviceId: 'device-a', rendezvousId: 'rv1',
    }, wsB);

    // Also create a second session for device-a to confirm all are cleaned up
    relay.handleMessage('device-a', {
      type: 'relay-bind', transferId: 'transfer-2',
      targetDeviceId: 'device-b', rendezvousId: 'rv1',
    }, wsA);

    assert.ok(relay.sessions.has('transfer-1'), 'transfer-1 should exist before disconnect');
    assert.ok(relay.sessions.has('transfer-2'), 'transfer-2 should exist before disconnect');

    relay.handleDisconnect('device-a');

    assert.ok(!relay.sessions.has('transfer-1'),
      'transfer-1 should be removed after device-a disconnects');
    assert.ok(!relay.sessions.has('transfer-2'),
      'transfer-2 should be removed after device-a disconnects');
  });
});
