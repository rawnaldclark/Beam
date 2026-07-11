/**
 * router.test.js — TDD tests for the production message router.
 *
 * The router is the `gateway.onMessage()` dispatcher extracted from server.js so
 * that the REAL routing can be exercised in a test. Previously the dispatch
 * switch lived inline in server.js and was hand-duplicated in integration.test.js,
 * so a routing bug in server.js could never be caught — that is exactly how
 * peer-ping/peer-pong/beam-v2-* ended up silently dropped in production despite
 * being valid SIGNALING_TYPES the Signaling module already relays.
 *
 * These tests drive a peer-ping and a beam-v2 rotation message through the real
 * router + real Signaling (mocking only the gateway/presence transport, in the
 * same style as signaling.test.js) and assert they reach the target device.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Signaling } from '../src/signaling.js';
import { createMessageRouter } from '../src/router.js';

/** Mock gateway: `sent` captures every send(deviceId, msg). */
function createMockGateway() {
  const sent = [];
  const sentTo = [];
  return {
    send(deviceId, msg) { sent.push({ deviceId, msg }); return true; },
    sendTo(ws, msg) { sentTo.push({ ws, msg }); },
    sent,
    sentTo,
  };
}

/** Mock presence: rendezvous membership + no-op heartbeat/register capture. */
function createMockPresence() {
  const rendezvousMap = new Map();
  const registered = [];
  return {
    getRendezvousPeers(id) { return rendezvousMap.get(id) ?? new Set(); },
    _setRendezvous(id, ids) { rendezvousMap.set(id, new Set(ids)); },
    register(deviceId, ids) { registered.push({ deviceId, ids }); },
    heartbeat() {},
    registered,
  };
}

const MOCK_WS = { id: 'mock-ws-sender', readyState: 1, OPEN: 1 };

describe('createMessageRouter', () => {
  let gateway, presence, signaling, dataRelay, rateLimiter, route;

  beforeEach(() => {
    gateway = createMockGateway();
    presence = createMockPresence();
    signaling = new Signaling(gateway, presence);
    dataRelay = { calls: [], handleMessage(...a) { this.calls.push(a); } };
    rateLimiter = { allowMessage: () => true, isRelayDisabled: () => false };
    route = createMessageRouter({
      rateLimiter, wsToConnId: new Map(), presence, signaling, dataRelay, gateway,
    });
  });

  it('routes peer-ping to the target device via signaling', () => {
    presence._setRendezvous('rv1', ['A', 'B']);

    route('A', { type: 'peer-ping', rendezvousId: 'rv1', targetDeviceId: 'B', nonce: 'abc' }, MOCK_WS);

    const relayed = gateway.sent.find((s) => s.deviceId === 'B' && s.msg.type === 'peer-ping');
    assert.ok(relayed, 'peer-ping must be relayed to target B (was silently dropped by the stale switch)');
    assert.equal(relayed.msg.nonce, 'abc', 'nonce must be preserved');
    assert.equal(relayed.msg.fromDeviceId, 'A', 'fromDeviceId must be added');
  });

  it('routes peer-pong to the target device via signaling', () => {
    presence._setRendezvous('rv1', ['A', 'B']);

    route('B', { type: 'peer-pong', rendezvousId: 'rv1', targetDeviceId: 'A', nonce: 'abc' }, MOCK_WS);

    const relayed = gateway.sent.find((s) => s.deviceId === 'A' && s.msg.type === 'peer-pong');
    assert.ok(relayed, 'peer-pong must be relayed to target A');
    assert.equal(relayed.msg.nonce, 'abc');
  });

  it('routes beam-v2-rotate-init to the target device via signaling', () => {
    presence._setRendezvous('rv1', ['A', 'B']);

    route('A', { type: 'beam-v2-rotate-init', rendezvousId: 'rv1', targetDeviceId: 'B', generation: 2 }, MOCK_WS);

    const relayed = gateway.sent.find((s) => s.deviceId === 'B' && s.msg.type === 'beam-v2-rotate-init');
    assert.ok(relayed, 'beam-v2-rotate-init must be relayed so key rotation can complete');
    assert.equal(relayed.msg.generation, 2, 'rotation payload must be preserved');
  });

  it('still routes register-rendezvous to presence.register', () => {
    route('A', { type: 'register-rendezvous', rendezvousIds: ['rv1'] }, MOCK_WS);
    assert.equal(presence.registered.length, 1, 'register-rendezvous must reach presence.register');
    assert.deepEqual(presence.registered[0].ids, ['rv1']);
  });

  it('still routes relay-bind to dataRelay.handleMessage', () => {
    route('A', { type: 'relay-bind', transferId: 'x', targetDeviceId: 'B' }, MOCK_WS);
    assert.equal(dataRelay.calls.length, 1, 'relay-bind must reach dataRelay');
  });
});
