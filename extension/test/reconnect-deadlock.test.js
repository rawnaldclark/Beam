/**
 * @file reconnect-deadlock.test.js
 * @description Regression tests for the pairing-relay connect lifecycle.
 *
 * Bug 1 (deadlock): _doConnect's promise only settled on auth-ok / auth-fail /
 * error — NOT on a plain socket close before auth-ok. A relay that accepted the
 * socket then closed it (restart, mid-handshake drop) left the promise, and
 * therefore _inflightConnect, hung forever; the single-flight guard in
 * startPairingListener then returned that hung promise for every future
 * reconnect, so the extension stayed permanently offline.
 *
 * Bug 2 (auth-fail storm): a rejected auth still triggered the 2s onclose
 * auto-reconnect with the same credentials, forever.
 *
 * Both are exercised with a controllable fake WebSocket installed as the global
 * before importing background-relay.js (which resolves `WebSocket` at call time).
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { installChromeStub } from './_helpers/chrome-stubs.js';
import { generateTestIdentity } from './_helpers/identity.js';

installChromeStub();

/** Controllable stand-in for the browser WebSocket. */
class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = FakeWebSocket.CONNECTING;
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;
    FakeWebSocket.instances.push(this);
  }

  send() { /* no-op */ }

  close(code = 1000, reason = '') { this._fireClose(code, reason); }

  /** Simulate the relay dropping the socket. */
  _fireClose(code = 1006, reason = '') {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    if (this.onclose) this.onclose({ code, reason });
  }

  /** Feed a JSON control message to the connect handler. */
  _deliver(obj) {
    if (this.onmessage) this.onmessage({ data: JSON.stringify(obj) });
  }
}

globalThis.WebSocket = FakeWebSocket;

const relay = await import('../background-relay.js');

/** Poll `pred` until true or timeout. */
function waitFor(pred, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      if (pred()) return resolve();
      if (Date.now() - start > timeoutMs) return reject(new Error('waitFor timed out'));
      setTimeout(tick, 5);
    };
    tick();
  });
}

/** Resolve to 'resolved' | 'rejected' | 'hung' for a promise within `ms`. */
function outcomeWithin(p, ms) {
  return Promise.race([
    p.then(() => 'resolved', () => 'rejected'),
    new Promise((r) => setTimeout(() => r('hung'), ms)),
  ]);
}

describe('pairing-relay connect lifecycle', () => {
  beforeEach(() => {
    FakeWebSocket.instances.length = 0;
    relay.stopPairingListener();
  });

  afterEach(() => {
    // Cancel any live socket + suppress the pending auto-reconnect timer.
    relay.stopPairingListener();
  });

  it('a socket close before auth-ok settles the connect instead of hanging', async () => {
    const id = await generateTestIdentity();

    const p = relay.startPairingListener(id.deviceId, id.ed25519Sk, id.ed25519Pk);
    p.catch(() => {}); // pre-auth close rejects it

    // _doConnect delays 100ms + imports keys before constructing the socket.
    await waitFor(() => FakeWebSocket.instances.length >= 1);
    FakeWebSocket.instances[0]._fireClose(1006, 'server gone before auth');

    // Pre-fix: the promise never settled (deadlock). Post-fix: it rejects.
    const outcome = await outcomeWithin(p, 1000);
    assert.equal(outcome, 'rejected', 'pre-auth close must settle (reject) the connect, not hang');
  });

  it('after a settled pre-auth close, a fresh connect opens a NEW socket (guard cleared)', async () => {
    const id = await generateTestIdentity();

    const p1 = relay.startPairingListener(id.deviceId, id.ed25519Sk, id.ed25519Pk);
    p1.catch(() => {});
    await waitFor(() => FakeWebSocket.instances.length >= 1);
    FakeWebSocket.instances[0]._fireClose(1006, 'server gone');
    await p1.catch(() => {}); // let the .finally clear _inflightConnect

    const p2 = relay.startPairingListener(id.deviceId, id.ed25519Sk, id.ed25519Pk);
    p2.catch(() => {});
    // Pre-fix the single-flight guard returned the hung p1 and no socket opened.
    await waitFor(() => FakeWebSocket.instances.length >= 2);
    assert.ok(FakeWebSocket.instances.length >= 2, 'a new socket must open after a pre-auth close');
  });

  it('auth-fail does not trigger the auto-reconnect storm', async () => {
    const id = await generateTestIdentity();

    const p = relay.startPairingListener(id.deviceId, id.ed25519Sk, id.ed25519Pk);
    p.catch(() => {});
    await waitFor(() => FakeWebSocket.instances.length >= 1);
    const ws1 = FakeWebSocket.instances[0];

    // Relay rejects auth, then closes the socket.
    ws1._deliver({ type: 'auth-fail', reason: 'revoked key' });
    ws1._fireClose(1008, 'auth failed');

    // Give the (suppressed) 2s auto-reconnect window time to NOT fire.
    await new Promise((r) => setTimeout(r, 2200));
    assert.equal(FakeWebSocket.instances.length, 1, 'auth-fail must not auto-reconnect with the same credentials');
  });
});
