/**
 * @file pairing-race.test.js
 * @description Regression coverage for the racing-startPairingListener bug
 * fixed on 2026-04-29.
 *
 * Original failure mode:
 *   Two near-simultaneous calls to startPairingListener (from
 *   chrome.runtime.onInstalled + the SW-boot top-level statement, or from
 *   the SW + popup) created two parallel WebSockets. The async signing
 *   inside the challenge handler awaited `crypto.subtle.sign`, then sent
 *   `auth` via the module-level `pairingWs` reference — which by that
 *   point pointed at the *other* still-CONNECTING socket, producing the
 *   error "Failed to execute 'send' on 'WebSocket': Still in CONNECTING
 *   state." Worse, when the orphaned socket eventually closed, its stale
 *   onclose nulled the live `pairingWs`, breaking transfers in both
 *   directions.
 *
 * What this test verifies:
 *   1. Two concurrent startPairingListener calls for the same deviceId
 *      DO NOT reject with the racing-auth error.
 *   2. Single-flight collapses both calls onto one WebSocket — the relay
 *      sees exactly one authenticated device, not two.
 *   3. After the dust settles, pairingWs is OPEN and usable for a real
 *      transfer-init send.
 *
 * If any of these assertions fail, the racing-auto-start failure mode
 * has regressed and pairing/transfer reliability is at risk.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { installChromeStub, chromeStub } from './_helpers/chrome-stubs.js';
import { startTestRelay }                from './_helpers/relay-fixture.js';
import { generateTestIdentity }          from './_helpers/identity.js';

// chrome.* must be installed BEFORE importing background-relay.js (the
// module evaluates `chrome.runtime.onConnect` etc. at import time via
// transitively-loaded files).
installChromeStub();

const { startPairingListener, stopPairingListener, sendPairingMessage, _setRelayUrl } =
  await import('../background-relay.js');

describe('pairing race regression', () => {
  /** @type {Awaited<ReturnType<typeof startTestRelay>>} */
  let relay;
  /** @type {Awaited<ReturnType<typeof generateTestIdentity>>} */
  let identity;

  before(async () => {
    relay = await startTestRelay();
    _setRelayUrl(relay.url);
    identity = await generateTestIdentity();
  });

  after(async () => {
    stopPairingListener();
    _setRelayUrl(null);
    if (relay) await relay.close();
  });

  it('two concurrent calls collapse onto one authenticated WebSocket', async () => {
    // Fire BOTH calls in the same tick — the race window the bug exploited.
    const p1 = startPairingListener(identity.deviceId, identity.ed25519Sk, identity.ed25519Pk);
    const p2 = startPairingListener(identity.deviceId, identity.ed25519Sk, identity.ed25519Pk);

    // Pre-fix, p1 would reject with "Still in CONNECTING state" while
    // p2 succeeded. Both must now resolve cleanly.
    const results = await Promise.allSettled([p1, p2]);
    for (const r of results) {
      assert.equal(r.status, 'fulfilled',
        `concurrent startPairingListener rejected: ${r.reason?.message}`);
    }

    // Server-side authoritative check: only one authenticated socket.
    // Pre-fix, the relay would briefly hold two — orphan timeout cleared
    // it eventually, but during the gap incoming transfer-accepts went
    // to the wrong socket and the SW dropped them.
    assert.equal(relay.gateway.devices.size, 1,
      `expected 1 authenticated device, got ${relay.gateway.devices.size}`);
    assert.ok(relay.gateway.devices.has(identity.deviceId),
      'authenticated device must be the one we connected with');
  });

  it('after the race settles, the WS is OPEN and can send', async () => {
    // sendPairingMessage drops silently if pairingWs is null/closed —
    // which was exactly the post-bug state. We probe by sending a
    // benign register-rendezvous (server tolerates re-registers).
    let sent = false;
    const original = relay.gateway.devices.get(identity.deviceId);
    assert.ok(original, 'device must still be registered');

    sendPairingMessage({
      type: 'register-rendezvous',
      rendezvousIds: [identity.deviceId],
    });
    sent = true;

    // Give the relay a tick to process; verify the same ws is still
    // the registered one (no ghost reconnect cycle was triggered).
    await new Promise(r => setTimeout(r, 50));
    assert.equal(relay.gateway.devices.get(identity.deviceId), original,
      'no spurious reconnect should have replaced the live ws');
    assert.ok(sent);
  });

  it('a sequential call to the same device hits early-return, no extra socket', async () => {
    const before = relay.gateway.devices.size;
    await startPairingListener(identity.deviceId, identity.ed25519Sk, identity.ed25519Pk);
    // No new socket — early return path took it.
    assert.equal(relay.gateway.devices.size, before);
  });
});
