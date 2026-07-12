/**
 * @file background-relay.js
 * @description Pairing WebSocket relay for the service worker context.
 *
 * This module manages the WebSocket connection to the relay server during the
 * pairing ceremony.  It lives in the service worker (not the popup) so that
 * the connection survives the popup closing when the user switches to their
 * phone to scan the QR code.
 *
 * Flow:
 *   1. Popup calls startPairingListener() via chrome.runtime.sendMessage.
 *   2. SW opens WebSocket, authenticates with Ed25519, registers rendezvous.
 *   3. When Android sends PAIRING_REQUEST, SW stores it in chrome.storage.session.
 *   4. SW also tries to notify the popup directly via chrome.runtime.sendMessage.
 *   5. When the popup reopens, it reads from chrome.storage.session.
 *
 * Security:
 *   - Private keys are passed as arrays (already stored in chrome.storage.local).
 *   - Web Crypto Ed25519 is available in service workers (Chrome 113+).
 *   - The WebSocket connection is TLS-encrypted (wss://).
 *
 * @module background-relay
 */

import { ensureTransport, _resetTransportSingleton } from './crypto/beam-v2-wiring.js';
import {
  ensureConnectionAuthority,
  getConnectionAuthority,
  installPopupBroadcaster,
} from './connection/connection-authority-wiring.js';
import { computeRendezvousIds } from './shared/rendezvous.js';

/**
 * Builds the COMPLETE rendezvous set to register: own deviceId + every paired
 * peer's deviceId. The relay's presence.register REPLACES membership, so we
 * MUST send the full set every time — own-only (or peers-only) drops rooms and
 * breaks routing. See shared/rendezvous.js.
 *
 * @param {string} ownDeviceId
 * @returns {Promise<string[]>}
 */
async function currentRendezvousIds(ownDeviceId) {
  const { pairedDevices = [] } = await chrome.storage.local.get('pairedDevices');
  return computeRendezvousIds(ownDeviceId, pairedDevices.map((d) => d.deviceId));
}

/**
 * Lazy accessor for the Beam v2 transport singleton. The hooks intentionally
 * close over `sendBinary` / `sendPairingMessage` (defined later in this
 * module) and over `deliverIncomingClipboard` / `deliverIncomingFile` (the
 * existing user-visible delivery functions, also defined below). The
 * function-style indirection lets us register hooks before those symbols
 * are evaluated.
 */
function getTransport() {
  return ensureTransport({
    sendBinary,
    sendJson: sendPairingMessage,
    onClipboardReceived: (content, fromDeviceId) => deliverIncomingClipboard(content, fromDeviceId),
    onFileReceived: (args) => deliverIncomingFile(args),
  });
}

/**
 * Public surface used by background.js for SEND_CLIPBOARD / SEND_FILE
 * handlers. Returns the singleton transport so callers can drive sendClipboard
 * / sendFile / rotateKAB without re-importing the wiring module.
 */
export function getBeamV2Transport() {
  return getTransport();
}

const DEFAULT_RELAY_URL = 'wss://zaptransfer-relay.fly.dev';

/**
 * Active relay URL. Defaults to the production endpoint; tests override it
 * via `_setRelayUrl()` to point at a locally-spun relay on a random port.
 * Production callers never touch this — it is a test-only seam.
 *
 * @type {string}
 */
let RELAY_URL = DEFAULT_RELAY_URL;

/**
 * TEST-ONLY: redirect the relay URL. No production code path calls this.
 * Exported so the Node test harness in `extension/test/` can drive the SW
 * code against a local ws://localhost relay fixture.
 *
 * @param {string|null} url - New relay URL, or null to restore the default.
 */
export function _setRelayUrl(url) {
  RELAY_URL = url ?? DEFAULT_RELAY_URL;
}

/** @type {WebSocket|null} Active pairing WebSocket connection. */
let pairingWs = null;

/**
 * Caller-injected restart function used by Rung 2/3 of the recovery ladder.
 * Set by `background.js` at SW boot via {@link setRestartHook}, where it
 * resolves to `autoStartRelayIfPaired`. We can't import that directly because
 * `background.js` already imports from this module — the indirection inverts
 * the dependency without introducing a circular import.
 *
 * @type {(() => Promise<void>) | null}
 */
let _restartHook = null;

/**
 * Inject the SW restart function (typically `autoStartRelayIfPaired`). Called
 * once at SW boot from `background.js` immediately after the import resolves.
 * Safe to call multiple times — overwrites the previous hook. No-op if `fn`
 * is not a function (defensive: a typo at the call site shouldn't crash boot).
 *
 * @param {() => Promise<void>} fn
 */
export function setRestartHook(fn) {
  if (typeof fn === 'function') _restartHook = fn;
}

/** @type {string|null} Device ID for the current pairing session. */
let pairingDeviceId = null;

/**
 * Single-flight guard: when a connect is in progress for `_inflightDeviceId`,
 * concurrent callers receive the same `_inflightConnect` promise instead of
 * each opening their own WebSocket. Without this, two near-simultaneous
 * starts (e.g. SW-boot top-level + onInstalled, or SW + popup) created
 * orphan sockets whose stale handlers nulled out the live successor.
 *
 * @type {Promise<void>|null}
 */
let _inflightConnect = null;
/** @type {string|null} */
let _inflightDeviceId = null;

/**
 * Timestamp of the last pong received from the relay server. Updated every
 * time we receive a `{ type: "pong" }` response to our heartbeat ping.
 *
 * The heartbeat interval checks this value: if more than
 * ZOMBIE_DETECTION_MS has elapsed since the last pong, the WebSocket is
 * declared a zombie (readyState reports OPEN but the TCP connection is
 * dead) and is force-closed. Auto-reconnect fires from the onclose handler.
 *
 * This is the Chrome equivalent of OkHttp's pingInterval — the browser
 * WebSocket API has no built-in dead-connection detection, so we must
 * implement it at the application layer.
 */
let _lastPongAt = Date.now();
const ZOMBIE_DETECTION_MS = 60_000; // 2 missed ping/pong cycles (25s each) + margin

/**
 * Watchdog for the connect/auth handshake. If the relay accepts the socket
 * but never completes challenge -> auth-ok (silent server, dropped
 * mid-handshake), the connect promise would hang forever — and with it
 * `_inflightConnect`, whose single-flight guard would then block every future
 * reconnect (permanent offline). The watchdog rejects the connect so the guard
 * clears and auto-reconnect can open a fresh socket.
 */
const AUTH_TIMEOUT_MS = 15_000;

/**
 * Start listening for a pairing request from an Android device.
 *
 * Opens a WebSocket to the relay server, authenticates using Ed25519
 * challenge-response, and registers the device ID as a rendezvous point.
 * When a PAIRING_REQUEST message arrives, it is stored in
 * chrome.storage.session and (if possible) forwarded to the popup.
 *
 * @param {string}   deviceId   - Our device ID (rendezvous target).
 * @param {number[]} ed25519Sk  - Ed25519 private key as PKCS8 byte array.
 * @param {number[]} ed25519Pk  - Ed25519 public key as raw byte array.
 * @returns {Promise<void>} Resolves on successful auth + rendezvous registration.
 * @throws {Error} On WebSocket error, auth failure, or crypto failure.
 */
export async function startPairingListener(deviceId, ed25519Sk, ed25519Pk) {
  console.log('[Beam SW] startPairingListener called for', deviceId);

  // Single-flight: a concurrent caller for the same device awaits the
  // existing connect instead of opening a parallel socket. This is the
  // primary defence against the racing-auto-start failure mode where
  // onInstalled + SW-boot top-level both invoked us simultaneously.
  if (_inflightConnect && _inflightDeviceId === deviceId) {
    console.log('[Beam SW] connect already in flight for', deviceId, '— awaiting');
    return _inflightConnect;
  }

  // If we already have an OPEN connection for this SAME device, don't reconnect.
  if (pairingWs?.readyState === WebSocket.OPEN && pairingDeviceId === deviceId) {
    console.log('[Beam SW] Already connected for', deviceId, '— skipping');
    return;
  }

  // Different device or no connection — fully close old state before starting new.
  stopPairingListener();

  _inflightDeviceId = deviceId;
  _inflightConnect = _doConnect(deviceId, ed25519Sk, ed25519Pk).finally(() => {
    _inflightConnect = null;
    _inflightDeviceId = null;
  });
  return _inflightConnect;
}

/**
 * Inner connect routine. Bound to a single `ws` instance throughout —
 * none of its handlers reach for the module-level `pairingWs`, so an
 * orphaned socket from an earlier racing call cannot corrupt the live
 * connection's state. The onclose handler additionally guards mutation
 * of module state with `pairingWs === ws`, ensuring a stale orphan's
 * close event is a true no-op for the active session.
 *
 * @param {string}   deviceId
 * @param {number[]} ed25519Sk
 * @param {number[]} ed25519Pk
 */
async function _doConnect(deviceId, ed25519Sk, ed25519Pk) {
  console.log('[Beam SW] _doConnect: entering, deviceId=', deviceId,
    'skLen=', ed25519Sk?.length, 'pkLen=', ed25519Pk?.length);
  await new Promise(r => setTimeout(r, 100));

  // Store credentials for auto-reconnect on unexpected disconnect
  _lastDeviceId = deviceId;
  _lastEd25519Sk = ed25519Sk;
  _lastEd25519Pk = ed25519Pk;
  _explicitStop = false;
  _authFailed = false;

  pairingDeviceId = deviceId;

  // Import Ed25519 keys from arrays via Web Crypto.
  //
  // The popup stores the private key shape that `crypto.subtle.exportKey`
  // returned. In Chrome 130+ that is unfortunately NOT proper PKCS8 ASN.1
  // for Ed25519 — it returns a 64-byte `seed || publicKey` blob, which
  // round-trips via `importKey('pkcs8', …)` with `DataError`. Node's
  // WebCrypto returns proper PKCS8 (~48 bytes). We try PKCS8 first
  // (correct path; Node tests, future browsers); on `DataError` we fall
  // back to JWK with the first 32 bytes as the seed, which handles both
  // Chrome's 64-byte form and a bare 32-byte seed.
  let privateKey, publicKey;
  try {
    const skArr = new Uint8Array(ed25519Sk);
    const pkArr = new Uint8Array(ed25519Pk);
    if (pkArr.byteLength !== 32) {
      throw new Error('expected 32-byte pk, got ' + pkArr.byteLength);
    }

    try {
      privateKey = await crypto.subtle.importKey(
        'pkcs8', skArr.buffer.slice(skArr.byteOffset, skArr.byteOffset + skArr.byteLength),
        'Ed25519', false, ['sign'],
      );
      console.log('[Beam SW] _doConnect: privateKey imported via PKCS8');
    } catch (pkcs8Err) {
      console.warn('[Beam SW] _doConnect: PKCS8 import failed, falling back to JWK seed-extract:',
        pkcs8Err?.message);
      const seed = skArr.byteLength >= 32 ? skArr.slice(0, 32) : skArr;
      if (seed.byteLength !== 32) {
        throw new Error('cannot derive 32-byte seed from sk of length ' + skArr.byteLength);
      }
      privateKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'OKP', crv: 'Ed25519', d: bytesToBase64Url(seed), x: bytesToBase64Url(pkArr) },
        { name: 'Ed25519' }, false, ['sign'],
      );
      console.log('[Beam SW] _doConnect: privateKey imported via JWK fallback');
    }

    publicKey = await crypto.subtle.importKey(
      'raw', pkArr.buffer.slice(pkArr.byteOffset, pkArr.byteOffset + pkArr.byteLength),
      'Ed25519', true, ['verify'],
    );
    console.log('[Beam SW] _doConnect: keys imported successfully');
  } catch (err) {
    console.error('[Beam SW] _doConnect: importKey failed:', err, '| stack:', err?.stack);
    throw new Error('importKey failed: ' + (err?.message || String(err)));
  }

  // Construct the ConnectionAuthority singleton if not already created, and
  // notify it that we are about to open the WebSocket. Wrap sendJson in a
  // lambda so the authority closes over the *eventual* binding of
  // sendPairingMessage (which is hoisted as a function declaration but the
  // lambda is the only safe form if we ever swap to a const/let binding).
  // The notifyWsOpening call must precede `new WebSocket(...)` so the
  // authority's selfState transitions OFFLINE -> CONNECTING before any
  // ws.onopen / onclose can fire.
  const authority = ensureConnectionAuthority({
    sendJson: (msg) => sendPairingMessage(msg),
    ownDeviceId: deviceId,
    // Rung 1: re-assert rendezvous membership. Must replay the COMPLETE set
    // (own + paired peers) — the relay REPLACES membership on register, so an
    // own-only re-register here would drop every peer room. Without this hook
    // the ladder falls back to sendJson({rendezvousId: ownDeviceId}) (own-only).
    register: async () => {
      const rendezvousIds = await currentRendezvousIds(deviceId);
      sendPairingMessage({ type: 'register-rendezvous', rendezvousIds });
    },
    // Rung 2: bounce the WS without dropping the v2 transport. Equivalent to
    // a soft reset — the relay sees us close + open a new socket, and the
    // existing transport singleton (with cached cipher state) is reused.
    forceWsReconnect: async () => {
      if (typeof _restartHook !== 'function') {
        console.warn('[Beam SW] forceWsReconnect: no _restartHook installed');
        return;
      }
      stopPairingListener();
      // Clear the explicit-stop sentinel before restarting (stopPairingListener
      // sets it to true; without flipping it back, the auto-reconnect guard
      // in ws.onclose would suppress the new connect).
      _explicitStop = false;
      try {
        await _restartHook();
      } catch (err) {
        console.error('[Beam SW] forceWsReconnect: restart failed:', err && err.message);
      }
    },
    // Rung 3: full session reset — see forceFullReset() above.
    forceFullReset: () => forceFullReset(_restartHook),
  });
  // Task 10: broadcast every selfState / peerHealth change to the popup.
  // Idempotent — the wiring module guards against double-subscription, so
  // re-entering _doConnect (e.g. after a Rung 2 reconnect) is safe.
  installPopupBroadcaster();
  authority.notifyWsOpening();

  return new Promise((resolve, reject) => {
    // Settle-once: the connect promise MUST settle exactly once, and settling
    // it is what clears `_inflightConnect` (via the .finally in
    // startPairingListener). Every terminal path — auth-ok, auth-fail, error,
    // constructor throw, a close before auth-ok, or the watchdog — routes
    // through here so the single-flight guard can never get stuck.
    let settled = false;
    let authTimer = null;
    const done = () => {
      if (settled) return;
      settled = true;
      if (authTimer) { clearTimeout(authTimer); authTimer = null; }
      resolve();
    };
    const fail = (err) => {
      if (settled) return;
      settled = true;
      if (authTimer) { clearTimeout(authTimer); authTimer = null; }
      reject(err);
    };
    authTimer = setTimeout(
      () => fail(new Error('connect/auth timeout after ' + AUTH_TIMEOUT_MS + 'ms')),
      AUTH_TIMEOUT_MS,
    );

    let ws;
    try {
      ws = new WebSocket(RELAY_URL);
      console.log('[Beam SW] _doConnect: WebSocket created, readyState=', ws.readyState);
    } catch (err) {
      console.error('[Beam SW] _doConnect: WebSocket constructor threw:', err);
      fail(new Error('WebSocket constructor failed: ' + (err?.message || String(err))));
      return;
    }
    pairingWs = ws;

    ws.onmessage = async (event) => {
      // Handle binary frames — every binary frame on this socket is now a
      // Beam v2 frame. The transport routes by transferId/index internally.
      if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
        const bytes = event.data instanceof Blob
          ? new Uint8Array(await event.data.arrayBuffer())
          : new Uint8Array(event.data);
        await getTransport().handleIncomingFrame(bytes);
        return;
      }

      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch {
        console.warn('[Beam SW] Non-JSON relay message ignored');
        return;
      }

      if (msg.type === 'challenge') {
        // Sign challenge||timestamp with Ed25519 private key.
        try {
          const timestamp = Date.now();
          const challengeBytes = hexToBytes(msg.challenge);
          const timestampBytes = new TextEncoder().encode(String(timestamp));

          const payload = new Uint8Array(challengeBytes.length + timestampBytes.length);
          payload.set(challengeBytes);
          payload.set(timestampBytes, challengeBytes.length);

          const signature = await crypto.subtle.sign('Ed25519', privateKey, payload);
          const publicKeyRaw = await crypto.subtle.exportKey('raw', publicKey);

          // Use the local `ws` reference, not module-level pairingWs — between
          // the await above and this send, a concurrent connect could have
          // replaced pairingWs with a still-CONNECTING socket.
          ws.send(JSON.stringify({
            type:      'auth',
            deviceId,
            publicKey: bytesToBase64(new Uint8Array(publicKeyRaw)),
            signature: bytesToBase64(new Uint8Array(signature)),
            timestamp,
          }));
        } catch (err) {
          fail(new Error('Auth signing failed: ' + err.message));
        }
      }
      else if (msg.type === 'pong') {
        // Heartbeat pong received — update the zombie detection timestamp.
        // If this stops arriving, the heartbeat interval will force-close
        // the WS after ZOMBIE_DETECTION_MS.
        _lastPongAt = Date.now();
      }
      else if (msg.type === 'auth-ok') {
        _lastPongAt = Date.now(); // reset zombie timer on fresh auth
        console.log('[Beam SW] Pairing relay authenticated as', deviceId);
        // Register own deviceId AND every paired peer's deviceId. Own is
        // required so our own-id-keyed peer-pings route; peers are required
        // so we're a member of each peer's room. presence.register REPLACES
        // the set, so sending own-only (the old bug) left peers unable to
        // reach us — "can't connect/send".
        const rendezvousIds = await currentRendezvousIds(deviceId);
        ws.send(JSON.stringify({
          type: 'register-rendezvous',
          rendezvousIds,
        }));
        console.log('[Beam SW] Registered rendezvous:', rendezvousIds);
        // Start heartbeat to keep connection alive while user switches to phone
        _startHeartbeat();
        // Authority now sees us as ONLINE (CONNECTING -> ONLINE).
        getConnectionAuthority()?.notifyAuthComplete();
        done();
      }
      else if (msg.type === 'auth-fail') {
        console.error('[Beam SW] Pairing relay auth failed:', msg.reason);
        // Bad/revoked key or clock skew — retrying with the same credentials
        // just storms the relay. Suppress the onclose auto-reconnect until the
        // next explicit connect.
        _authFailed = true;
        fail(new Error('Auth failed: ' + (msg.reason || 'unknown')));
      }
      else if (msg.type === 'pairing-request') {
        console.log('[Beam SW] PAIRING_REQUEST received from', msg.fromDeviceId || msg.deviceId);

        const pairingData = {
          ...msg,
          receivedAt: Date.now(),
        };

        // Store in session storage for the popup to read (survives popup close/reopen).
        await chrome.storage.session.set({ pendingPairingRequest: pairingData });

        // Also try to notify the popup directly — if it's open it can react immediately.
        try {
          await chrome.runtime.sendMessage({
            type: 'PAIRING_REQUEST_RECEIVED',
            payload: msg,
          });
        } catch {
          // Popup is closed — that's the entire reason this module exists.
          // The popup will read from chrome.storage.session when it reopens.
        }
      }
      else if (msg.type === 'peer-online' || msg.type === 'peer-offline') {
        const peerId = msg.deviceId;
        const isOnline = msg.type === 'peer-online';
        console.log('[Beam SW] Presence update:', peerId, isOnline ? 'online' : 'offline');

        // Authority observes relay-reported presence (weaker-than-pong evidence).
        if (isOnline) {
          getConnectionAuthority()?.notifyPeerOnline(peerId);
        } else {
          getConnectionAuthority()?.notifyPeerOffline(peerId);
        }

        // Update session storage so the popup can read it on open.
        const stored = await chrome.storage.session.get('devicePresence');
        const presence = stored.devicePresence || {};
        presence[peerId] = { isOnline, timestamp: Date.now() };
        await chrome.storage.session.set({ devicePresence: presence });

        // Notify popup if open — it will merge the single update without a reload.
        try {
          await chrome.runtime.sendMessage({
            type: 'device-presence-changed',
            payload: { deviceId: peerId, online: isOnline },
          });
        } catch {
          // Popup closed — it will read from storage when next opened.
        }
      }
      else if (msg.type === 'peer-ping') {
        // A peer is probing our liveness. Echo the nonce back as peer-pong.
        // Routing rules (mirrors Task 2's outbound peer-ping shape):
        //   - targetDeviceId: the peer that pinged us (msg.fromDeviceId).
        //   - rendezvousId  : OUR own deviceId — both clients registered to
        //                     the Chrome-owned rendezvous, and the relay's
        //                     membership check requires both sender and
        //                     target to be in the named rendezvous.
        sendPairingMessage({
          type: 'peer-pong',
          nonce: msg.nonce,
          targetDeviceId: msg.fromDeviceId,
          rendezvousId: deviceId,
        });
      }
      else if (msg.type === 'peer-pong') {
        // Forward the nonce to the authority's ping tracker so the matching
        // sendPing promise resolves. No-op if the authority hasn't been
        // constructed yet (e.g. a stray message before _doConnect ran).
        getConnectionAuthority()?.notifyPongReceived(msg.nonce);
      }
      else {
        // Try the v2 transport first (resend / fail / rotate-init/ack/commit).
        // If it doesn't recognise the type, the message is dropped silently —
        // the v1 transfer-init/accept/reject/file-complete paths have been
        // removed, and unknown types don't belong on this socket.
        const handled = await getTransport().handleJsonMessage(msg);
        if (!handled && msg.type) {
          // Useful while v1 callers are still around in the wild; drop
          // quietly once we're confident no client speaks v1.
          // console.debug('[Beam SW] unhandled relay message type:', msg.type);
        }
      }
    };

    ws.onerror = (e) => {
      console.error('[Beam SW] Pairing relay WebSocket error event:', e,
        'readyState=', ws?.readyState);
      fail(new Error('WebSocket connection error (readyState=' + ws?.readyState + ')'));
    };

    ws.onclose = async (e) => {
      // Critical orphan guard: if module-level pairingWs no longer points to
      // *this* ws, we are a stale leftover from a racing connect — exiting
      // here is what prevents an orphan close from nulling the live socket
      // and triggering a spurious reconnect cascade.
      if (pairingWs !== ws) {
        console.log('[Beam SW] Orphan WebSocket closed (code:', e.code + ') — ignored');
        return;
      }

      // Settle the connect promise if it is still pending. A close BEFORE
      // auth-ok would otherwise leave `_inflightConnect` hung forever, and the
      // single-flight guard would then block every future reconnect. No-op if
      // the promise already resolved (auth-ok) or rejected.
      fail(new Error('WebSocket closed before auth-ok (code ' + e.code + ')'));

      console.warn('[Beam SW] Pairing relay WebSocket closed. Code:', e.code, 'Reason:', e.reason);
      if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; }
      pairingWs = null;
      // Authority transitions ONLINE/CONNECTING -> RECONNECTING (or OFFLINE).
      getConnectionAuthority()?.notifyWsClosed();

      // Clear cached presence — we don't know the current state after a reconnect.
      // The relay will re-send peer-online events for any online peers when we
      // re-register the rendezvous.
      try {
        await chrome.storage.session.set({ devicePresence: {} });
        // Notify popup so UI updates immediately
        chrome.runtime.sendMessage({
          type: 'device-presence-changed',
          payload: { reset: true },
        }).catch(() => {});
      } catch { /* ignore */ }

      // Auto-reconnect if we weren't explicitly stopped and auth didn't fail
      // (a failed auth won't succeed on retry — see _authFailed).
      if (!_explicitStop && !_authFailed && _lastDeviceId && _lastEd25519Sk && _lastEd25519Pk) {
        console.log('[Beam SW] Auto-reconnecting to relay in 2s...');
        _reconnectTimer = setTimeout(() => {
          _reconnectTimer = null;
          if (!pairingWs && !_explicitStop) {
            startPairingListener(_lastDeviceId, _lastEd25519Sk, _lastEd25519Pk)
              .then(() => console.log('[Beam SW] Reconnected successfully'))
              .catch(err => console.error('[Beam SW] Reconnect failed:', err));
          }
        }, 2000);
      }
    };
  });
}

// Reconnection state
let _explicitStop = false;
/**
 * Set when the relay rejected our auth (bad/revoked key, clock skew). Retrying
 * with the same credentials just storms the relay, so the onclose auto-reconnect
 * is suppressed until the next explicit connect (which resets this). Cleared at
 * the top of every _doConnect.
 */
let _authFailed = false;
let _lastDeviceId = null;
let _lastEd25519Sk = null;
let _lastEd25519Pk = null;

/** @type {number|null} */
let _heartbeatTimer = null;

/** Pending 2s auto-reconnect timer, tracked so stopPairingListener can cancel it. */
let _reconnectTimer = null;

/**
 * Start the heartbeat: sends JSON `ping` every 25 seconds AND checks for
 * zombie WebSockets by verifying that `pong` responses are arriving.
 *
 * If more than ZOMBIE_DETECTION_MS passes without a pong, the WS is
 * declared dead and force-closed. The onclose handler triggers
 * auto-reconnect, which opens a fresh TCP connection and re-authenticates.
 *
 * This is the application-level equivalent of OkHttp's `pingInterval` —
 * Chrome's browser WebSocket API has no built-in dead-connection
 * detection, so without this check a zombie WS can sit in
 * `readyState === OPEN` for hours while sends silently go to /dev/null.
 */
function _startHeartbeat() {
  if (_heartbeatTimer) clearInterval(_heartbeatTimer);
  _lastPongAt = Date.now(); // reset on fresh connection
  _heartbeatTimer = setInterval(() => {
    if (pairingWs?.readyState === WebSocket.OPEN) {
      // Check zombie: if no pong received in ZOMBIE_DETECTION_MS, force-close.
      if (Date.now() - _lastPongAt > ZOMBIE_DETECTION_MS) {
        console.warn('[Beam SW] WebSocket zombie detected (no pong for',
          Math.round((Date.now() - _lastPongAt) / 1000), 's) — force-closing');
        pairingWs.close(4000, 'zombie detected');
        return; // onclose will trigger auto-reconnect
      }
      pairingWs.send(JSON.stringify({ type: 'ping' }));
    }
  }, 25000);
}

/**
 * Close the pairing relay WebSocket and clear state.
 * Safe to call even if no connection is active.
 */
export function stopPairingListener() {
  _explicitStop = true;
  _inflightConnect = null;
  _inflightDeviceId = null;
  if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; }
  if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
  if (pairingWs) {
    pairingWs.onmessage = null;
    pairingWs.onerror = null;
    pairingWs.onclose = null;
    pairingWs.close();
    pairingWs = null;
  }
  pairingDeviceId = null;
}

/**
 * Rung 3 hook: tear down EVERY piece of relay/transport state and re-enter
 * the boot path from scratch. Implements spec §"Rung 3 — Full session reset"
 * step-by-step:
 *
 *   1. `stopPairingListener()` — close the WS and clear heartbeat / inflight.
 *   2. Clear the module-level `pairingWs` / `_inflightConnect` /
 *      `_inflightDeviceId` (stopPairingListener already did the WS close;
 *       we belt-and-braces null them in case a racing connect re-set them
 *       between our calls).
 *   3. `_resetTransportSingleton()` — drop the BeamV2Transport singleton so
 *      any cached cipher / chunked-send state is forgotten.
 *   4. Call the caller-supplied `restartFn` (typically `autoStartRelayIfPaired`
 *      from `background.js`) to begin a fresh `_doConnect` cycle. The
 *      indirection keeps `background-relay.js` free of a circular import on
 *      `background.js`.
 *
 * The auth-side `await for selfState === ONLINE` budget timer is owned by the
 * recovery ladder (see `connection-authority.js` `_rung3Action`) — this
 * function only performs the I/O. We deliberately reset `_explicitStop` after
 * `stopPairingListener` so the restart path isn't suppressed by the
 * "user wanted to stop" sentinel that `stopPairingListener` sets.
 *
 * @param {() => Promise<void>} restartFn
 *   Function that re-opens the relay connection. Typically
 *   `autoStartRelayIfPaired` from `background.js`. Required — Rung 3 without
 *   a restart hook is a no-op that surrenders to the user immediately.
 * @returns {Promise<void>} Resolves once `restartFn()` has settled. Does NOT
 *                          wait for `selfState === ONLINE` — that wait is the
 *                          ladder's responsibility.
 */
export async function forceFullReset(restartFn) {
  console.log('[Beam SW] forceFullReset: tearing down WS + transport singleton');
  // Step 1: tear down WS, heartbeat, and inflight tracking. After this,
  // _explicitStop = true (set by stopPairingListener) — flip it back so the
  // restart path can run.
  stopPairingListener();
  // Step 2: belt-and-braces null in case a racing connect set them between
  // step 1 and now (defensive — should be no-op after stopPairingListener).
  pairingWs = null;
  _inflightConnect = null;
  _inflightDeviceId = null;
  // Step 3: drop the v2 transport singleton.
  _resetTransportSingleton();
  // Allow the caller's restart path to actually start by clearing the stop
  // flag stopPairingListener set. Without this, a racing reconnect would be
  // suppressed by the auto-reconnect guard in the ws.onclose handler.
  _explicitStop = false;
  // Step 4: re-enter the SW boot connect path.
  if (typeof restartFn !== 'function') {
    console.warn('[Beam SW] forceFullReset: no restartFn supplied — cannot recover');
    return;
  }
  try {
    await restartFn();
    console.log('[Beam SW] forceFullReset: restart kicked off');
  } catch (err) {
    console.error('[Beam SW] forceFullReset: restart failed:', err && err.message);
    // Swallow — the ladder's selfState wait will time out if the connect
    // ultimately failed; we don't want to throw out of the rung action.
  }
}

/**
 * Send a JSON message through the active pairing WebSocket.
 * Used by the popup to send PAIRING_ACK back to the Android device.
 *
 * @param {object} msg - JSON-serialisable message to send.
 */
export function sendPairingMessage(msg) {
  if (pairingWs?.readyState === WebSocket.OPEN) {
    pairingWs.send(JSON.stringify(msg));
  } else {
    console.warn('[Beam SW] sendPairingMessage: WebSocket not open');
  }
}

// ---------------------------------------------------------------------------
// Incoming delivery (called by Beam v2 transport via the wiring hooks)
// ---------------------------------------------------------------------------

/**
 * Deliver a fully-assembled, fully-decrypted incoming file to the user via
 * the existing auto-save / manual-save UX. Called from the Beam v2 transport
 * once all chunks have been decrypted and assembled.
 */
export async function deliverIncomingFile({
  bytes,
  fileName,
  fileSize,
  mimeType,
  fromDeviceId,
}) {
  // Convert to base64 for storage. chrome.storage cannot hold ArrayBuffer
  // and data: URLs for chrome.downloads also need a base64 body. Process
  // in 32KB slices to avoid call-stack overflow on large files.
  let base64 = '';
  const SLICE = 32768;
  for (let i = 0; i < bytes.length; i += SLICE) {
    base64 += String.fromCharCode.apply(null, bytes.subarray(i, i + SLICE));
  }
  base64 = btoa(base64);

  const settingsData = await chrome.storage.local.get('settings');
  const autoSave = !!settingsData?.settings?.autoSave;
  const safeMime = mimeType || 'application/octet-stream';

  if (autoSave) {
    const dataUrl = `data:${safeMime};base64,${base64}`;
    try {
      await chrome.downloads.download({
        url:      dataUrl,
        filename: fileName,
        saveAs:   false,
      });
      console.log('[Beam SW] Auto-saved file:', fileName);
      chrome.notifications.create('file-' + Date.now(), {
        type:    'basic',
        iconUrl: 'icons/icon-128.png',
        title:   'File Saved',
        message: fileName + ' (' + formatSize(fileSize) + ') saved to Downloads',
      });
      return;
    } catch (err) {
      // Download failed (missing permission, disk full, ...). Do NOT claim
      // success, and do NOT lose the bytes — fall through to the manual-save
      // stash below so the user can still retrieve the file from the popup.
      console.error('[Beam SW] Auto-save download failed; falling back to manual save:', err);
    }
  }

  // Manual-save path: auto-save is off, or the auto-save download failed above.
  // Stash the bytes in session storage for the popup and prompt the user.
  await chrome.storage.session.set({
    receivedFile: {
      fileName,
      fileSize,
      mimeType: safeMime,
      fromDeviceId,
      data:     base64,
      timestamp: Date.now(),
    },
  });
  chrome.notifications.create('file-' + Date.now(), {
    type:    'basic',
    iconUrl: 'icons/icon-128.png',
    title:   'File Received',
    message: fileName + ' (' + formatSize(fileSize) + ') — open Beam to save',
  });
}

/**
 * Format a byte count as a human-readable size string.
 *
 * @param {number} bytes
 * @returns {string} e.g. "1.4 MB"
 */
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

/**
 * Send raw binary data through the active pairing WebSocket.
 * Used by background.js to transmit file chunks to the relay.
 *
 * @param {ArrayBuffer} data - Binary payload to send.
 * @returns {boolean} true if the data was sent; false if the socket is unavailable.
 */
export function sendBinary(data) {
  if (pairingWs?.readyState === WebSocket.OPEN) {
    pairingWs.send(data);
    return true;
  }
  return false;
}

/**
 * Surface a desktop notification when an incoming Beam transfer cannot be
 * decrypted (most often: tampered ciphertext, missing session, or peer
 * keys out of sync). Receiver-side counterpart to the sender error UX.
 */
function notifyReceiveFailure() {
  try {
    chrome.notifications.create('beam-rxerr-' + Date.now(), {
      type:    'basic',
      iconUrl: 'icons/icon-128.png',
      title:   'Beam',
      message: 'Received transfer could not be decrypted.',
    });
  } catch (_) {
    /* notifications API may be unavailable in some test contexts */
  }
}

// ---------------------------------------------------------------------------
// Beam E2E encrypted clipboard
// ---------------------------------------------------------------------------

/**
 * Deliver a Beam-decrypted clipboard payload to session storage, the popup,
 * and a desktop notification. Single authoritative inbound clipboard UX.
 */
export async function deliverIncomingClipboard(content, fromDeviceId) {
  const settingsData = await chrome.storage.local.get('settings');
  const autoCopy = settingsData?.settings?.autoCopy !== false;

  const existing = (await chrome.storage.session.get('receivedClipboard'))?.receivedClipboard || [];
  existing.unshift({
    content,
    fromDeviceId,
    timestamp: Date.now(),
  });
  if (existing.length > 20) existing.length = 20;
  await chrome.storage.session.set({ receivedClipboard: existing });

  if (autoCopy) {
    await chrome.storage.session.set({ autoCopyPending: content });
    try {
      await chrome.runtime.sendMessage({
        type: 'AUTO_COPY_CLIPBOARD',
        payload: { content },
      });
    } catch {
      /* popup closed — autoCopyPending will be consumed on next open */
    }
  }

  const notifTitle = autoCopy ? 'Clipboard Copied' : 'Clipboard Received';
  chrome.notifications.create('clipboard-' + Date.now(), {
    type: 'basic',
    iconUrl: 'icons/icon-128.png',
    title: notifTitle,
    message: content.slice(0, 100) + (content.length > 100 ? '...' : ''),
  });
}

/**
 * Public API: encrypt and send a clipboard payload to a paired device.
 *
 * Stateless single AEAD frame under the long-lived pairing key K_AB.
 * `rendezvousId` is accepted for source-compat with the v1 call sites but is
 * unused — the transport routes by `targetDeviceId` and the relay handles
 * binary forwarding via the existing rendezvous registration.
 *
 * @param {string} targetDeviceId
 * @param {string} _rendezvousId  - unused, kept for caller compatibility
 * @param {string} content
 * @returns {Promise<{transferIdHex: string}>}
 */
export async function sendClipboardEncrypted(targetDeviceId, _rendezvousId, content) {
  // Task 9: pre-flight gate. When the authority is wired (production), bail
  // early on a known-bad send path so we don't encode frames into a closed
  // channel. The authority is null in tests that bypass `_doConnect` — there
  // we skip the gate so transport-level coverage stays unaffected.
  const auth = getConnectionAuthority();
  if (auth) {
    const gate = await auth.ensureSendable(targetDeviceId);
    if (!gate.ok) {
      const err = new Error(`pre-flight ${gate.reason}`);
      err.code = gate.reason;
      throw err;
    }
  }

  const transferIdHex = await getBeamV2Transport().sendClipboard(targetDeviceId, content);
  // End-to-end success is strong proof of life — promote the peer to HEALTHY.
  // No-op if the authority is null (e.g. tests that bypass _doConnect).
  getConnectionAuthority()?.notifySendCompleted(targetDeviceId);
  return { transferIdHex };
}

/**
 * Public API: encrypt and send a file to a paired device.
 *
 * Stateless multi-frame transmission under the long-lived pairing key K_AB.
 * Frame 0 carries the meta envelope (`{kind:"file", fileName, fileSize, ...}`);
 * frames 1..N carry chunk plaintext. Resend on dropped chunks is handled by
 * the transport state machine.
 *
 * @param {{
 *   targetDeviceId: string,
 *   rendezvousId?: string,        // unused, kept for caller compatibility
 *   fileName: string,
 *   fileSize: number,
 *   mimeType: string,
 *   data: string, // base64-encoded file bytes (kept stable for callers)
 * }} payload
 * @returns {Promise<{transferIdHex: string, totalChunks: number}>}
 */
export async function sendFileEncrypted(payload) {
  const { fileName, fileSize, mimeType, data, targetDeviceId } = payload;

  // Task 9: pre-flight gate (see sendClipboardEncrypted for rationale).
  const auth = getConnectionAuthority();
  if (auth) {
    const gate = await auth.ensureSendable(targetDeviceId);
    if (!gate.ok) {
      const err = new Error(`pre-flight ${gate.reason}`);
      err.code = gate.reason;
      throw err;
    }
  }

  const binStr = atob(data);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i += 1) bytes[i] = binStr.charCodeAt(i);
  const result = await getBeamV2Transport().sendFile(targetDeviceId, {
    fileName, fileSize, mimeType, bytes,
  });
  // End-to-end success is strong proof of life — promote the peer to HEALTHY.
  // No-op if the authority is null (e.g. tests that bypass _doConnect).
  getConnectionAuthority()?.notifySendCompleted(targetDeviceId);
  // The current callers don't read totalChunks, but preserve the v1 shape.
  return { transferIdHex: result.transferIdHex, totalChunks: result.totalChunks };
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/**
 * Decode a hex string into a Uint8Array.
 *
 * @param {string} hex - Even-length hex string.
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Encode a Uint8Array to a standard base64 string.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Encode a Uint8Array to base64url (no padding) — required by JWK fields
 * `d` and `x` for Ed25519 key material.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
