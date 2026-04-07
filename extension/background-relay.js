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

const RELAY_URL = 'wss://zaptransfer-relay.fly.dev';

/** @type {WebSocket|null} Active pairing WebSocket connection. */
let pairingWs = null;

/** @type {string|null} Device ID for the current pairing session. */
let pairingDeviceId = null;

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
  // Close any existing connection before starting a new one.
  stopPairingListener();

  pairingDeviceId = deviceId;

  // Import Ed25519 keys from raw/PKCS8 arrays via Web Crypto.
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    new Uint8Array(ed25519Sk).buffer,
    'Ed25519',
    false,
    ['sign'],
  );
  const publicKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(ed25519Pk).buffer,
    'Ed25519',
    true,
    ['verify'],
  );

  return new Promise((resolve, reject) => {
    pairingWs = new WebSocket(RELAY_URL);

    pairingWs.onmessage = async (event) => {
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

          pairingWs.send(JSON.stringify({
            type:      'auth',
            deviceId,
            publicKey: bytesToBase64(new Uint8Array(publicKeyRaw)),
            signature: bytesToBase64(new Uint8Array(signature)),
            timestamp,
          }));
        } catch (err) {
          reject(new Error('Auth signing failed: ' + err.message));
        }
      }
      else if (msg.type === 'auth-ok') {
        console.log('[Beam SW] Pairing relay authenticated');
        // Register our deviceId as rendezvous so the relay routes Android's message.
        pairingWs.send(JSON.stringify({
          type: 'register-rendezvous',
          rendezvousIds: [deviceId],
        }));
        resolve();
      }
      else if (msg.type === 'auth-fail') {
        console.error('[Beam SW] Pairing relay auth failed:', msg.reason);
        reject(new Error('Auth failed: ' + (msg.reason || 'unknown')));
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
    };

    pairingWs.onerror = () => {
      reject(new Error('WebSocket connection error'));
    };

    pairingWs.onclose = () => {
      pairingWs = null;
    };
  });
}

/**
 * Close the pairing relay WebSocket and clear state.
 * Safe to call even if no connection is active.
 */
export function stopPairingListener() {
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
