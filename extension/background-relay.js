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

import {
  sendClipboardEncrypted as _sendClipboardEncrypted,
  sendFileEncrypted as _sendFileEncrypted,
  handleTransferInit,
  handleTransferAccept,
  handleTransferReject,
  handleIncomingBeamFrame,
  isBeamFrame,
} from './crypto/beam-relay-handlers.js';

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
  console.log('[Beam SW] startPairingListener called for', deviceId);

  // If we already have an OPEN connection for this SAME device, don't reconnect.
  if (pairingWs?.readyState === WebSocket.OPEN && pairingDeviceId === deviceId) {
    console.log('[Beam SW] Already connected for', deviceId, '— skipping');
    return;
  }

  // Different device or no connection — fully close old state before starting new.
  stopPairingListener();
  await new Promise(r => setTimeout(r, 100));

  // Store credentials for auto-reconnect on unexpected disconnect
  _lastDeviceId = deviceId;
  _lastEd25519Sk = ed25519Sk;
  _lastEd25519Pk = ed25519Pk;
  _explicitStop = false;

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
      // Handle binary frames (file data from relay).
      if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
        await handleIncomingBinaryFrame(event.data);
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
        console.log('[Beam SW] Pairing relay authenticated as', deviceId);
        // Register our deviceId as rendezvous so the relay routes Android's message.
        pairingWs.send(JSON.stringify({
          type: 'register-rendezvous',
          rendezvousIds: [deviceId],
        }));
        console.log('[Beam SW] Registered rendezvous:', deviceId);
        // Start heartbeat to keep connection alive while user switches to phone
        _startHeartbeat();
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
      else if (msg.type === 'peer-online' || msg.type === 'peer-offline') {
        const peerId = msg.deviceId;
        const isOnline = msg.type === 'peer-online';
        console.log('[Beam SW] Presence update:', peerId, isOnline ? 'online' : 'offline');

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
      else if (msg.type === 'transfer-init') {
        // Beam E2E handshake — peer wants to start an encrypted transfer.
        await handleTransferInit({ msg, sendJson: sendPairingMessage });
      }
      else if (msg.type === 'transfer-accept') {
        await handleTransferAccept({ msg });
      }
      else if (msg.type === 'transfer-reject') {
        await handleTransferReject({ msg });
      }
      else if (msg.type === 'file-complete') {
        // Advisory signal that the sender has finished — the receiver
        // already drives completion off chunksReceived === totalChunks
        // inside handleIncomingBeamFrame, so this is currently a no-op.
      }
    };

    pairingWs.onerror = (e) => {
      console.error('[Beam SW] Pairing relay WebSocket error');
      reject(new Error('WebSocket connection error'));
    };

    pairingWs.onclose = async (e) => {
      console.warn('[Beam SW] Pairing relay WebSocket closed. Code:', e.code, 'Reason:', e.reason);
      if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; }
      pairingWs = null;

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

      // Auto-reconnect if we weren't explicitly stopped
      if (!_explicitStop && _lastDeviceId && _lastEd25519Sk && _lastEd25519Pk) {
        console.log('[Beam SW] Auto-reconnecting to relay in 2s...');
        setTimeout(() => {
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
let _lastDeviceId = null;
let _lastEd25519Sk = null;
let _lastEd25519Pk = null;

/** @type {number|null} */
let _heartbeatTimer = null;

/** Start sending pings every 25 seconds to keep the connection alive. */
function _startHeartbeat() {
  if (_heartbeatTimer) clearInterval(_heartbeatTimer);
  _heartbeatTimer = setInterval(() => {
    if (pairingWs?.readyState === WebSocket.OPEN) {
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
  if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; }
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
// File transfer helpers
// ---------------------------------------------------------------------------

/**
 * Handle an incoming binary WebSocket frame (a file data chunk).
 * Appends the chunk to the pending file transfer's buffer.
 *
 * @param {ArrayBuffer|Blob} data - Raw binary frame data.
 * @returns {Promise<void>}
 */
async function handleIncomingBinaryFrame(data) {
  const bytes = data instanceof Blob
    ? new Uint8Array(await data.arrayBuffer())
    : new Uint8Array(data);

  // Every binary frame MUST be a Beam E2E encrypted frame with the 'BEAM'
  // magic prefix. The legacy plaintext file path has been removed.
  if (isBeamFrame(bytes)) {
    try {
      await handleIncomingBeamFrame({
        bytes,
        onClipboardDecrypted: async (content, fromDeviceId) => {
          await deliverIncomingClipboard(content, fromDeviceId);
        },
        onFileComplete: async ({ bytes: fileBytes, fileName, fileSize, mimeType, fromDeviceId }) => {
          await deliverIncomingFile({
            bytes: fileBytes,
            fileName,
            fileSize,
            mimeType,
            fromDeviceId,
          });
        },
      });
    } catch (err) {
      console.error('[Beam SW] Beam frame handling failed:', err);
      notifyReceiveFailure();
    }
    return;
  }
  console.warn('[Beam SW] Unexpected non-Beam binary frame dropped (size:', bytes.length, 'bytes)');
  notifyReceiveFailure();
}

/**
 * Deliver a fully-assembled, fully-decrypted incoming file to the user via
 * the existing auto-save / manual-save UX. Called from the Beam frame
 * handler once a file's metadata + all chunks have been decrypted and
 * assembled.
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
    } catch (err) {
      console.error('[Beam SW] Auto-save download failed:', err);
    }
    chrome.notifications.create('file-' + Date.now(), {
      type:    'basic',
      iconUrl: 'icons/icon-128.png',
      title:   'File Saved',
      message: fileName + ' (' + formatSize(fileSize) + ') saved to Downloads',
    });
  } else {
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
 * Runs the Beam Triple-DH handshake on the pairing WebSocket, derives a
 * per-transfer session key, and emits the ciphertext as a single Beam
 * binary frame. Rejects with an Error (with a `code` field from
 * ERROR_CODES) if the peer is unreachable, the handshake times out, or
 * the handshake is actively rejected.
 *
 * @param {string} targetDeviceId
 * @param {string} rendezvousId
 * @param {string} content
 * @returns {Promise<{transferIdHex: string}>}
 */
export async function sendClipboardEncrypted(targetDeviceId, rendezvousId, content) {
  return _sendClipboardEncrypted({
    targetDeviceId,
    rendezvousId,
    content,
    sendJson: sendPairingMessage,
    sendBinary,
  });
}

/**
 * Public API: encrypt and send a file to a paired device.
 *
 * Runs the Beam Triple-DH handshake, encrypts the metadata envelope
 * (fileName/fileSize/mime/totalChunks) under metaKey, then encrypts each
 * 200KB chunk under chunkKey. Frames are emitted on the pairing WebSocket
 * with the 'BEAM' magic prefix so the receiver can demux them from the
 * legacy plaintext file path.
 *
 * @param {{
 *   targetDeviceId: string,
 *   rendezvousId: string,
 *   fileName: string,
 *   fileSize: number,
 *   mimeType: string,
 *   data: string, // base64-encoded file bytes (same shape as legacy payload)
 * }} payload
 * @returns {Promise<{transferIdHex: string, totalChunks: number}>}
 */
export async function sendFileEncrypted(payload) {
  const { fileName, fileSize, mimeType, data, targetDeviceId, rendezvousId } = payload;
  // Decode the base64 payload once — senders up the stack already produce
  // base64 (image fetches, popup file picker) so keeping the API stable.
  const binStr = atob(data);
  const rawBytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i += 1) rawBytes[i] = binStr.charCodeAt(i);
  return _sendFileEncrypted({
    targetDeviceId,
    rendezvousId,
    fileName,
    fileSize,
    mimeType,
    rawBytes,
    sendJson: sendPairingMessage,
    sendBinary,
  });
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
