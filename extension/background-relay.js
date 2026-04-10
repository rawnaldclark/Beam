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
 * State for an in-progress incoming file transfer.
 * Populated when a file-offer is received; consumed when file-complete arrives.
 *
 * @type {{
 *   transferId: string,
 *   fileName: string,
 *   fileSize: number,
 *   mimeType: string,
 *   fromDeviceId: string,
 *   chunks: Uint8Array[],
 *   bytesReceived: number,
 * }|null}
 */
let pendingFileTransfer = null;

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
      else if (msg.type === 'clipboard-transfer') {
        // Incoming clipboard content from a paired Android device.
        console.log('[Beam SW] Clipboard received from', msg.fromDeviceId || msg.deviceId);

        // Read the auto-copy setting (default: ON).
        const settingsData = await chrome.storage.local.get('settings');
        const autoCopy = settingsData?.settings?.autoCopy !== false;

        // Append to session storage ring buffer (most recent first, max 20 entries).
        const existing = (await chrome.storage.session.get('receivedClipboard'))?.receivedClipboard || [];
        existing.unshift({
          content: msg.content,
          fromDeviceId: msg.fromDeviceId || msg.deviceId,
          timestamp: Date.now(),
        });
        if (existing.length > 20) existing.length = 20;
        await chrome.storage.session.set({ receivedClipboard: existing });

        if (autoCopy) {
          // Service workers cannot write to the clipboard directly.
          // Set a flag in session storage so the popup can copy on next open,
          // and notify the popup if it is currently open.
          await chrome.storage.session.set({ autoCopyPending: msg.content });
          try {
            await chrome.runtime.sendMessage({
              type: 'AUTO_COPY_CLIPBOARD',
              payload: { content: msg.content },
            });
          } catch {
            // Popup is closed — autoCopyPending will be consumed when it reopens.
          }
        }

        // Show a desktop notification with a content preview.
        const notifTitle = autoCopy ? 'Clipboard Copied' : 'Clipboard Received';
        chrome.notifications.create('clipboard-' + Date.now(), {
          type: 'basic',
          iconUrl: 'icons/icon-128.png',
          title: notifTitle,
          message: msg.content.slice(0, 100) + (msg.content.length > 100 ? '...' : ''),
        });
      }
      else if (msg.type === 'file-offer') {
        // A remote device wants to send us a file.
        const fromId = msg.fromDeviceId || msg.deviceId;
        console.log('[Beam SW] File offer from', fromId, ':', msg.fileName, msg.fileSize, 'bytes');

        // Auto-accept: set up state to receive binary chunks.
        pendingFileTransfer = {
          transferId:   msg.transferId,
          fileName:     msg.fileName,
          fileSize:     msg.fileSize,
          mimeType:     msg.mimeType,
          fromDeviceId: fromId,
          chunks:       [],
          bytesReceived: 0,
        };

        // Send file-accept back to sender.
        sendPairingMessage({
          type:           'file-accept',
          targetDeviceId: fromId,
          rendezvousId:   msg.rendezvousId || pairingDeviceId,
          transferId:     msg.transferId,
        });

        // Bind the relay session so binary frames are routed to us.
        sendPairingMessage({
          type:           'relay-bind',
          transferId:     msg.transferId,
          targetDeviceId: fromId,
          rendezvousId:   msg.rendezvousId || pairingDeviceId,
        });
      }
      else if (msg.type === 'file-accept') {
        // The remote device accepted our file offer — binary send can proceed.
        console.log('[Beam SW] File accepted by remote, transferId:', msg.transferId);
      }
      else if (msg.type === 'file-complete') {
        // All binary chunks have been sent by the remote device.
        if (pendingFileTransfer && msg.transferId === pendingFileTransfer.transferId) {
          await assembleAndSaveFile();
        }
      }
    };

    pairingWs.onerror = (e) => {
      console.error('[Beam SW] Pairing relay WebSocket error');
      reject(new Error('WebSocket connection error'));
    };

    pairingWs.onclose = (e) => {
      console.warn('[Beam SW] Pairing relay WebSocket closed. Code:', e.code, 'Reason:', e.reason);
      if (_heartbeatTimer) { clearInterval(_heartbeatTimer); _heartbeatTimer = null; }
      pairingWs = null;

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
  if (!pendingFileTransfer) return;

  const bytes = data instanceof Blob
    ? new Uint8Array(await data.arrayBuffer())
    : new Uint8Array(data);

  pendingFileTransfer.chunks.push(bytes);
  pendingFileTransfer.bytesReceived += bytes.length;
  console.log(
    '[Beam SW] File chunk:',
    bytes.length, 'B, total:',
    pendingFileTransfer.bytesReceived, '/', pendingFileTransfer.fileSize,
  );

  // Auto-assemble when all bytes received — don't wait for file-complete message
  if (pendingFileTransfer.bytesReceived >= pendingFileTransfer.fileSize) {
    console.log('[Beam SW] All bytes received, assembling file');
    await assembleAndSaveFile();
  }
}

/**
 * Assemble all received chunks into a single file and store it in session
 * storage for the popup to trigger a download.
 *
 * The file data is stored as a base64 string because chrome.storage cannot
 * hold ArrayBuffer values.
 *
 * @returns {Promise<void>}
 */
async function assembleAndSaveFile() {
  const ft = pendingFileTransfer;
  if (!ft) return;

  console.log('[Beam SW] Assembling file:', ft.fileName, ft.bytesReceived, 'bytes');

  // Combine all chunks into one contiguous buffer.
  const totalSize = ft.chunks.reduce((s, c) => s + c.length, 0);
  const combined = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of ft.chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  // Convert to base64 for storage (chrome.storage can't hold ArrayBuffer).
  // Process in 32KB slices to avoid call-stack overflow on large files.
  let base64 = '';
  const SLICE = 32768;
  for (let i = 0; i < combined.length; i += SLICE) {
    base64 += String.fromCharCode.apply(null, combined.subarray(i, i + SLICE));
  }
  base64 = btoa(base64);

  // Read the auto-save setting (default: OFF).
  const settingsData = await chrome.storage.local.get('settings');
  const autoSave = !!settingsData?.settings?.autoSave;

  if (autoSave) {
    // Auto-save: trigger a browser download directly from the service worker.
    const dataUrl = `data:${ft.mimeType};base64,${base64}`;
    try {
      await chrome.downloads.download({
        url:      dataUrl,
        filename: ft.fileName,
        saveAs:   false,
      });
      console.log('[Beam SW] Auto-saved file:', ft.fileName);
    } catch (err) {
      console.error('[Beam SW] Auto-save download failed:', err);
    }

    // Desktop notification
    chrome.notifications.create('file-' + Date.now(), {
      type:    'basic',
      iconUrl: 'icons/icon-128.png',
      title:   'File Saved',
      message: ft.fileName + ' (' + formatSize(ft.fileSize) + ') saved to Downloads',
    });
  } else {
    // Manual save: store in session storage for the popup to show a download banner.
    await chrome.storage.session.set({
      receivedFile: {
        fileName:     ft.fileName,
        fileSize:     ft.fileSize,
        mimeType:     ft.mimeType,
        fromDeviceId: ft.fromDeviceId,
        data:         base64,
        timestamp:    Date.now(),
      },
    });

    // Desktop notification so the user knows a file arrived.
    chrome.notifications.create('file-' + Date.now(), {
      type:    'basic',
      iconUrl: 'icons/icon-128.png',
      title:   'File Received',
      message: ft.fileName + ' (' + formatSize(ft.fileSize) + ') — open Beam to save',
    });
  }

  // Release the relay session and clear state.
  sendPairingMessage({ type: 'relay-release', transferId: ft.transferId });
  pendingFileTransfer = null;
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
