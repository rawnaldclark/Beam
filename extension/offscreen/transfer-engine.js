/**
 * @file transfer-engine.js
 * @description Beam offscreen transfer-engine orchestrator.
 *
 * This module is the entry point for the offscreen document
 * (offscreen/transfer-engine.html).  It runs in a long-lived offscreen
 * document context that persists for the lifetime of the browser session
 * (kept alive by the service worker's keepalive alarm).
 *
 * Current responsibilities (Phase A — scaffold):
 *   - Load libsodium and generate or restore persistent device key pairs.
 *   - Derive a stable device ID from the Ed25519 public key.
 *   - Respond to MSG.KEEPALIVE_PING so the service worker knows we are alive.
 *   - Expose the paired device list to the popup via MSG.GET_DEVICE_LIST.
 *   - Stub out pairing and transfer handlers (implemented in later phases).
 *
 * Future responsibilities (implemented in later tasks):
 *   - WebSocket connection to the relay server (Phase C).
 *   - WebRTC peer connections and ICE signalling (Phase H).
 *   - File chunking, encryption, and reassembly (Phase E).
 *   - Pairing QR / SAS ceremony (Phase D).
 *   - Transfer history and clipboard history (Phase F).
 *
 * Design notes:
 *   - Key material is stored in chrome.storage.local as plain Arrays (JSON
 *     serialisable).  On startup we restore and re-wrap them as Uint8Arrays.
 *   - `pairedDevices` is kept in module-level state; it is populated from
 *     storage on startup and updated as devices come online/offline.
 *   - All chrome.runtime.onMessage handlers return a boolean:
 *       false — synchronous (sendResponse called inline or not at all).
 *       true  — asynchronous (sendResponse will be called after an await).
 *
 * @module offscreen/transfer-engine
 */

import { init as initCrypto, generateKeyPairs, deriveDeviceId } from './crypto.js';
import { MSG } from '../shared/message-types.js';

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

/**
 * The device's persistent key pairs.
 * @type {{ x25519: { pk: Uint8Array, sk: Uint8Array }, ed25519: { pk: Uint8Array, sk: Uint8Array } } | null}
 */
let deviceKeys = null;

/**
 * Stable device identifier (22-char base64url derived from the Ed25519 public key).
 * @type {string | null}
 */
let deviceId = null;

/**
 * List of all paired devices known to this instance.
 * Populated from chrome.storage.local on startup and kept in sync as
 * devices come online / offline.
 *
 * @type {Array<{deviceId: string, name: string, platform: string, isOnline: boolean, lastSeen: number}>}
 */
let pairedDevices = [];

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/**
 * Bootstrap the offscreen document.
 *
 * Steps:
 *   1. Initialise libsodium (waits for the WASM binary to load).
 *   2. Load or generate the device's persistent Ed25519 + X25519 key pairs.
 *   3. Load the paired device list from storage.
 *
 * Errors are re-thrown so the top-level `startup().catch(console.error)` call
 * surfaces them in the DevTools console of the offscreen document.
 *
 * @returns {Promise<void>}
 */
async function startup() {
  // Step 1: wait for libsodium WASM
  await initCrypto();

  // Step 2: load or generate device keys
  const stored = await chrome.storage.local.get(['deviceKeys', 'deviceId', 'pairedDevices']);

  if (stored.deviceKeys && stored.deviceId) {
    // Restore persisted keys — storage holds plain Arrays, convert back to Uint8Array.
    deviceKeys = {
      x25519: {
        pk: new Uint8Array(stored.deviceKeys.x25519.pk),
        sk: new Uint8Array(stored.deviceKeys.x25519.sk),
      },
      ed25519: {
        pk: new Uint8Array(stored.deviceKeys.ed25519.pk),
        sk: new Uint8Array(stored.deviceKeys.ed25519.sk),
      },
    };
    deviceId = stored.deviceId;
  } else {
    // First run — generate fresh key pairs and persist them.
    deviceKeys = generateKeyPairs();
    deviceId   = deriveDeviceId(deviceKeys.ed25519.pk);

    await chrome.storage.local.set({
      // Serialise Uint8Arrays as plain Arrays for JSON storage.
      deviceKeys: {
        x25519: {
          pk: Array.from(deviceKeys.x25519.pk),
          sk: Array.from(deviceKeys.x25519.sk),
        },
        ed25519: {
          pk: Array.from(deviceKeys.ed25519.pk),
          sk: Array.from(deviceKeys.ed25519.sk),
        },
      },
      deviceId,
    });
  }

  // Step 3: load paired device list
  pairedDevices = stored.pairedDevices ?? [];

  console.log(`[Beam] Transfer engine started. Device ID: ${deviceId}`);
}

// ---------------------------------------------------------------------------
// Message handler
// ---------------------------------------------------------------------------

/**
 * Handle chrome.runtime messages from the service worker and popup.
 *
 * Each case documents which component sends the message and what the
 * expected response shape is.
 *
 * @param {object}   msg        - Incoming message with at least a `type` field.
 * @param {object}   sender     - MessageSender (unused; kept for documentation).
 * @param {Function} sendResponse - Callback to send a synchronous or async reply.
 * @returns {boolean} true if sendResponse will be called asynchronously.
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {

    // ── Keepalive ping (from service worker alarm) ──────────────────────────
    // Sender : background.js (alarm handler)
    // Response: { type: MSG.KEEPALIVE_PONG, payload: { status, deviceId } }
    case MSG.KEEPALIVE_PING:
      sendResponse({
        type:    MSG.KEEPALIVE_PONG,
        payload: { status: 'alive', deviceId },
      });
      return false;

    // ── Device list request (from popup) ────────────────────────────────────
    // Sender : popup
    // Response: { type: MSG.DEVICE_LIST, payload: { devices } }
    case MSG.GET_DEVICE_LIST:
      sendResponse({
        type:    MSG.DEVICE_LIST,
        payload: { devices: pairedDevices },
      });
      return false;

    // ── Start pairing ceremony (from popup) ─────────────────────────────────
    // Sender : popup
    // Response: { type: MSG.PAIRING_QR_DATA, payload: { deviceId, publicKey } }
    // NOTE: Full implementation deferred to Phase D (pairing task).
    case MSG.START_PAIRING:
      handleStartPairing(sendResponse);
      return true; // async

    // ── Initiate an outbound transfer (from popup or service worker) ─────────
    // Sender : popup (direct file drop) or background.js (context menu / shortcut)
    // No response — progress is reported via TRANSFER_PROGRESS / TRANSFER_COMPLETE.
    // NOTE: Full implementation deferred to Phase E (transfer engine task).
    case MSG.INITIATE_TRANSFER:
      handleTransfer(msg.payload);
      return false;

  }

  // Unknown message type — no response needed.
  return false;
});

// ---------------------------------------------------------------------------
// Stub handlers (to be replaced in later phases)
// ---------------------------------------------------------------------------

/**
 * Stub: begin the QR / SAS pairing ceremony.
 *
 * Returns just enough information for the popup to render a QR code in
 * Phase A testing.  The real implementation (Phase D) will:
 *   1. Generate an ephemeral X25519 key pair for the ECDH exchange.
 *   2. Encode the QR payload (deviceId + public key + relay URL) as a URL.
 *   3. Open a WebSocket to the relay to wait for the peer's pairing request.
 *
 * @param {Function} sendResponse - Reply callback.
 * @returns {Promise<void>}
 */
async function handleStartPairing(sendResponse) {
  // Phase A stub: echo back the device's identity so the popup can display
  // a placeholder QR code while the real pairing flow is being built.
  sendResponse({
    type:    MSG.PAIRING_QR_DATA,
    payload: {
      deviceId,
      // Expose only the public key (never the secret key).
      publicKey: deviceKeys ? Array.from(deviceKeys.ed25519.pk) : null,
    },
  });
}

/**
 * Stub: handle an outbound transfer request.
 *
 * Logs the request and does nothing further.  The real implementation
 * (Phase E) will:
 *   1. Validate and normalise the payload (file, text, clipboard, image).
 *   2. Look up the target device's session key.
 *   3. Chunk and encrypt the data.
 *   4. Send chunks over the WebRTC data channel (or relay fallback).
 *   5. Emit TRANSFER_PROGRESS / TRANSFER_COMPLETE / TRANSFER_FAILED messages.
 *
 * @param {object} payload - Transfer request payload from the initiating component.
 */
async function handleTransfer(payload) {
  // Phase A stub — will be replaced in Phase E.
  console.log('[Beam] Transfer requested (stub — not yet implemented):', payload);
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

startup().catch(console.error);
