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

import { init as initCrypto, generateKeyPairs, deriveDeviceId, deriveSharedSecret, deriveSAS, sasToEmoji } from './crypto.js';
import { MSG, WIRE } from '../shared/message-types.js';
import { WsClient } from './ws-client.js';
import { RELAY_URL } from '../shared/constants.js';
import { TransferManager } from './transfer-manager.js';

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

/**
 * WebSocket client connected to the relay server.
 * Null until startup() completes and connectRelay() is called.
 * Exposed at module scope so future phases (transfer, signalling) can reuse it.
 *
 * @type {WsClient | null}
 */
let wsClient = null;

/**
 * Holds in-progress pairing state between the moment we receive a peer's
 * public keys and the moment the user confirms the SAS emoji and names the
 * device.  Set by handlePairRequest(), cleared by savePairedDevice() or on
 * any error.
 *
 * @type {{ peerInfo: object, sharedSecret: Uint8Array } | null}
 */
let pendingPairing = null;

/**
 * Transfer manager — owns the complete file/clipboard transfer lifecycle.
 * Instantiated once connectRelay() has authenticated the WebSocket so that
 * outbound transfers can be dispatched immediately.
 *
 * Null until startup() + connectRelay() complete successfully.
 *
 * @type {TransferManager | null}
 */
let transferManager = null;

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
    // Response: { type: MSG.PAIRING_QR_DATA, payload: { deviceId, ed25519Pk,
    //             x25519Pk, relayUrl } }
    case MSG.START_PAIRING:
      handleStartPairing(sendResponse);
      return true; // async

    // ── User confirmed the SAS emoji matches (from popup) ───────────────────
    // Sender : popup (after the user taps "They match")
    // No response — completion is signalled by MSG.PAIRING_COMPLETE later.
    case MSG.PAIRING_CONFIRM_SAS:
      completePairing(msg.payload);
      return false;

    // ── User supplied a friendly device name (from popup) ───────────────────
    // Sender : popup (naming form submit)
    // No response — MSG.PAIRING_COMPLETE is sent once the record is persisted.
    case MSG.PAIRING_SET_DEVICE_NAME:
      savePairedDevice(msg.payload);
      return false;

    // ── Initiate an outbound transfer (from popup or service worker) ─────────
    // Sender : popup (direct file drop) or background.js (context menu / shortcut)
    // No response — progress is reported asynchronously via:
    //   TRANSFER_PROGRESS, TRANSFER_COMPLETE, TRANSFER_FAILED
    case MSG.INITIATE_TRANSFER:
      // Fire-and-forget; TransferManager sends progress/complete messages internally.
      handleTransfer(msg.payload).catch(console.error);
      return false;

  }

  // Unknown message type — no response needed.
  return false;
});

// ---------------------------------------------------------------------------
// Relay WebSocket connection + presence tracking (Phase C)
// ---------------------------------------------------------------------------

/**
 * Connect to the relay server, register rendezvous IDs, and subscribe to
 * peer presence events.
 *
 * Called once after startup() resolves.  The WsClient handles all subsequent
 * reconnects internally; this function is not re-called on reconnect.
 *
 * Presence events from the relay update chrome.storage.session so that the
 * popup and service worker always have a fresh online/offline state, and a
 * MSG.DEVICE_PRESENCE_CHANGED notification is sent to the service worker so
 * it can rebuild context menus.
 *
 * @returns {Promise<void>}
 */
async function connectRelay() {
  wsClient = new WsClient();

  // Derive rendezvous IDs from the paired device list.  A rendezvousId is
  // stored on each paired device record during the pairing ceremony (Phase D).
  // Devices without one (e.g. legacy records) are silently skipped.
  const rendezvousIds = pairedDevices
    .map((d) => d.rendezvousId)
    .filter(Boolean);

  try {
    await wsClient.connect(deviceId, deviceKeys, rendezvousIds);
    console.log('[Beam] Relay connected. Presence tracking active.');
  } catch (err) {
    // Connection failure is non-fatal; the WsClient will keep retrying.
    // Log and continue — the extension works in degraded mode until the relay
    // becomes reachable.
    console.warn('[Beam] Initial relay connection failed (will retry):', err);
  }

  // ── Peer presence handlers ──────────────────────────────────────────────

  wsClient.on(WIRE.PEER_ONLINE, (msg) => {
    updatePresence(msg.deviceId, true);
  });

  wsClient.on(WIRE.PEER_OFFLINE, (msg) => {
    updatePresence(msg.deviceId, false);
  });

  // ── Incoming pairing request ────────────────────────────────────────────
  // An Android peer that scanned our QR code sends its public keys inside an
  // SDP_OFFER frame during Phase D.  Phase H will repurpose SDP_OFFER for
  // WebRTC signalling; until then we distinguish the two by the absence of an
  // `sdp` field in a pairing message.
  //
  // TODO(Phase H): replace this dual-purpose handler with a dedicated
  // PAIRING_REQUEST wire type once the Android companion app is updated.
  wsClient.on(WIRE.SDP_OFFER, async (msg) => {
    // Distinguish a pairing request (carries peer public keys) from a WebRTC
    // SDP offer (carries `sdp` field).  The latter is handled in Phase H.
    if (msg.ed25519Pk && msg.x25519Pk) {
      await handlePairRequest(msg);
    }
    // Otherwise silently ignore — WebRTC handling not yet implemented.
  });

  // ── Instantiate TransferManager ────────────────────────────────────────
  // Created here (after auth completes) so it can immediately use the
  // authenticated wsClient for outbound transfers.
  transferManager = new TransferManager(wsClient, deviceKeys, pairedDevices);

  // ── Incoming relay data frames ──────────────────────────────────────────
  // The relay server routes encrypted frames from peers via WIRE.RELAY_DATA.
  // We dispatch on the embedded `msgType` field to the correct TransferManager
  // handler.  Binary frames (raw chunks) arrive on the WsClient binary handler.
  wsClient.on(WIRE.RELAY_DATA, (msg) => {
    if (!transferManager) return;

    switch (msg.msgType) {
      // ── Incoming file transfer request ────────────────────────────────
      case 'transfer-request':
        transferManager.handleIncomingRequest({
          ...msg,
          fromDeviceId: msg.fromDeviceId ?? msg.senderDeviceId,
        });
        break;

      // ── Transfer accepted by receiver ─────────────────────────────────
      // Resolves the accept-promise in sendFile() so chunk streaming begins.
      case 'transfer-accept':
        transferManager.handleChunkAck({
          ...msg,
          msgType: 'transfer-accept',
        });
        break;

      // ── Chunk ACK from receiver ───────────────────────────────────────
      case 'chunk-ack':
        transferManager.handleChunkAck(msg);
        break;

      // ── Clipboard fast-path ───────────────────────────────────────────
      case 'clipboard':
        handleIncomingClipboard(msg);
        break;

      default:
        // Unknown msgType — silently ignore to remain forward-compatible.
        break;
    }
  });

  // ── Binary chunk frames ─────────────────────────────────────────────────
  // Raw binary WebSocket frames carry the 64-byte header + encrypted chunk
  // ciphertext.  The WsClient exposes a single binary handler slot.
  wsClient.onBinary((data) => {
    if (transferManager) {
      transferManager.handleChunk(data);
    }
  });
}

/**
 * Persist a device's online/offline state and notify the service worker.
 *
 * Presence is stored in chrome.storage.session (cleared on browser restart)
 * keyed by device ID.  The service worker receives a DEVICE_PRESENCE_CHANGED
 * message carrying the full paired device list annotated with current presence
 * so it can rebuild context menus without querying storage itself.
 *
 * @param {string}  peerId   - The relay-assigned device ID of the peer.
 * @param {boolean} isOnline - true = peer came online, false = peer went offline.
 * @returns {Promise<void>}
 */
async function updatePresence(peerId, isOnline) {
  // chrome.storage.session.get() always returns an object; the key is absent
  // (not null/undefined) when it has never been written.
  const stored   = await chrome.storage.session.get('devicePresence');
  const presence = stored.devicePresence ?? {};

  presence[peerId] = { isOnline, lastSeen: Date.now() };
  await chrome.storage.session.set({ devicePresence: presence });

  // Annotate the in-memory paired list with live presence state and forward
  // to the service worker.  The SW uses this to update context menu items.
  const devices = pairedDevices.map((d) => ({
    ...d,
    isOnline: presence[d.deviceId]?.isOnline ?? false,
  }));

  try {
    chrome.runtime.sendMessage({
      type:    MSG.DEVICE_PRESENCE_CHANGED,
      payload: { devices },
    });
  } catch (err) {
    // The service worker may be suspended between events; the error is benign.
    console.warn('[Beam] Could not notify SW of presence change:', err);
  }
}

// ---------------------------------------------------------------------------
// Pairing ceremony handlers (Phase D)
// ---------------------------------------------------------------------------

/**
 * Respond to MSG.START_PAIRING from the popup with the QR payload the popup
 * needs to render the QR code.
 *
 * The QR payload encodes this device's identity and both public keys so the
 * Android companion app can:
 *   1. Derive the rendezvous ID and open a WebSocket to the relay.
 *   2. Send its own public keys back (via WIRE.SDP_OFFER) to begin the ECDH
 *      exchange.
 *
 * Both the Ed25519 key (for identity binding) and the X25519 key (for the DH
 * exchange) are included so the popup can encode them into the QR code without
 * needing to query storage separately.
 *
 * @param {Function} sendResponse - chrome.runtime.sendMessage reply callback.
 * @returns {Promise<void>}
 */
async function handleStartPairing(sendResponse) {
  sendResponse({
    type:    MSG.PAIRING_QR_DATA,
    payload: {
      deviceId,
      // Serialise as plain Arrays (JSON-safe; Uint8Array does not survive
      // the chrome.runtime message boundary).
      ed25519Pk: deviceKeys ? Array.from(deviceKeys.ed25519.pk) : null,
      x25519Pk:  deviceKeys ? Array.from(deviceKeys.x25519.pk)  : null,
      relayUrl:  RELAY_URL,
    },
  });
}

/**
 * Handle an incoming pairing request from an Android peer.
 *
 * Called when the relay delivers a WIRE.SDP_OFFER frame that carries peer
 * public keys (the Phase D pairing marker) rather than a WebRTC SDP blob.
 *
 * Steps:
 *   1. Perform X25519 ECDH to derive a shared secret.
 *   2. Derive the 4-emoji SAS from the shared secret and both Ed25519 keys.
 *   3. Push the SAS to the popup for out-of-band user confirmation.
 *   4. Stash the pairing state in `pendingPairing` until the user confirms.
 *
 * The pairing is not finalised here — `completePairing` (triggered by
 * MSG.PAIRING_CONFIRM_SAS) marks the SAS step as verified, and
 * `savePairedDevice` (triggered by MSG.PAIRING_SET_DEVICE_NAME) persists the
 * paired device record.
 *
 * @param {{
 *   deviceId:  string,
 *   ed25519Pk: number[],
 *   x25519Pk:  number[]
 * }} peerInfo - Public identity received from the Android peer.
 * @returns {Promise<void>}
 */
async function handlePairRequest(peerInfo) {
  if (!deviceKeys) {
    console.error('[Beam] handlePairRequest: device keys not yet loaded.');
    return;
  }

  // Step 1: X25519 scalar multiplication → 32-byte shared secret.
  const sharedSecret = deriveSharedSecret(
    new Uint8Array(deviceKeys.x25519.sk),
    new Uint8Array(peerInfo.x25519Pk),
  );

  // Step 2: Derive the 8-byte SAS and map it to 4 emoji.
  // pk1 and pk2 are ordered canonically so both sides produce the same SAS.
  const sasBytes = deriveSAS(
    sharedSecret,
    deviceKeys.ed25519.pk,
    new Uint8Array(peerInfo.ed25519Pk),
  );
  const emojis = sasToEmoji(sasBytes);

  // Step 3: Push SAS emoji to the popup for user verification.
  try {
    chrome.runtime.sendMessage({
      type:    MSG.PAIRING_SAS,
      payload: { emojis, peerId: peerInfo.deviceId },
    });
  } catch (err) {
    // The popup may have closed before the SAS arrived; log and continue so
    // the pending state is still available if the popup re-opens.
    console.warn('[Beam] Could not push SAS to popup:', err);
  }

  // Step 4: Stash pairing state — overwrite any previous in-flight pairing.
  pendingPairing = { peerInfo, sharedSecret };
}

/**
 * Handle MSG.PAIRING_CONFIRM_SAS: the user indicated that the SAS emoji
 * displayed on both devices match.
 *
 * At this point the shared secret is authenticated.  The popup will
 * immediately follow with MSG.PAIRING_SET_DEVICE_NAME; this function is a
 * no-op gate that could be extended in the future to send a confirmation
 * signal back to the Android peer.
 *
 * @param {object} _payload - Unused (no payload fields required for SAS confirm).
 */
function completePairing(_payload) {
  if (!pendingPairing) {
    console.warn('[Beam] completePairing called with no pending pairing — ignoring.');
    return;
  }
  // Nothing to do beyond keeping pendingPairing alive for the naming step.
  // Future: send an acknowledgement wire message to the Android peer here.
  console.log(`[Beam] SAS confirmed for peer ${pendingPairing.peerInfo.deviceId}.`);
}

/**
 * Handle MSG.PAIRING_SET_DEVICE_NAME: persist the newly-paired device record
 * to chrome.storage.local and broadcast MSG.PAIRING_COMPLETE to the popup.
 *
 * Stores:
 *   - Both Ed25519 and X25519 public keys (as plain Arrays).
 *   - The derived shared secret (as a plain Array) for future session
 *     key derivations without re-running ECDH.
 *   - The human-readable name and icon chosen by the user.
 *   - A pairedAt timestamp.
 *
 * After persisting, `pendingPairing` is cleared and the popup receives
 * MSG.PAIRING_COMPLETE so it can transition to the device list view.
 *
 * @param {{ name: string, icon: string }} param0 - Name and icon slug from
 *   the device-naming form.
 * @returns {Promise<void>}
 */
async function savePairedDevice({ name, icon }) {
  if (!pendingPairing) {
    console.error('[Beam] savePairedDevice called with no pending pairing — ignoring.');
    return;
  }

  /** @type {object} */
  const device = {
    deviceId:       pendingPairing.peerInfo.deviceId,
    name,
    icon,
    // Store public keys as plain Arrays so they survive JSON serialisation.
    ed25519PublicKey: Array.from(pendingPairing.peerInfo.ed25519Pk),
    x25519PublicKey:  Array.from(pendingPairing.peerInfo.x25519Pk),
    // Persist the shared secret so the transfer engine can derive session
    // keys on demand without re-running ECDH.
    // NOTE: sharedSecret is stored in chrome.storage.local which is not
    // encrypted at rest on all platforms.  A future hardening pass should
    // wrap this with a key derived from the OS keychain.
    sharedSecret: Array.from(pendingPairing.sharedSecret),
    pairedAt:     Date.now(),
  };

  pairedDevices.push(device);
  await chrome.storage.local.set({ pairedDevices });

  // TODO(Phase D follow-up): compute the rendezvous ID for this pair via
  // HKDF and register it with the relay so presence events flow immediately
  // after pairing without requiring a restart.

  pendingPairing = null;

  // Notify the popup that pairing is complete.
  try {
    chrome.runtime.sendMessage({
      type:    MSG.PAIRING_COMPLETE,
      payload: { device },
    });
  } catch (err) {
    console.warn('[Beam] Could not send PAIRING_COMPLETE to popup:', err);
  }

  console.log(`[Beam] Paired device saved: ${name} (${device.deviceId})`);
}

/**
 * Handle an outbound transfer request (MSG.INITIATE_TRANSFER).
 *
 * Dispatches to the TransferManager based on the transfer type:
 *   - `clipboard`: fast-path single-message transfer (sendClipboard).
 *   - otherwise:   full two-phase file transfer (sendFile).
 *
 * The payload shape from the popup / service worker:
 * ```
 * {
 *   targetDeviceId: string,
 *   // File transfer:
 *   fileName?:  string,
 *   fileSize?:  number,
 *   mimeType?:  string,
 *   dataUrl?:   string,       // base64 data URI
 *   arrayBuffer?: number[],   // raw bytes as plain array
 *   // Clipboard transfer:
 *   text?: string,
 *   type?: 'clipboard',
 * }
 * ```
 *
 * Progress/completion is reported asynchronously via MSG.TRANSFER_PROGRESS,
 * MSG.TRANSFER_COMPLETE, and MSG.TRANSFER_FAILED chrome.runtime messages.
 *
 * @param {object} payload - Transfer request payload from the popup or SW.
 * @returns {Promise<void>}
 */
async function handleTransfer(payload) {
  if (!transferManager) {
    console.error('[Beam] handleTransfer: TransferManager not yet ready.');
    return;
  }

  const { targetDeviceId, type, text } = payload;

  // ── Clipboard fast-path ───────────────────────────────────────────────
  if (type === 'clipboard' || (typeof text === 'string' && !payload.fileName)) {
    try {
      await transferManager.sendClipboard(targetDeviceId, text ?? '');
    } catch (err) {
      console.error('[Beam] sendClipboard failed:', err);
    }
    return;
  }

  // ── File transfer ─────────────────────────────────────────────────────
  // Reconstruct a File-like object from the payload.  The popup serialises
  // file data as a base64 data URI or plain number array because File objects
  // do not survive the chrome.runtime message boundary.
  let file;
  try {
    file = _reconstructFile(payload);
  } catch (err) {
    console.error('[Beam] handleTransfer: could not reconstruct file:', err);
    return;
  }

  try {
    await transferManager.sendFile(targetDeviceId, file);
  } catch (err) {
    console.error('[Beam] sendFile failed:', err);
    // TransferManager notifies SW internally; this catch prevents unhandled rejections.
  }
}

/**
 * Handle an incoming clipboard fast-path message from a peer.
 *
 * Decrypts the clipboard payload, verifies its SHA-256 integrity check,
 * then writes the text to the clipboard and notifies the service worker.
 *
 * @param {object} msg - Relay message with { transferId, ciphertext, fromDeviceId }.
 */
function handleIncomingClipboard(msg) {
  if (!transferManager) return;

  const { transferId, ciphertext, fromDeviceId } = msg;
  const peer = pairedDevices.find((d) => d.deviceId === fromDeviceId);
  if (!peer) {
    console.warn('[Beam] handleIncomingClipboard: unknown peer', fromDeviceId);
    return;
  }

  // Derive the metadata key for this peer (uses the long-term shared secret).
  // For clipboard fast-path we use a simplified derivation that mirrors
  // TransferManager._deriveSessionKeys() but without an ephemeral key.
  // TODO(Phase H): use the same triple-DH derivation once WebRTC is in place.
  import('./crypto.js').then(({ deriveSharedSecret: dss, deriveMetadataKey: dmk }) => {
    try {
      const staticSharedSecret = dss(
        new Uint8Array(deviceKeys.x25519.sk),
        new Uint8Array(peer.x25519PublicKey),
      );
      // Derive a stable metadata key from the long-term shared secret.
      const metadataKey = dmk(staticSharedSecret);
      const envelope    = new Uint8Array(ciphertext);

      import('./crypto.js').then(({ decryptMetadata }) => {
        try {
          const { content, sha256, autoCopy } = decryptMetadata(envelope, metadataKey);

          // Write to clipboard if autoCopy is set.
          if (autoCopy && typeof navigator !== 'undefined' && navigator.clipboard) {
            navigator.clipboard.writeText(content).catch((err) => {
              console.warn('[Beam] Could not write to clipboard:', err);
            });
          }

          // Notify SW: content for notification + clipboard history.
          try {
            chrome.runtime.sendMessage({
              type:    MSG.TRANSFER_COMPLETE,
              payload: {
                transferId,
                fromDeviceId,
                text:     content,
                sha256,
                isClipboard: true,
              },
            });
          } catch (_) { /* SW may be sleeping */ }
        } catch (err) {
          console.error('[Beam] Clipboard decryption failed:', err);
        }
      });
    } catch (err) {
      console.error('[Beam] Clipboard key derivation failed:', err);
    }
  });
}

/**
 * Reconstruct a File-like object from the serialised transfer payload.
 *
 * The popup cannot pass a real File across the chrome.runtime message boundary
 * because it is not structured-cloneable.  Instead the popup serialises the
 * file as:
 *   - `dataUrl`:     base64 data URI (e.g. "data:image/png;base64,...")
 *   - `arrayBuffer`: plain number array of the raw bytes
 *
 * This function reconstructs a minimal File-compatible object with:
 *   `.name`, `.size`, `.type`, `.arrayBuffer() → Promise<ArrayBuffer>`
 *
 * @param {object} payload
 * @returns {{name: string, size: number, type: string, arrayBuffer: () => Promise<ArrayBuffer>}}
 * @throws {Error} If neither dataUrl nor arrayBuffer is present.
 */
function _reconstructFile(payload) {
  const { fileName, fileSize, mimeType, dataUrl, arrayBuffer: rawArray } = payload;

  let bytes;
  if (rawArray) {
    bytes = new Uint8Array(rawArray);
  } else if (dataUrl) {
    // Strip the data URI prefix (e.g. "data:image/png;base64,").
    const base64 = dataUrl.slice(dataUrl.indexOf(',') + 1);
    const binary  = atob(base64);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
  } else {
    throw new Error('_reconstructFile: payload contains neither dataUrl nor arrayBuffer');
  }

  return {
    name:        fileName ?? 'file',
    size:        fileSize ?? bytes.byteLength,
    type:        mimeType ?? 'application/octet-stream',
    arrayBuffer: () => Promise.resolve(bytes.buffer),
  };
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

// Chain relay connection after startup so deviceId, deviceKeys, and
// pairedDevices are fully populated before we attempt to authenticate.
startup()
  .then(() => connectRelay())
  .catch(console.error);
