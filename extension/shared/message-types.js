/**
 * message-types.js — Inter-component message type constants for the Beam extension.
 *
 * Two separate namespaces are exported:
 *
 *   MSG  — Internal chrome.runtime.sendMessage / postMessage types used
 *           between the service worker (background.js), the offscreen document,
 *           and the popup. These are never sent over the network.
 *
 *   WIRE — Relay wire-protocol message types. These mirror the MSG constants
 *           defined in server/src/protocol.js and must stay in sync with the
 *           server. They appear in JSON objects sent over the WebSocket to/from
 *           the relay, and in RTCDataChannel payloads between peers.
 *
 * Using frozen objects instead of bare strings catches typos at the call site
 * (accessing an unknown key returns undefined, which is easy to grep for)
 * rather than silently sending a malformed type string at runtime.
 */

// ---------------------------------------------------------------------------
// Internal extension message types (SW <-> Offscreen <-> Popup)
// ---------------------------------------------------------------------------

/**
 * Internal chrome.runtime.sendMessage / MessageChannel types.
 *
 * Naming convention: VERB_NOUN or NOUN_STATE.
 *   - Requests end in a plain noun  (e.g. GET_DEVICE_LIST)
 *   - Responses end in a past tense (e.g. DEVICE_LIST — the data itself)
 *   - Events end in _CHANGED or _COMPLETE / _FAILED
 *
 * @type {Readonly<Record<string, string>>}
 */
export const MSG = Object.freeze({
  // -------------------------------------------------------------------------
  // Service-worker keepalive
  // The popup sends KEEPALIVE_PING periodically while it is open so Chrome
  // does not suspend the service worker mid-transfer.
  // -------------------------------------------------------------------------

  /** Popup -> SW: bump the service-worker's activity timer. */
  KEEPALIVE_PING: 'keepalive-ping',

  /** SW -> Popup: acknowledgement of a keepalive ping. */
  KEEPALIVE_PONG: 'keepalive-pong',

  // -------------------------------------------------------------------------
  // File / clipboard transfers
  // -------------------------------------------------------------------------

  /**
   * Popup | SW -> Offscreen: begin sending data to a peer.
   * Payload: { transferId, targetDeviceId, fileName, fileSize, mimeType,
   *            dataUrl | arrayBuffer, useRelay }
   */
  INITIATE_TRANSFER: 'initiate-transfer',

  /**
   * Offscreen -> SW -> Popup: streaming progress update.
   * Payload: { transferId, bytesTransferred, totalBytes, speedBps }
   */
  TRANSFER_PROGRESS: 'transfer-progress',

  /**
   * Offscreen -> SW -> Popup: transfer finished successfully.
   * Payload: { transferId, fileName, fileSize, durationMs }
   */
  TRANSFER_COMPLETE: 'transfer-complete',

  /**
   * Offscreen -> SW -> Popup: transfer ended with an error.
   * Payload: { transferId, reason }
   */
  TRANSFER_FAILED: 'transfer-failed',

  /**
   * SW -> Popup: a remote peer wants to send us a file.
   * Payload: { transferId, fromDeviceId, fromDeviceName, fileName, fileSize, mimeType }
   */
  INCOMING_TRANSFER: 'incoming-transfer',

  // -------------------------------------------------------------------------
  // Screenshot / image capture
  // -------------------------------------------------------------------------

  /**
   * SW -> Offscreen: fetch an image from a URL and return its data URI.
   * Used to pull tab screenshots or clipboard images into a transferable form.
   * Payload: { url }
   */
  FETCH_IMAGE: 'fetch-image',

  /**
   * Offscreen -> SW: result of a FETCH_IMAGE request.
   * Payload: { url, dataUrl, mimeType } | { url, error }
   */
  IMAGE_FETCHED: 'image-fetched',

  /**
   * SW -> Offscreen: capture the visible area of the current tab.
   * Payload: { tabId }
   */
  CAPTURE_SCREENSHOT: 'capture-screenshot',

  // -------------------------------------------------------------------------
  // Device list / presence
  // -------------------------------------------------------------------------

  /**
   * Popup -> SW: request the current list of paired, online devices.
   * No payload required.
   */
  GET_DEVICE_LIST: 'get-device-list',

  /**
   * SW -> Popup: response carrying the device list.
   * Payload: { devices: Array<{ deviceId, name, platform, online, lastSeen }> }
   */
  DEVICE_LIST: 'device-list',

  /**
   * SW -> Popup: a device came online or went offline.
   * Payload: { deviceId, name, online }
   */
  DEVICE_PRESENCE_CHANGED: 'device-presence-changed',

  // -------------------------------------------------------------------------
  // Pairing flow
  // -------------------------------------------------------------------------

  /**
   * Popup -> SW: begin the QR / SAS pairing ceremony.
   * No payload required; SW generates the ephemeral key pair.
   */
  START_PAIRING: 'start-pairing',

  /**
   * SW -> Popup: the QR code payload is ready to render.
   * Payload: { qrData: string }  (URL-safe base64 blob for the QR library)
   */
  PAIRING_QR_DATA: 'pairing-qr-data',

  /**
   * SW -> Popup: a Short Authentication String is ready for out-of-band
   * comparison with the other device's display.
   * Payload: { sas: string }  (e.g. "7482-3951")
   */
  PAIRING_SAS: 'pairing-sas',

  /**
   * Popup -> SW: the user confirmed the SAS matches.
   * No payload required.
   */
  PAIRING_CONFIRM_SAS: 'pairing-confirm-sas',

  /**
   * Popup -> SW: the user has typed a friendly name for the new device.
   * Payload: { name: string }
   */
  PAIRING_SET_DEVICE_NAME: 'pairing-set-device-name',

  /**
   * SW -> Popup: pairing finished; the device is now trusted.
   * Payload: { deviceId, name }
   */
  PAIRING_COMPLETE: 'pairing-complete',

  // -------------------------------------------------------------------------
  // History queries
  // -------------------------------------------------------------------------

  /**
   * Popup -> SW: retrieve completed/failed transfer records.
   * No payload required.
   */
  GET_TRANSFER_HISTORY: 'get-transfer-history',

  /**
   * Popup -> SW: retrieve recent clipboard entries.
   * No payload required.
   */
  GET_CLIPBOARD_HISTORY: 'get-clipboard-history',

  // -------------------------------------------------------------------------
  // UI helpers
  // -------------------------------------------------------------------------

  /**
   * SW -> Background (self): update the extension action badge text and colour.
   * Payload: { text: string, color: string }
   */
  UPDATE_BADGE: 'update-badge',

  /**
   * SW -> Background (self): show a Chrome notification.
   * Payload: { title, message, iconUrl? }
   */
  SEND_NOTIFICATION: 'send-notification',
});

// ---------------------------------------------------------------------------
// Relay wire-protocol message types (WebSocket transport)
// ---------------------------------------------------------------------------

/**
 * Wire-protocol type strings for messages exchanged over the WebSocket
 * connection to the relay server.
 *
 * These values are identical to the MSG constants in server/src/protocol.js.
 * If the server protocol is updated, this object must be updated in lockstep.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const WIRE = Object.freeze({
  // -------------------------------------------------------------------------
  // Authentication handshake
  // Server sends CHALLENGE; client replies with AUTH; server responds AUTH_OK
  // or AUTH_FAIL.
  // -------------------------------------------------------------------------

  /** Server -> Client: nonce for the Ed25519 sign-challenge handshake. */
  CHALLENGE:           'challenge',

  /** Client -> Server: signed auth payload (deviceId, publicKey, signature, timestamp). */
  AUTH:                'auth',

  /** Server -> Client: authentication accepted; connection is now live. */
  AUTH_OK:             'auth-ok',

  /** Server -> Client: authentication rejected; connection will be closed. */
  AUTH_FAIL:           'auth-fail',

  // -------------------------------------------------------------------------
  // Peer discovery / rendezvous
  // -------------------------------------------------------------------------

  /**
   * Client -> Server: register one or more rendezvous IDs (derived from
   * paired device public keys) so the server can route peer signals.
   * Payload: { rendezvousIds: string[] }
   */
  REGISTER_RENDEZVOUS: 'register-rendezvous',

  /** Server -> Client: a peer associated with one of our rendezvous IDs came online. */
  PEER_ONLINE:         'peer-online',

  /** Server -> Client: a previously online peer disconnected. */
  PEER_OFFLINE:        'peer-offline',

  // -------------------------------------------------------------------------
  // WebRTC signaling
  // -------------------------------------------------------------------------

  /** Client -> Server -> Peer: WebRTC SDP offer. Payload: { targetDeviceId, rendezvousId, sdp }. */
  SDP_OFFER:           'sdp-offer',

  /** Client -> Server -> Peer: WebRTC SDP answer. Payload: { targetDeviceId, rendezvousId, sdp }. */
  SDP_ANSWER:          'sdp-answer',

  /** Client -> Server -> Peer: trickle ICE candidate. Payload: { targetDeviceId, rendezvousId, candidate }. */
  ICE_CANDIDATE:       'ice-candidate',

  // -------------------------------------------------------------------------
  // Data relay (fallback when WebRTC cannot establish a direct channel)
  // -------------------------------------------------------------------------

  /**
   * Client -> Server: bind a relay session for a transfer.
   * Payload: { transferId, targetDeviceId, rendezvousId }
   */
  RELAY_BIND:          'relay-bind',

  /**
   * Client -> Server: release a relay session when the transfer ends.
   * Payload: { transferId }
   */
  RELAY_RELEASE:       'relay-release',

  /**
   * Client <-> Server: carry an encrypted binary frame through the relay.
   * The body is a binary WebSocket frame; JSON envelope wraps metadata only.
   * Payload: { transferId, seq, data: ArrayBuffer }
   */
  RELAY_DATA:          'relay-data',

  // -------------------------------------------------------------------------
  // Session management
  // -------------------------------------------------------------------------

  /**
   * Client -> Server: re-authenticate an existing session after a reconnect.
   * Same payload shape as AUTH (deviceId, publicKey, signature, timestamp).
   */
  RECONNECT:           'reconnect',

  /**
   * Server -> Client: a protocol or application-level error occurred.
   * Payload: { code: string, message: string }
   */
  ERROR:               'error',

  /** Client -> Server: application-level ping (distinct from WebSocket ping frames). */
  PING:                'ping',

  /** Server -> Client: response to an application-level PING. */
  PONG:                'pong',
});
