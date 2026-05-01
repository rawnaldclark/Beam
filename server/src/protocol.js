/**
 * protocol.js — Message type constants and validation for ZapTransfer relay.
 *
 * All WebSocket messages are JSON objects with a required `type` field drawn
 * from the MSG constants. The validate() function provides a single entry
 * point for validating inbound messages before any handler logic runs.
 */

// ---------------------------------------------------------------------------
// Size limits (bytes, measured against JSON.stringify output)
// ---------------------------------------------------------------------------

/** Maximum JSON-encoded size for text messages. Enforced in validate(). */
export const MAX_TEXT_SIZE = 64 * 1024; // 64 KB

/**
 * Maximum size for binary relay frames. Sized to comfortably hold an
 * encrypted Beam file chunk: a 200 KB plaintext padded to the next
 * power-of-2 bucket (256 KB) plus the 16-byte Poly1305 tag and the
 * 24-byte Beam binary header. Previously 256 KB, which was exactly
 * 40 bytes short of the encrypted frame and caused the ws library to
 * close connections with code 1009 ("Message too big").
 */
export const MAX_BINARY_SIZE = 512 * 1024; // 512 KB

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

/**
 * Canonical string constants for every protocol message type.
 * Using the MSG object (instead of bare strings) throughout the codebase
 * catches typos at reference time rather than at runtime.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const MSG = Object.freeze({
  // Authentication handshake (server -> client, then client -> server)
  CHALLENGE:          'challenge',
  AUTH:               'auth',
  AUTH_OK:            'auth-ok',
  AUTH_FAIL:          'auth-fail',

  // Peer discovery
  REGISTER_RENDEZVOUS: 'register-rendezvous',
  PEER_ONLINE:        'peer-online',
  PEER_OFFLINE:       'peer-offline',

  // WebRTC signaling
  SDP_OFFER:          'sdp-offer',
  SDP_ANSWER:         'sdp-answer',
  ICE_CANDIDATE:      'ice-candidate',

  // Data relay management
  RELAY_BIND:         'relay-bind',
  RELAY_RELEASE:      'relay-release',
  RELAY_DATA:         'relay-data',

  // Pairing ceremony
  PAIRING_REQUEST:    'pairing-request',
  PAIRING_ACK:        'pairing-ack',

  // Clipboard transfer (relay-routed like pairing messages)
  CLIPBOARD_TRANSFER: 'clipboard-transfer',

  // File transfer signaling (relay-routed)
  FILE_OFFER:         'file-offer',
  FILE_ACCEPT:        'file-accept',
  FILE_COMPLETE:      'file-complete',

  // Beam E2E encryption handshake (relay is a dumb passthrough — no
  // server-side crypto; sender and receiver derive keys end-to-end).
  TRANSFER_INIT:      'transfer-init',
  TRANSFER_ACCEPT:    'transfer-accept',
  TRANSFER_REJECT:    'transfer-reject',

  // Beam v2: stateless E2E transport. The relay is again a passthrough —
  // these JSON messages carry resend requests and key-rotation handshake
  // signals between paired peers. See docs/superpowers/specs/2026-04-30.
  BEAM_V2_RESEND:        'beam-v2-resend',
  BEAM_V2_FAIL:          'beam-v2-fail',
  BEAM_V2_ROTATE_INIT:   'beam-v2-rotate-init',
  BEAM_V2_ROTATE_ACK:    'beam-v2-rotate-ack',
  BEAM_V2_ROTATE_COMMIT: 'beam-v2-rotate-commit',

  // Session management
  RECONNECT:          'reconnect',
  ERROR:              'error',
  PING:               'ping',
  PONG:               'pong',
});

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Returns a failure result with the given error message.
 * @param {string} error - Human-readable description of why validation failed.
 * @returns {{ valid: false, error: string }}
 */
const fail = (error) => ({ valid: false, error });

/** Singleton success result — no allocation on the hot path. */
const OK = Object.freeze({ valid: true });

/**
 * Checks that `value` is a non-empty string.
 * @param {unknown} value
 * @returns {boolean}
 */
const isNonEmptyString = (value) =>
  typeof value === 'string' && value.length > 0;

// Pre-built set of all known type strings for O(1) membership test.
const KNOWN_TYPES = new Set(Object.values(MSG));

// ---------------------------------------------------------------------------
// Per-type field rules
// ---------------------------------------------------------------------------
//
// Each rule is a function that receives the full message object and returns
// either null (all required fields present and valid) or an error string.
//
// Types not listed here have no additional field requirements beyond `type`.

/**
 * Shared auth/reconnect rule: deviceId, publicKey, signature (strings),
 * timestamp (positive number).
 * @param {{ deviceId?: unknown, publicKey?: unknown, signature?: unknown, timestamp?: unknown }} msg
 * @returns {string|null}
 */
const authRule = (msg) => {
  if (!isNonEmptyString(msg.deviceId))   return 'Missing or invalid field: deviceId (must be a non-empty string)';
  if (!isNonEmptyString(msg.publicKey))  return 'Missing or invalid field: publicKey (must be a non-empty string)';
  if (!isNonEmptyString(msg.signature))  return 'Missing or invalid field: signature (must be a non-empty string)';
  if (typeof msg.timestamp !== 'number' || msg.timestamp <= 0)
    return 'Missing or invalid field: timestamp (must be a positive number)';
  return null;
};

/**
 * Shared SDP offer/answer rule: targetDeviceId, rendezvousId, sdp (strings).
 * @param {{ targetDeviceId?: unknown, rendezvousId?: unknown, sdp?: unknown }} msg
 * @returns {string|null}
 */
const sdpRule = (msg) => {
  if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
  if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
  if (!isNonEmptyString(msg.sdp))            return 'Missing or invalid field: sdp (must be a non-empty string)';
  return null;
};

/**
 * Map from message type string to a validation rule function.
 * Rule returns null on success or an error string on failure.
 *
 * @type {Map<string, (msg: object) => string|null>}
 */
const FIELD_RULES = new Map([
  [MSG.AUTH, authRule],

  [MSG.REGISTER_RENDEZVOUS, (msg) => {
    if (!Array.isArray(msg.rendezvousIds) || msg.rendezvousIds.length === 0)
      return 'Missing or invalid field: rendezvousIds (must be a non-empty array)';
    return null;
  }],

  [MSG.SDP_OFFER,  sdpRule],
  [MSG.SDP_ANSWER, sdpRule],

  [MSG.ICE_CANDIDATE, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (msg.candidate === null || typeof msg.candidate !== 'object')
      return 'Missing or invalid field: candidate (must be a non-null object)';
    return null;
  }],

  [MSG.RELAY_BIND, (msg) => {
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    return null;
  }],

  [MSG.PAIRING_REQUEST, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.deviceId))       return 'Missing or invalid field: deviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.ed25519Pk))      return 'Missing or invalid field: ed25519Pk (must be a non-empty string)';
    if (!isNonEmptyString(msg.x25519Pk))       return 'Missing or invalid field: x25519Pk (must be a non-empty string)';
    return null;
  }],

  [MSG.PAIRING_ACK, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.deviceId))       return 'Missing or invalid field: deviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.ed25519Pk))      return 'Missing or invalid field: ed25519Pk (must be a non-empty string)';
    if (!isNonEmptyString(msg.x25519Pk))       return 'Missing or invalid field: x25519Pk (must be a non-empty string)';
    return null;
  }],

  [MSG.CLIPBOARD_TRANSFER, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (typeof msg.content !== 'string')       return 'Missing or invalid field: content (must be a string)';
    return null;
  }],

  [MSG.FILE_OFFER, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.fileName))       return 'Missing or invalid field: fileName (must be a non-empty string)';
    if (typeof msg.fileSize !== 'number' || msg.fileSize <= 0)
      return 'Missing or invalid field: fileSize (must be a positive number)';
    if (!isNonEmptyString(msg.mimeType))       return 'Missing or invalid field: mimeType (must be a non-empty string)';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    return null;
  }],

  [MSG.FILE_ACCEPT, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    return null;
  }],

  [MSG.FILE_COMPLETE, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    return null;
  }],

  // Beam E2E encryption handshake. The server never inspects the crypto
  // fields themselves — it only enforces that the envelope is well-formed
  // so we fail fast on garbage and keep the binary relay path pristine.
  [MSG.TRANSFER_INIT, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    if (!isNonEmptyString(msg.kind))           return 'Missing or invalid field: kind (must be a non-empty string)';
    if (msg.kind !== 'clipboard' && msg.kind !== 'file')
      return `Invalid field: kind must be "clipboard" or "file", got "${msg.kind}"`;
    if (!isNonEmptyString(msg.ephPkA))         return 'Missing or invalid field: ephPkA (must be a non-empty string)';
    if (!isNonEmptyString(msg.salt))           return 'Missing or invalid field: salt (must be a non-empty string)';
    if (typeof msg.v !== 'number' || msg.v <= 0)
      return 'Missing or invalid field: v (must be a positive number)';
    return null;
  }],

  [MSG.TRANSFER_ACCEPT, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    if (!isNonEmptyString(msg.ephPkB))         return 'Missing or invalid field: ephPkB (must be a non-empty string)';
    if (typeof msg.v !== 'number' || msg.v <= 0)
      return 'Missing or invalid field: v (must be a positive number)';
    return null;
  }],

  [MSG.TRANSFER_REJECT, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId (must be a non-empty string)';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId (must be a non-empty string)';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId (must be a non-empty string)';
    if (!isNonEmptyString(msg.errorCode))      return 'Missing or invalid field: errorCode (must be a non-empty string)';
    return null;
  }],

  [MSG.RECONNECT, authRule],

  // ── Beam v2 ────────────────────────────────────────────────────────────
  // Each v2 message carries the standard relay routing pair plus a few
  // type-specific fields. The server never inspects crypto material.

  [MSG.BEAM_V2_RESEND, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId';
    if (!Array.isArray(msg.missing) || msg.missing.length === 0)
      return 'Missing or invalid field: missing (must be a non-empty array)';
    return null;
  }],
  [MSG.BEAM_V2_FAIL, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId';
    if (!isNonEmptyString(msg.transferId))     return 'Missing or invalid field: transferId';
    if (!isNonEmptyString(msg.code))           return 'Missing or invalid field: code';
    return null;
  }],
  [MSG.BEAM_V2_ROTATE_INIT, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId';
    if (typeof msg.fromGen !== 'number' || msg.fromGen < 0)
      return 'Missing or invalid field: fromGen';
    if (typeof msg.toGen !== 'number' || msg.toGen <= msg.fromGen)
      return 'Missing or invalid field: toGen (must be > fromGen)';
    if (!isNonEmptyString(msg.nonce)) return 'Missing or invalid field: nonce';
    return null;
  }],
  [MSG.BEAM_V2_ROTATE_ACK, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId';
    if (typeof msg.fromGen !== 'number') return 'Missing or invalid field: fromGen';
    if (typeof msg.toGen   !== 'number') return 'Missing or invalid field: toGen';
    if (!isNonEmptyString(msg.nonce)) return 'Missing or invalid field: nonce';
    return null;
  }],
  [MSG.BEAM_V2_ROTATE_COMMIT, (msg) => {
    if (!isNonEmptyString(msg.targetDeviceId)) return 'Missing or invalid field: targetDeviceId';
    if (!isNonEmptyString(msg.rendezvousId))   return 'Missing or invalid field: rendezvousId';
    if (typeof msg.toGen !== 'number') return 'Missing or invalid field: toGen';
    return null;
  }],
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validates an inbound protocol message.
 *
 * Validation order (fail-fast):
 *   1. Must be a plain, non-null object
 *   2. Must have a non-empty `type` string field
 *   3. JSON-serialised size must not exceed MAX_TEXT_SIZE
 *   4. `type` must be a known MSG value
 *   5. Per-type required fields must be present and correctly typed
 *
 * @param {unknown} msg - The parsed message value (from JSON.parse or similar).
 * @returns {{ valid: true } | { valid: false, error: string }}
 */
export function validate(msg) {
  // --- Guard 1: must be a plain, non-null object ---
  if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
    return fail('Message must be an object');
  }

  // --- Guard 2: type field must be a non-empty string ---
  if (!isNonEmptyString(msg.type)) {
    return fail('Missing or empty type field');
  }

  // --- Guard 3: size check before any further work ---
  // JSON.stringify handles circular-reference risk: if msg came from
  // JSON.parse it cannot be circular, but we handle the error defensively.
  let serialised;
  try {
    serialised = JSON.stringify(msg);
  } catch {
    return fail('Message could not be serialised');
  }
  if (serialised.length > MAX_TEXT_SIZE) {
    return fail(`Message too large: ${serialised.length} bytes exceeds the ${MAX_TEXT_SIZE}-byte limit`);
  }

  // --- Guard 4: type must be a known protocol type ---
  if (!KNOWN_TYPES.has(msg.type)) {
    return fail(`Unknown message type: "${msg.type}"`);
  }

  // --- Guard 5: per-type field validation ---
  const rule = FIELD_RULES.get(msg.type);
  if (rule) {
    const error = rule(msg);
    if (error !== null) {
      return fail(error);
    }
  }

  return OK;
}
