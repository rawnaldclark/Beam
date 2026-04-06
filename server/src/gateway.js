/**
 * gateway.js — WebSocket connection management with Ed25519 authentication.
 *
 * Each inbound WebSocket connection goes through a mandatory authentication
 * handshake before any other messages are processed:
 *
 *   Server → Client : { type: "challenge", challenge: "<64 hex chars>" }
 *   Client → Server : { type: "auth", deviceId, publicKey, signature, timestamp }
 *   Server → Client : { type: "auth-ok" }  |  { type: "auth-fail", reason: "..." }
 *
 * The signature must cover the raw challenge bytes concatenated with the UTF-8
 * encoding of the decimal timestamp string:
 *
 *   payload = challengeBytes || Buffer.from(String(timestamp))
 *   signature = Ed25519Sign(privKey, payload)           [base64-encoded]
 *
 * The public key is transmitted base64-encoded. The device ID is derived as:
 *
 *   deviceId = base64url( SHA-256(pubKeyBytes)[0:16] )
 *
 * @module gateway
 */

import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { MSG, validate } from './protocol.js';

// ---------------------------------------------------------------------------
// Wire @noble/ed25519 v2 synchronous SHA-512 implementation.
// Must be set before any sign/verify calls are made.
// ---------------------------------------------------------------------------
ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Auth window in milliseconds — reject timestamps outside this range. */
const AUTH_WINDOW_MS = 30_000;

/** Default time (ms) to wait for auth before forcibly closing the socket. */
const DEFAULT_AUTH_TIMEOUT_MS = 30_000;

/** Length of the challenge in bytes (transmitted as 64 lowercase hex chars). */
const CHALLENGE_BYTES = 32;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Derives a device ID from a raw Ed25519 public key.
 * deviceId = base64url( SHA-256(pubKey)[0:16] )
 *
 * @param {Uint8Array} pubKey - Raw 32-byte Ed25519 public key
 * @returns {string} base64url-encoded 16-byte prefix of the public key hash
 */
function deriveDeviceId(pubKey) {
  const hash = sha256(pubKey);
  return Buffer.from(hash.slice(0, 16)).toString('base64url');
}

/**
 * Serialises a message object to a JSON string and sends it over a WebSocket.
 * Silently ignores sends to already-closed sockets.
 *
 * @param {import('ws').WebSocket} ws
 * @param {object} msg
 */
function safeSend(ws, msg) {
  try {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  } catch {
    /* ignore — socket may have closed between the readyState check and send */
  }
}

// ---------------------------------------------------------------------------
// Gateway class
// ---------------------------------------------------------------------------

/**
 * Manages all active WebSocket connections, enforces the auth handshake, and
 * provides a message-routing interface for higher-level modules.
 *
 * Events emitted:
 *   'authenticated' (deviceId: string, ws: WebSocket)  — after successful auth
 *   'disconnect'    (deviceId: string)                  — after authenticated close
 *   'message'       (deviceId: string, msg: object, ws) — for authenticated messages
 *
 * @extends EventEmitter
 */
export class Gateway extends EventEmitter {
  /**
   * @param {object} opts
   * @param {import('ws').WebSocketServer} opts.wss         - Attached WebSocket server
   * @param {number} [opts.authTimeoutMs=30000]             - Ms before unauthenticated sockets are closed
   */
  constructor({ wss, authTimeoutMs = DEFAULT_AUTH_TIMEOUT_MS } = {}) {
    super();

    /**
     * Authenticated devices: deviceId → WebSocket.
     * @type {Map<string, import('ws').WebSocket>}
     */
    this.devices = new Map();

    /**
     * Reverse lookup: WebSocket → deviceId (for efficient disconnect cleanup).
     * @type {Map<import('ws').WebSocket, string>}
     */
    this.wsToDevice = new Map();

    /**
     * Pending auth challenges: WebSocket → challenge hex string.
     * Entries are removed on successful auth or socket close.
     * @type {Map<import('ws').WebSocket, string>}
     */
    this.pendingChallenges = new Map();

    /** Configurable auth timeout in milliseconds. @type {number} */
    this.authTimeoutMs = authTimeoutMs;

    /** External message handler set via onMessage(). @type {Function|null} */
    this._messageHandler = null;

    if (wss) {
      this._attachToWss(wss);
    }
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Registers a handler function that will be called with every authenticated
   * inbound message (after the auth handshake is complete).
   *
   * @param {(deviceId: string, msg: object, ws: import('ws').WebSocket) => void} handler
   */
  onMessage(handler) {
    this._messageHandler = handler;
  }

  /**
   * Sends a JSON message to an authenticated device by device ID.
   * Returns false if the device is not connected.
   *
   * @param {string} deviceId
   * @param {object} msg
   * @returns {boolean} true if the send was attempted
   */
  send(deviceId, msg) {
    const ws = this.devices.get(deviceId);
    if (!ws) return false;
    safeSend(ws, msg);
    return true;
  }

  /**
   * Sends a JSON message directly to a WebSocket instance.
   *
   * @param {import('ws').WebSocket} ws
   * @param {object} msg
   */
  sendTo(ws, msg) {
    safeSend(ws, msg);
  }

  // -------------------------------------------------------------------------
  // Private — WebSocketServer attachment
  // -------------------------------------------------------------------------

  /**
   * Attaches connection and error handlers to the provided WebSocketServer.
   * @param {import('ws').WebSocketServer} wss
   */
  _attachToWss(wss) {
    wss.on('connection', (ws) => this._onConnection(ws));
  }

  // -------------------------------------------------------------------------
  // Private — Connection lifecycle
  // -------------------------------------------------------------------------

  /**
   * Handles a new inbound WebSocket connection.
   * Generates a random challenge, stores it, sends it to the client, and
   * schedules an auth timeout.
   *
   * @param {import('ws').WebSocket} ws
   */
  _onConnection(ws) {
    // Generate a fresh 32-byte challenge for this connection
    const challengeBytes = randomBytes(CHALLENGE_BYTES);
    const challengeHex = challengeBytes.toString('hex');
    this.pendingChallenges.set(ws, challengeHex);

    // Send challenge immediately
    safeSend(ws, { type: MSG.CHALLENGE, challenge: challengeHex });

    // Schedule auth timeout — close the socket if auth not completed in time
    const authTimer = setTimeout(() => {
      if (this.pendingChallenges.has(ws)) {
        // Still unauthenticated — close the socket
        ws.close();
      }
    }, this.authTimeoutMs);

    // Ensure the timer doesn't keep the Node.js event loop alive
    if (authTimer.unref) authTimer.unref();

    // Attach per-socket handlers
    ws.on('message', (data) => this._onMessage(ws, data));
    ws.on('close', () => this._onClose(ws));
    ws.on('error', () => {
      /* errors are surfaced via the close event; suppress unhandled-error crashes */
    });
  }

  // -------------------------------------------------------------------------
  // Private — Message handling
  // -------------------------------------------------------------------------

  /**
   * Handles a raw WebSocket message frame.
   * Validates the JSON structure, routes auth messages to _handleAuth(), and
   * forwards authenticated messages to the registered handler.
   *
   * @param {import('ws').WebSocket} ws
   * @param {Buffer|string} data
   */
  _onMessage(ws, data) {
    // --- Parse JSON ---
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      safeSend(ws, { type: MSG.ERROR, message: 'Invalid JSON' });
      return;
    }

    // --- Protocol-level validation (type, required fields, size) ---
    const result = validate(msg);
    if (!result.valid) {
      safeSend(ws, { type: MSG.ERROR, message: result.error });
      return;
    }

    const isAuthenticated = this.wsToDevice.has(ws);

    // --- Pre-auth gate: only auth/reconnect are allowed before handshake ---
    if (!isAuthenticated) {
      if (msg.type === MSG.AUTH || msg.type === MSG.RECONNECT) {
        this._handleAuth(ws, msg);
      } else {
        safeSend(ws, { type: MSG.ERROR, message: 'not authenticated' });
      }
      return;
    }

    // --- Authenticated path ---
    const deviceId = this.wsToDevice.get(ws);

    // Handle ping internally — respond with pong
    if (msg.type === MSG.PING) {
      safeSend(ws, { type: MSG.PONG });
      return;
    }

    // Forward to external handler or emit as event
    if (this._messageHandler) {
      this._messageHandler(deviceId, msg, ws);
    }
    this.emit('message', deviceId, msg, ws);
  }

  // -------------------------------------------------------------------------
  // Private — Auth verification
  // -------------------------------------------------------------------------

  /**
   * Verifies an auth (or reconnect) message and registers the device on success.
   *
   * Verification order (fail-fast, cheapest checks first):
   *   1. Timestamp freshness (arithmetic only)
   *   2. Device ID derivation and comparison (hash + base64url)
   *   3. Ed25519 signature verification (most expensive)
   *
   * @param {import('ws').WebSocket} ws
   * @param {{ deviceId: string, publicKey: string, signature: string, timestamp: number }} msg
   */
  _handleAuth(ws, msg) {
    const challenge = this.pendingChallenges.get(ws);
    if (!challenge) {
      // Should not happen in normal flow but guard defensively
      safeSend(ws, { type: MSG.AUTH_FAIL, reason: 'No pending challenge for this connection' });
      return;
    }

    const { deviceId, publicKey, signature, timestamp } = msg;

    // --- Check 1: Timestamp freshness ---
    const age = Math.abs(Date.now() - timestamp);
    if (age > AUTH_WINDOW_MS) {
      safeSend(ws, { type: MSG.AUTH_FAIL, reason: 'timestamp out of range (must be within 30 seconds)' });
      return;
    }

    // --- Decode public key ---
    let pubKeyBytes;
    try {
      pubKeyBytes = Buffer.from(publicKey, 'base64');
      if (pubKeyBytes.length !== 32) throw new Error('wrong length');
    } catch {
      safeSend(ws, { type: MSG.AUTH_FAIL, reason: 'publicKey must be a base64-encoded 32-byte Ed25519 public key' });
      return;
    }

    // --- Check 2: Device ID derivation ---
    const expectedDeviceId = deriveDeviceId(pubKeyBytes);
    if (expectedDeviceId !== deviceId) {
      safeSend(ws, { type: MSG.AUTH_FAIL, reason: 'device ID does not match SHA-256(publicKey)[0:16]' });
      return;
    }

    // --- Decode signature ---
    let sigBytes;
    try {
      sigBytes = Buffer.from(signature, 'base64');
    } catch {
      safeSend(ws, { type: MSG.AUTH_FAIL, reason: 'signature must be base64-encoded' });
      return;
    }

    // --- Check 3: Ed25519 signature ---
    // Payload = challengeBytes || UTF-8(String(timestamp))
    const challengeBytes = Buffer.from(challenge, 'hex');
    const timestampBytes = Buffer.from(String(timestamp));
    const payload = Buffer.concat([challengeBytes, timestampBytes]);

    let signatureValid;
    try {
      signatureValid = ed.verify(sigBytes, payload, pubKeyBytes);
    } catch {
      signatureValid = false;
    }

    if (!signatureValid) {
      safeSend(ws, { type: MSG.AUTH_FAIL, reason: 'signature verification failed' });
      return;
    }

    // --- Auth success ---
    this.pendingChallenges.delete(ws);
    this.devices.set(deviceId, ws);
    this.wsToDevice.set(ws, deviceId);

    safeSend(ws, { type: MSG.AUTH_OK });
    this.emit('authenticated', deviceId, ws);
  }

  // -------------------------------------------------------------------------
  // Private — Disconnect cleanup
  // -------------------------------------------------------------------------

  /**
   * Cleans up all maps for a closing WebSocket.
   * Emits 'disconnect' if the socket was authenticated.
   *
   * @param {import('ws').WebSocket} ws
   */
  _onClose(ws) {
    // Remove pending challenge (covers unauthenticated closes)
    this.pendingChallenges.delete(ws);

    // Clean up authenticated device registration
    const deviceId = this.wsToDevice.get(ws);
    if (deviceId !== undefined) {
      this.wsToDevice.delete(ws);
      this.devices.delete(deviceId);
      this.emit('disconnect', deviceId);
    }
  }
}
