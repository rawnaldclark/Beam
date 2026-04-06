/**
 * relay.js — Binary data passthrough with backpressure and session limits.
 *
 * Responsibilities:
 *   - Bind two authenticated devices into a relay session via RELAY_BIND.
 *   - Forward raw binary frames between the paired sockets without copying
 *     the payload into JSON (binary passthrough at the ws layer).
 *   - Apply TCP-level backpressure: pause the sender's underlying socket when
 *     the receiver's ws send-buffer exceeds BACKPRESSURE_HIGH (2 MB), and
 *     resume once it drains below BACKPRESSURE_LOW (512 KB).
 *   - Enforce a 500 MB per-session byte cap; reject further data with an ERROR
 *     frame once the limit is reached.
 *   - Clean up all sessions owned by a device on disconnect, notifying any
 *     live peer that the session has ended.
 *
 * Session lifecycle:
 *   1. Device A sends RELAY_BIND → session created with senderWs set.
 *   2. Device B sends RELAY_BIND (same transferId) → receiverWs set; session
 *      is now "complete" and ready to relay frames.
 *   3. Binary frames from either side are forwarded to the peer via
 *      relayBinary().
 *   4. Either device sends RELAY_RELEASE → session is destroyed.
 *   5. Either device disconnects → handleDisconnect() destroys all its sessions.
 *
 * @module relay
 */

import { MSG } from './protocol.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Bytes in a megabyte — used for threshold calculations. */
const MB = 1024 * 1024;

/**
 * High-water mark for receiver bufferedAmount.
 * When the receiver's ws.bufferedAmount exceeds this value the sender's
 * underlying TCP socket is paused to prevent unbounded memory growth.
 * @type {number}
 */
const BACKPRESSURE_HIGH = 2 * MB; // 2 MB

/**
 * Low-water mark for receiver bufferedAmount.
 * The drain handler resumes the sender only once bufferedAmount drops below
 * this threshold, providing hysteresis that prevents rapid pause/resume cycling.
 * @type {number}
 */
const BACKPRESSURE_LOW = 512 * 1024; // 512 KB

/**
 * Maximum bytes that may be relayed within a single session.
 * Once this cap is reached the session is considered exhausted and any further
 * relay attempt is rejected with an ERROR frame.
 * @type {number}
 */
const SESSION_LIMIT = 500 * MB; // 500 MB

// ---------------------------------------------------------------------------
// DataRelay class
// ---------------------------------------------------------------------------

/**
 * Manages binary relay sessions between pairs of authenticated devices.
 *
 * @example
 * const relay = new DataRelay({ gateway });
 * gateway.onMessage((deviceId, msg, ws) => {
 *   if (relay.handleMessage(deviceId, msg, ws)) return;
 *   // ...other handlers
 * });
 * // In the binary-frame handler:
 * relay.relayBinary(deviceId, binaryData, ws);
 */
export class DataRelay {
  /**
   * @param {object} opts
   * @param {object} opts.gateway - Gateway instance (or mock); must expose
   *                                sendTo(ws, msg).
   */
  constructor({ gateway } = {}) {
    /**
     * Active relay sessions keyed by transferId.
     *
     * Each entry has the shape:
     * {
     *   senderDeviceId:   string,
     *   receiverDeviceId: string,
     *   senderWs:         WebSocket | null,
     *   receiverWs:       WebSocket | null,
     *   bytesRelayed:     number,
     *   rendezvousId:     string,
     * }
     *
     * @type {Map<string, object>}
     */
    this.sessions = new Map();

    /**
     * Reverse-lookup: deviceId → Set of transferIds that device participates in.
     * Used by handleDisconnect() to quickly find all sessions to destroy.
     *
     * @type {Map<string, Set<string>>}
     */
    this._deviceSessions = new Map();

    /**
     * Reference to the gateway for sending error messages back to senders.
     * @type {object}
     */
    this._gateway = gateway ?? null;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Handles RELAY_BIND and RELAY_RELEASE protocol messages.
   *
   * Returns true if the message was a relay control message (handled or
   * rejected); returns false if the type is unrelated so the caller can
   * continue routing.
   *
   * @param {string} deviceId - Authenticated device ID of the sender.
   * @param {object} msg      - Validated protocol message.
   * @param {import('ws').WebSocket} ws - Sender's WebSocket connection.
   * @returns {boolean}
   */
  handleMessage(deviceId, msg, ws) {
    if (msg.type === MSG.RELAY_BIND) {
      this._handleBind(deviceId, msg, ws);
      return true;
    }

    if (msg.type === MSG.RELAY_RELEASE) {
      this._handleRelease(deviceId, msg, ws);
      return true;
    }

    return false;
  }

  /**
   * Attempts to relay a binary frame from `fromDeviceId` to its session peer.
   *
   * Processing steps (fail-fast):
   *   1. Find the session where fromDeviceId is a participant.
   *   2. Enforce the 500 MB per-session byte cap.
   *   3. Identify the peer WebSocket.
   *   4. Check backpressure — if peer buffer > BACKPRESSURE_HIGH, pause sender.
   *   5. Forward the frame to the peer.
   *   6. Increment bytesRelayed.
   *
   * @param {string} fromDeviceId - Authenticated device ID of the sender.
   * @param {Buffer|Uint8Array} data - Raw binary payload to forward.
   * @param {import('ws').WebSocket} fromWs - Sender's WebSocket connection.
   */
  relayBinary(fromDeviceId, data, fromWs) {
    // --- Step 1: Find session ---
    const session = this._sessionForDevice(fromDeviceId);
    if (!session) {
      // No active session — silently discard (device may have sent a late frame
      // after a release; flooding protection handled by rate limiter in Task 7).
      return;
    }

    // Ensure both sides are bound before relaying
    if (!session.senderWs || !session.receiverWs) {
      return;
    }

    // --- Step 2: Byte-cap check ---
    const chunkSize = Buffer.isBuffer(data) ? data.length : data.byteLength;
    if (session.bytesRelayed + chunkSize > SESSION_LIMIT) {
      if (this._gateway) {
        this._gateway.sendTo(fromWs, {
          type:    MSG.ERROR,
          message: `Session data limit reached: 500 MB per-session limit exceeded`,
        });
      }
      return;
    }

    // --- Step 3: Identify peer ---
    const isSender = fromDeviceId === session.senderDeviceId;
    const peerWs   = isSender ? session.receiverWs : session.senderWs;

    // --- Step 4: Backpressure check ---
    // If the peer's write buffer is above the high-water mark, pause the sender
    // at the TCP level so the Node.js event loop stops reading from that socket.
    // Register a drain handler to resume once the buffer falls below the low-water
    // mark, providing hysteresis.
    if (peerWs.bufferedAmount > BACKPRESSURE_HIGH) {
      this._applyBackpressure(fromWs, peerWs);
    }

    // --- Step 5: Forward frame ---
    // Use binary send (options object signals ws to treat payload as binary).
    peerWs.send(data, { binary: true });

    // --- Step 6: Track bytes ---
    session.bytesRelayed += chunkSize;
  }

  /**
   * Destroys all sessions in which `deviceId` is a participant and notifies
   * any live peer that the session has ended.
   *
   * Called by the server when a device's WebSocket closes.
   *
   * @param {string} deviceId
   */
  handleDisconnect(deviceId) {
    const transferIds = this._deviceSessions.get(deviceId);
    if (!transferIds) return;

    // Collect transfer IDs to avoid mutating the Set while iterating it
    for (const transferId of [...transferIds]) {
      this._destroySession(transferId, deviceId);
    }

    this._deviceSessions.delete(deviceId);
  }

  // ---------------------------------------------------------------------------
  // Private — RELAY_BIND
  // ---------------------------------------------------------------------------

  /**
   * Processes a RELAY_BIND message from a device.
   *
   * If no session exists for the transferId, a new one is created and the
   * binding device is recorded as the initiating side (senderDeviceId).
   *
   * If a session already exists (the peer has already bound), we record this
   * device as the receiver side, completing the pair.
   *
   * The mapping from deviceId → Set<transferId> is updated for both sides so
   * that handleDisconnect() can clean up efficiently.
   *
   * @param {string} deviceId
   * @param {{ transferId: string, targetDeviceId: string, rendezvousId: string }} msg
   * @param {import('ws').WebSocket} ws
   */
  _handleBind(deviceId, msg, ws) {
    const { transferId, targetDeviceId, rendezvousId } = msg;

    if (!this.sessions.has(transferId)) {
      // First device to bind — create the session skeleton.
      // We record the binding device as the sender (initiator) by convention.
      const session = {
        senderDeviceId:   deviceId,
        receiverDeviceId: targetDeviceId,
        senderWs:         ws,
        receiverWs:       null,
        bytesRelayed:     0,
        rendezvousId,
      };
      this.sessions.set(transferId, session);
    } else {
      // Second device to bind — complete the session.
      const session = this.sessions.get(transferId);

      // The second binder is the receiver side of the already-created session.
      // Both senderDeviceId and receiverDeviceId fields were set when the first
      // device bound; we just need to attach the WebSocket for whichever role
      // this device fills.
      if (deviceId === session.senderDeviceId) {
        session.senderWs = ws;
      } else {
        // Treat as receiver regardless (handles cases where the target bound
        // first before the initiator, which should not occur in practice but is
        // defended here for robustness).
        session.receiverDeviceId = deviceId;
        session.receiverWs       = ws;
      }
    }

    // Maintain reverse-lookup for both participants
    this._registerDeviceSession(deviceId, transferId);
    this._registerDeviceSession(targetDeviceId, transferId);
  }

  // ---------------------------------------------------------------------------
  // Private — RELAY_RELEASE
  // ---------------------------------------------------------------------------

  /**
   * Processes a RELAY_RELEASE message.
   * Destroys the session and notifies the peer if it is still connected.
   *
   * @param {string} deviceId
   * @param {{ transferId: string }} msg
   * @param {import('ws').WebSocket} _ws - Unused; present for handler signature uniformity.
   */
  _handleRelease(deviceId, msg, _ws) {
    const { transferId } = msg;
    if (!this.sessions.has(transferId)) return;
    this._destroySession(transferId, deviceId);
  }

  // ---------------------------------------------------------------------------
  // Private — Session lifecycle helpers
  // ---------------------------------------------------------------------------

  /**
   * Destroys a session by transferId, notifies any live peer, and removes
   * both participants' reverse-lookup entries.
   *
   * @param {string} transferId
   * @param {string} [initiatorDeviceId] - Device ID that triggered the destroy
   *                                       (used to identify the peer to notify).
   */
  _destroySession(transferId, initiatorDeviceId) {
    const session = this.sessions.get(transferId);
    if (!session) return;

    this.sessions.delete(transferId);

    // Remove from reverse-lookup for both participants
    this._unregisterDeviceSession(session.senderDeviceId,   transferId);
    this._unregisterDeviceSession(session.receiverDeviceId, transferId);

    // Notify the peer (the side that did NOT initiate the destroy) if connected
    if (initiatorDeviceId !== undefined) {
      const isSender = initiatorDeviceId === session.senderDeviceId;
      const peerWs   = isSender ? session.receiverWs : session.senderWs;

      if (peerWs && peerWs.readyState === 1 /* OPEN */ && this._gateway) {
        this._gateway.sendTo(peerWs, {
          type:       MSG.RELAY_RELEASE,
          transferId,
          message:    `Peer disconnected`,
        });
      }
    }
  }

  /**
   * Adds a transferId to a device's session set, creating the set if needed.
   *
   * @param {string} deviceId
   * @param {string} transferId
   */
  _registerDeviceSession(deviceId, transferId) {
    if (!this._deviceSessions.has(deviceId)) {
      this._deviceSessions.set(deviceId, new Set());
    }
    this._deviceSessions.get(deviceId).add(transferId);
  }

  /**
   * Removes a transferId from a device's session set.
   * No-ops if the device or transferId is not present.
   *
   * @param {string} deviceId
   * @param {string} transferId
   */
  _unregisterDeviceSession(deviceId, transferId) {
    const set = this._deviceSessions.get(deviceId);
    if (!set) return;
    set.delete(transferId);
    if (set.size === 0) {
      this._deviceSessions.delete(deviceId);
    }
  }

  /**
   * Finds the first session where `deviceId` is either the sender or receiver.
   * Returns null if no matching session exists.
   *
   * O(k) where k = number of transferIds for the device (typically 1).
   *
   * @param {string} deviceId
   * @returns {object|null}
   */
  _sessionForDevice(deviceId) {
    const transferIds = this._deviceSessions.get(deviceId);
    if (!transferIds) return null;

    for (const transferId of transferIds) {
      const session = this.sessions.get(transferId);
      if (session) return session;
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Private — Backpressure
  // ---------------------------------------------------------------------------

  /**
   * Pauses `fromWs._socket` and registers a one-shot drain handler on `peerWs`
   * that resumes `fromWs._socket` once the peer's buffer falls below the
   * low-water mark.
   *
   * Using `_socket.pause()` rather than `ws.pause()` avoids interacting with
   * the ws-level message queue and operates directly at the TCP layer for
   * maximal efficiency.
   *
   * The drain handler guard (`if (peerWs.bufferedAmount <= BACKPRESSURE_LOW)`)
   * prevents a resume if the buffer is still high (the drain event fires
   * repeatedly until the buffer empties).
   *
   * @param {import('ws').WebSocket} fromWs - The socket to pause.
   * @param {import('ws').WebSocket} peerWs - The congested receiver socket.
   */
  _applyBackpressure(fromWs, peerWs) {
    // Pause at the TCP level so no further data is read from the OS buffer
    if (fromWs._socket) {
      fromWs._socket.pause();
    } else {
      fromWs.pause();
    }

    // Register a drain handler if peerWs supports event listeners
    if (typeof peerWs.on === 'function') {
      const onDrain = () => {
        // Only resume if the buffer has fallen to the low-water mark
        if (peerWs.bufferedAmount <= BACKPRESSURE_LOW) {
          if (fromWs._socket) {
            fromWs._socket.resume();
          } else {
            fromWs.resume();
          }
          peerWs.removeListener('drain', onDrain);
        }
      };
      peerWs.on('drain', onDrain);
    }
  }
}
