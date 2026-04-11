/**
 * signaling.js — WebRTC SDP/ICE relay for ZapTransfer.
 *
 * Relays SDP offers, SDP answers, and ICE candidates between two devices that
 * share a common rendezvous ID. Before forwarding any message the module
 * validates that both the sending device and the declared target are members
 * of the same rendezvous, preventing cross-session information leakage.
 *
 * Design decisions:
 *   - `handleMessage` returns a boolean so the caller (server.js) can chain
 *     handlers and short-circuit after the first match. `true` means "this
 *     module handled the message" (even if it rejected it with an error);
 *     `false` means "not a signaling message — pass it along".
 *   - Errors are sent back via `gateway.sendTo(ws, ...)` rather than
 *     `gateway.send(deviceId, ...)` because the ws reference is the most
 *     reliable return path at the point of rejection.
 *   - `targetDeviceId` is stripped from the relayed message so the receiving
 *     peer cannot learn the relay's internal routing field.
 *
 * @module signaling
 */

import { MSG } from './protocol.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The set of message types handled by this module.
 * Any type not in this set causes handleMessage() to return false immediately.
 *
 * @type {Set<string>}
 */
const SIGNALING_TYPES = new Set([
  MSG.SDP_OFFER,
  MSG.SDP_ANSWER,
  MSG.ICE_CANDIDATE,
  MSG.PAIRING_REQUEST,
  MSG.PAIRING_ACK,
  MSG.CLIPBOARD_TRANSFER,
  MSG.FILE_OFFER,
  MSG.FILE_ACCEPT,
  MSG.FILE_COMPLETE,
  // Beam E2E handshake — relay is a passthrough; rendezvous membership
  // is still enforced so these go through the same sender/target check.
  MSG.TRANSFER_INIT,
  MSG.TRANSFER_ACCEPT,
  MSG.TRANSFER_REJECT,
]);

// ---------------------------------------------------------------------------
// Signaling class
// ---------------------------------------------------------------------------

/**
 * Relays WebRTC signaling messages (SDP offer/answer, ICE candidates) between
 * paired devices that share a rendezvous ID.
 *
 * @example
 * const signaling = new Signaling(gateway, presence);
 * gateway.onMessage((deviceId, msg, ws) => {
 *   if (signaling.handleMessage(deviceId, msg, ws)) return;
 *   // ...other handlers
 * });
 */
export class Signaling {
  /**
   * @param {object} gateway  - Gateway instance (or compatible mock); must
   *                            expose send(deviceId, msg) and sendTo(ws, msg).
   * @param {object} presence - Presence instance (or compatible mock); must
   *                            expose getRendezvousPeers(rendezvousId).
   */
  constructor(gateway, presence) {
    /**
     * Reference to the gateway for outbound message delivery.
     * @type {object}
     */
    this._gateway = gateway;

    /**
     * Reference to the presence module for rendezvous membership lookups.
     * @type {object}
     */
    this._presence = presence;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Attempts to handle an inbound signaling message.
   *
   * Processing steps (fail-fast order):
   *   1. Type gate  — return false immediately for non-signaling types.
   *   2. Sender check — reject if fromDeviceId is not in the rendezvous.
   *   3. Target check — reject if targetDeviceId is not in the rendezvous.
   *   4. Relay       — build and forward the message to the target device.
   *
   * @param {string} fromDeviceId - Authenticated device ID of the sender.
   * @param {object} msg          - Validated protocol message object.
   * @param {import('ws').WebSocket} ws - Sender's WebSocket connection (used
   *                                      to deliver errors back to the sender).
   * @returns {boolean} true if the message was handled (relayed or rejected);
   *                    false if the message type is not a signaling type.
   */
  handleMessage(fromDeviceId, msg, ws) {
    // --- Step 1: Type gate ---
    // Return false for anything outside the signaling domain so the caller can
    // continue routing to the next handler.
    if (!SIGNALING_TYPES.has(msg.type)) {
      return false;
    }

    const { rendezvousId, targetDeviceId } = msg;

    // Retrieve the current membership Set for this rendezvous.
    // getRendezvousPeers() always returns a Set (empty for unknown IDs).
    const peers = this._presence.getRendezvousPeers(rendezvousId);

    // --- Step 2: Sender membership check ---
    // The sender must be a known member of the rendezvous to prevent devices
    // from injecting signals into sessions they were not invited to.
    if (!peers.has(fromDeviceId)) {
      this._gateway.sendTo(ws, {
        type: MSG.ERROR,
        message: `Not in rendezvous: sender "${fromDeviceId}" is not a member of rendezvous "${rendezvousId}"`,
      });
      return true;
    }

    // --- Step 3: Target membership check ---
    // The target must also share the rendezvous — this prevents a device from
    // probing the existence of arbitrary device IDs or relaying to unrelated peers.
    if (!peers.has(targetDeviceId)) {
      this._gateway.sendTo(ws, {
        type: MSG.ERROR,
        message: `Not in rendezvous: target "${targetDeviceId}" is not a member of rendezvous "${rendezvousId}"`,
      });
      return true;
    }

    // --- Step 4: Build and relay the message ---
    // Spread the original message, inject fromDeviceId, and remove targetDeviceId.
    // Removing targetDeviceId keeps the receiver from seeing routing metadata
    // that is only meaningful at the relay layer.
    const { targetDeviceId: _stripped, ...rest } = msg; // eslint-disable-line no-unused-vars
    const relayedMsg = {
      ...rest,
      fromDeviceId,
    };

    this._gateway.send(targetDeviceId, relayedMsg);

    return true;
  }
}
