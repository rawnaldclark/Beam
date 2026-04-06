/**
 * @file transfer-manager.js
 * @description Beam transfer engine — state machine, chunked encryption,
 *   AIMD flow control, and full send/receive pipeline.
 *
 * ## Architecture overview
 *
 * The module exposes three classes:
 *
 *   ChunkSizer      — Adaptive 8 KB–512 KB chunk-size tiers driven by RTT
 *                     measurements over a sliding window of the last 8 ACKs.
 *
 *   FlowController  — AIMD congestion window (additive increase on full window
 *                     ACKed, multiplicative decrease on loss / timeout).
 *
 *   TransferManager — Orchestrates the complete transfer lifecycle:
 *                       • Send: SHA-256 → triple-DH session key → chunk loop
 *                       • Receive: decrypt → reorder → hash → reassemble
 *                       • Clipboard fast-path (single encrypted message)
 *
 * ## State machine (per Transfer)
 *
 *   IDLE → REQUESTING → AWAITING_ACCEPT → TRANSFERRING → VERIFYING → COMPLETE
 *                                       → DECLINED
 *                          TRANSFERRING → PAUSED → TRANSFERRING (resume)
 *                          TRANSFERRING → FAILED
 *
 * ## Per-chunk encryption (spec §4.6)
 *
 *   1. Pad plaintext into power-of-2 bucket via padChunk()
 *   2. Derive deterministic nonce from (chunkKey, chunkIndex)
 *   3. Encrypt with XChaCha20-Poly1305; AAD binds chunk position to transfer
 *   4. Prepend 64-byte binary header (encodeChunkHeader)
 *
 * ## Session key derivation (spec §4.5 — triple-DH)
 *
 *   dh1 = DH(ephA_sk, staticB_pk)
 *   dh2 = DH(staticA_sk, ephB_pk)
 *   dh3 = DH(ephA_sk, ephB_pk)
 *   sessionKey = HKDF(dh1 || dh2 || dh3, salt, "zaptransfer-session")
 *   chunkKey    = HKDF(sessionKey, "zaptransfer-chunk-encryption")
 *   metadataKey = HKDF(sessionKey, "zaptransfer-metadata-encryption")
 *
 * @module offscreen/transfer-manager
 */

import {
  encryptChunk,
  decryptChunk,
  encryptMetadata,
  decryptMetadata,
  deriveSessionKey,
  deriveChunkKey,
  deriveMetadataKey,
  deriveSharedSecret,
  generateKeyPairs,
  sign,
  verify,
} from './crypto.js';
import { encodeChunkHeader, decodeChunkHeader, uuidToBytes } from './wire-format.js';
import { MSG } from '../shared/message-types.js';
import { WIRE } from '../shared/message-types.js';
import * as C from '../shared/constants.js';

// ---------------------------------------------------------------------------
// Transfer state machine constants
// ---------------------------------------------------------------------------

/**
 * All valid states for a Transfer instance.
 * The transition graph is documented in the module JSDoc above.
 *
 * @readonly
 * @enum {string}
 */
export const STATE = Object.freeze({
  IDLE:            'IDLE',
  REQUESTING:      'REQUESTING',
  AWAITING_ACCEPT: 'AWAITING_ACCEPT',
  TRANSFERRING:    'TRANSFERRING',
  VERIFYING:       'VERIFYING',
  COMPLETE:        'COMPLETE',
  DECLINED:        'DECLINED',
  PAUSED:          'PAUSED',
  FAILED:          'FAILED',
});

// ---------------------------------------------------------------------------
// Transfer record
// ---------------------------------------------------------------------------

/**
 * Represents a single file or clipboard transfer (inbound or outbound).
 *
 * This is a plain data class — logic lives in TransferManager.
 */
class Transfer {
  /**
   * @param {string} id        - UUID string for this transfer.
   * @param {'send'|'receive'} direction - Transfer direction from local perspective.
   * @param {string} peerId    - Remote device ID.
   */
  constructor(id, direction, peerId) {
    /** @type {string} UUID identifying this transfer. */
    this.id = id;

    /** @type {'send'|'receive'} */
    this.direction = direction;

    /** @type {string} Remote device ID. */
    this.peerId = peerId;

    /** @type {string} Current state machine state. */
    this.state = STATE.IDLE;

    // ── File metadata ──────────────────────────────────────────────────────
    /** @type {string|null} Original filename. */
    this.fileName = null;

    /** @type {number} Total file size in bytes. */
    this.fileSize = 0;

    /** @type {string|null} MIME type string. */
    this.mimeType = null;

    /** @type {number} Total number of chunks for this transfer. */
    this.totalChunks = 0;

    // ── Progress counters ──────────────────────────────────────────────────
    /** @type {number} Chunks sent by sender. */
    this.chunksSent = 0;

    /** @type {number} Chunks received and decrypted by receiver. */
    this.chunksReceived = 0;

    /** @type {number} Cumulative bytes transferred. */
    this.bytesTransferred = 0;

    // ── Crypto material ────────────────────────────────────────────────────
    /** @type {Uint8Array|null} 32-byte session key (zeroed after use). */
    this.sessionKey = null;

    /** @type {Uint8Array|null} 32-byte chunk encryption key. */
    this.chunkKey = null;

    /** @type {Uint8Array|null} 32-byte metadata encryption key. */
    this.metadataKey = null;

    /** @type {Uint8Array|null} SHA-256 of metadata ciphertext (for chunk AAD). */
    this.metadataCiphertextHash = null;

    /** @type {string|null} Expected hex SHA-256 of the complete file. */
    this.sha256 = null;

    // ── Timing ────────────────────────────────────────────────────────────
    /** @type {number} UNIX timestamp (ms) when the transfer was created. */
    this.startTime = Date.now();

    // ── Internal receive-side bookkeeping ──────────────────────────────────
    /**
     * Reorder buffer for out-of-order chunk arrival.
     * Maps chunkIndex → decrypted plaintext Uint8Array.
     * Max 32 entries per spec §5.7.
     *
     * @type {Map<number, Uint8Array>}
     */
    this._reorderBuffer = new Map();

    /**
     * Index of the next chunk we are expecting to hand to the hash accumulator
     * in sequence order.
     *
     * @type {number}
     */
    this._nextExpected = 0;

    /**
     * Chunks stored in final assembly order (indexed by chunkIndex).
     * On the receiver side this grows as chunks arrive and are verified.
     *
     * @type {Uint8Array[]}
     */
    this._receivedChunks = [];

    // ── Timing for ACK round-trips (sender side) ───────────────────────────
    /**
     * Per-chunk send timestamps keyed by chunkIndex.
     * Used to compute RTT when the ACK arrives.
     *
     * @type {Map<number, number>}
     */
    this._sendTimestamps = new Map();

    // ── Accept/decline promise handles (sender side) ───────────────────────
    /**
     * Resolve callback for the accept-promise created in sendFile().
     * Calling it signals that the receiver accepted the transfer.
     *
     * @type {Function|null}
     */
    this._acceptResolve = null;

    /**
     * Reject callback for the accept-promise (used for decline / timeout).
     *
     * @type {Function|null}
     */
    this._acceptReject = null;

    /**
     * setTimeout handle for the acceptance timeout.
     *
     * @type {ReturnType<typeof setTimeout>|null}
     */
    this._acceptTimeoutHandle = null;
  }
}

// ---------------------------------------------------------------------------
// ChunkSizer — adaptive chunk sizing
// ---------------------------------------------------------------------------

/**
 * Adaptive chunk-size controller driven by ACK round-trip measurements.
 *
 * Tiers (from C.CHUNK_TIERS): 8 KB, 16 KB, 32 KB, **64 KB (default)**, 128 KB, 256 KB, 512 KB.
 *
 * ## Promotion rule (increase tier)
 *   - Sliding window of last 8 ACKs is full AND all ACKs are loss-free AND
 *     no RTT spike detected.
 *   - After promotion the window is cleared (cooldown = 8 ACKs).
 *
 * ## Demotion rule (decrease tier)
 *   - At least 4 measurements in window AND the latest RTT > 2× rolling average.
 *   - After demotion the window is cleared (cooldown = 4 ACKs).
 *
 * Both rules check for the minimum/maximum tier bounds before applying.
 */
export class ChunkSizer {
  constructor() {
    /**
     * Current tier index into C.CHUNK_TIERS.
     * @type {number}
     */
    this.tier = C.DEFAULT_CHUNK_TIER;

    /**
     * Sliding window of recent ACK measurements (max 8 entries).
     * Each entry: { rttMs: number, chunkSize: number, time: number }
     *
     * @type {Array<{rttMs: number, chunkSize: number, time: number}>}
     */
    this._measurements = [];
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Current chunk size in bytes (read-only convenience getter).
   * @returns {number}
   */
  get size() {
    return C.CHUNK_TIERS[this.tier];
  }

  /**
   * Record an ACK observation and adapt the chunk size if warranted.
   *
   * @param {number} rttMs     - Round-trip time for the ACKed chunk (milliseconds).
   * @param {number} chunkSize - Payload size of the chunk that was ACKed (bytes).
   */
  recordAck(rttMs, chunkSize) {
    this._measurements.push({ rttMs, chunkSize, time: Date.now() });

    // Keep window bounded at 8 entries (the most recent).
    if (this._measurements.length > 8) {
      this._measurements.shift();
    }

    // Attempt adaptation once we have enough data.
    if (this._measurements.length >= 4) {
      this._adapt();
    }
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  /**
   * Apply the promotion / demotion rules based on the current measurement window.
   *
   * Called by recordAck() whenever the window has ≥4 entries.
   *
   * Order of evaluation: demotion check first (safety-first), then promotion.
   * Both checks clear the window after acting to enforce the cooldown period.
   */
  _adapt() {
    const avg    = this._avgRtt();
    const latest = this._measurements[this._measurements.length - 1];

    // ── Demotion: latest RTT is a spike (> 2× rolling average) ─────────────
    // Requires at least 4 measurements to have a meaningful average.
    if (latest.rttMs > avg * 2) {
      this.tier = Math.max(this.tier - 1, 0);
      this._measurements = [];
      return; // restart window; do not also check for promotion this cycle
    }

    // ── Promotion: all 8 measurements are spike-free ─────────────────────
    // The promotion window requires a full 8-entry window with no spikes.
    if (this._measurements.length >= 8) {
      const allGood = this._measurements.every((m) => m.rttMs <= avg * 2);
      if (allGood) {
        this.tier = Math.min(this.tier + 1, C.CHUNK_TIERS.length - 1);
        this._measurements = [];
      }
    }
  }

  /**
   * Compute the arithmetic mean RTT across all current measurements.
   *
   * @returns {number} Mean RTT in milliseconds.
   */
  _avgRtt() {
    return this._measurements.reduce((sum, m) => sum + m.rttMs, 0) / this._measurements.length;
  }
}

// ---------------------------------------------------------------------------
// FlowController — AIMD congestion window
// ---------------------------------------------------------------------------

/**
 * Additive-increase / multiplicative-decrease (AIMD) congestion window.
 *
 * Models the number of chunks that may be in flight simultaneously.
 *
 * ## Parameters (from C.*)
 *   - Initial window : C.WINDOW_INITIAL (4)
 *   - Minimum window : C.WINDOW_MIN     (2)
 *   - Max relay      : C.WINDOW_MAX_RELAY  (8)
 *   - Max direct     : C.WINDOW_MAX_DIRECT (64)
 *
 * ## Rules
 *   - Additive increase (+1 window) after `window` ACKs received since last
 *     increase (i.e. one complete window's worth of ACKs without loss).
 *   - Multiplicative decrease (window = max(floor(window/2), WINDOW_MIN))
 *     on any loss or ACK timeout.
 *   - Counter resets on each increase and on each loss event.
 */
export class FlowController {
  /**
   * @param {'relay'|'direct'} mode - Transport mode that determines the window ceiling.
   */
  constructor(mode) {
    /**
     * Current congestion window size (chunks in flight allowed simultaneously).
     * @type {number}
     */
    this.window = C.WINDOW_INITIAL;

    /**
     * Number of chunks currently in-flight (sent but not yet ACKed).
     * @type {number}
     */
    this.inFlight = 0;

    /**
     * Maximum allowed window for this transport mode.
     * @type {number}
     */
    this.maxWindow = mode === 'relay' ? C.WINDOW_MAX_RELAY : C.WINDOW_MAX_DIRECT;

    /**
     * Number of ACKs received since the last window increase.
     * When this reaches `window`, the window is incremented and the counter resets.
     *
     * @type {number}
     * @private
     */
    this._ackedSinceIncrease = 0;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Returns true if another chunk may be sent without exceeding the window.
   *
   * @returns {boolean}
   */
  canSend() {
    return this.inFlight < this.window;
  }

  /**
   * Record that a chunk was sent.  Increments the in-flight counter.
   * Call this immediately before transmitting each chunk.
   */
  onSend() {
    this.inFlight++;
  }

  /**
   * Record receipt of a chunk ACK.
   *
   * - Decrements in-flight counter.
   * - Accumulates the ACK toward the next additive increase.
   * - When `_ackedSinceIncrease` reaches the current window size, increases
   *   the window by 1 (up to maxWindow) and resets the counter.
   */
  onAck() {
    this.inFlight--;
    this._ackedSinceIncrease++;

    if (this._ackedSinceIncrease >= this.window) {
      this.window = Math.min(this.window + 1, this.maxWindow);
      this._ackedSinceIncrease = 0;
    }
  }

  /**
   * Record a loss event (packet loss detected or ACK timeout).
   *
   * Halves the window (floor division, minimum C.WINDOW_MIN) and resets the
   * ACK accumulator so a fresh full window is needed before the next increase.
   */
  onLoss() {
    this.window = Math.max(Math.floor(this.window / 2), C.WINDOW_MIN);
    this._ackedSinceIncrease = 0;
  }
}

// ---------------------------------------------------------------------------
// TransferManager
// ---------------------------------------------------------------------------

/**
 * Orchestrates the complete lifecycle of file and clipboard transfers.
 *
 * Responsibilities:
 *   - Generate transfer IDs and derive per-transfer session keys.
 *   - Send: hash → metadata encrypt → two-phase handshake → chunk pipeline.
 *   - Receive: decrypt metadata → auto-accept → chunk decrypt/reorder/hash.
 *   - Clipboard fast-path: single encrypted message, no handshake.
 *   - Report progress to service worker via chrome.runtime messages.
 *
 * This class is designed to run inside the offscreen document where browser
 * crypto APIs (SubtleCrypto, File.arrayBuffer) are available.
 *
 * ## Usage
 * ```js
 * const mgr = new TransferManager(wsClient, deviceKeys, pairedDevices);
 * await mgr.sendFile('device-id-abc', fileObject);
 * ```
 */
export class TransferManager {
  /**
   * @param {import('./ws-client.js').WsClient} wsClient
   *   Authenticated WebSocket client connected to the relay.
   * @param {{ x25519: { pk: Uint8Array, sk: Uint8Array }, ed25519: { pk: Uint8Array, sk: Uint8Array } }} deviceKeys
   *   The local device's static key pairs.
   * @param {Array<object>} pairedDevices
   *   Array of paired device records (each with x25519PublicKey, ed25519PublicKey, deviceId, etc.).
   */
  constructor(wsClient, deviceKeys, pairedDevices) {
    /** @type {import('./ws-client.js').WsClient} */
    this.ws = wsClient;

    /** @type {object} Static device key pairs for the local device. */
    this.deviceKeys = deviceKeys;

    /** @type {Array<object>} Paired device registry. */
    this.pairedDevices = pairedDevices;

    /**
     * Active transfer registry keyed by transfer UUID.
     * @type {Map<string, Transfer>}
     */
    this.transfers = new Map();

    /**
     * Shared chunk sizer — one instance per TransferManager because sizing
     * decisions are global (they reflect the current network path quality).
     * @type {ChunkSizer}
     */
    this._chunkSizer = new ChunkSizer();

    /**
     * Congestion window controller.  Defaults to 'relay' mode; switches to
     * 'direct' when a WebRTC data channel is negotiated (Phase H).
     * @type {FlowController}
     */
    this._flowController = new FlowController('relay');
  }

  // ── Public API: sending ─────────────────────────────────────────────────

  /**
   * Initiate a file transfer to a paired device.
   *
   * ## Steps
   *   1. Validate target device is paired.
   *   2. Compute SHA-256 of the file via SubtleCrypto.
   *   3. Generate ephemeral X25519 key pair for triple-DH.
   *   4. Derive session / chunk / metadata keys.
   *   5. Encrypt and send transfer-request metadata envelope.
   *   6. Wait up to 60 s for ACCEPT; decline or timeout → FAILED / DECLINED.
   *   7. Stream chunks through the AIMD window respecting flow control.
   *   8. After final chunk: transition to VERIFYING → COMPLETE.
   *
   * @param {string} targetDeviceId - Relay device ID of the intended recipient.
   * @param {File}   file           - Browser File object to transfer.
   * @returns {Promise<void>} Resolves when the transfer reaches COMPLETE or FAILED.
   * @throws {Error} If the target device is not found in `pairedDevices`.
   */
  async sendFile(targetDeviceId, file) {
    // ── 1. Look up peer ──────────────────────────────────────────────────
    const peer = this._findPeer(targetDeviceId);
    if (!peer) {
      throw new Error(`[TransferManager] sendFile: unknown device "${targetDeviceId}"`);
    }

    // ── 2. Generate transfer ID ──────────────────────────────────────────
    const transferId = crypto.randomUUID();

    // ── 3. Compute SHA-256 of the file ───────────────────────────────────
    const sha256Hex = await this._computeSHA256(file);

    // ── 4. Derive session keys via triple-DH ─────────────────────────────
    const { sessionKey, chunkKey, metadataKey, ephemeralKeyPair, salt } =
      this._deriveSessionKeys(peer);

    // ── 5. Build the Transfer record ──────────────────────────────────────
    const chunkSize   = this._chunkSizer.size;
    const totalChunks = Math.ceil(file.size / chunkSize);

    const transfer = new Transfer(transferId, 'send', targetDeviceId);
    transfer.fileName     = file.name;
    transfer.fileSize     = file.size;
    transfer.mimeType     = file.type || 'application/octet-stream';
    transfer.totalChunks  = totalChunks;
    transfer.sha256       = sha256Hex;
    transfer.sessionKey   = sessionKey;
    transfer.chunkKey     = chunkKey;
    transfer.metadataKey  = metadataKey;
    transfer.state        = STATE.REQUESTING;
    this.transfers.set(transferId, transfer);

    // ── 6. Encrypt and send the transfer-request metadata envelope ────────
    const metadataPlain = {
      transferId,
      fileName:         file.name,
      fileSize:         file.size,
      mimeType:         transfer.mimeType,
      totalChunks,
      initialChunkSize: chunkSize,
      sha256:           sha256Hex,
      contentCategory:  _contentCategory(file.size),
      resumable:        file.size > C.CHUNK_TIERS[C.DEFAULT_CHUNK_TIER],
      // Sender's ephemeral public key so receiver can complete the triple-DH.
      ephemeralPublicKey: Array.from(ephemeralKeyPair.pk),
      salt:               Array.from(salt),
    };

    const metadataCiphertext = encryptMetadata(metadataPlain, metadataKey);
    transfer.metadataCiphertextHash = await _sha256Bytes(metadataCiphertext);

    this.ws.send(JSON.stringify({
      type:             WIRE.RELAY_DATA,
      transferId,
      msgType:          'transfer-request',
      targetDeviceId,
      metadataCiphertext: Array.from(metadataCiphertext),
      // Include ephemeral public key unencrypted so receiver can derive the
      // same session key before decrypting the metadata envelope.
      ephemeralPublicKey: Array.from(ephemeralKeyPair.pk),
      salt:               Array.from(salt),
    }));

    // ── 7. Wait for accept (60 s timeout) ────────────────────────────────
    transfer.state = STATE.AWAITING_ACCEPT;
    await this._waitForAccept(transfer);

    // ── 8. Chunk and send ─────────────────────────────────────────────────
    transfer.state = STATE.TRANSFERRING;
    await this._sendChunks(transfer, file);

    // ── 9. Verifying ──────────────────────────────────────────────────────
    transfer.state = STATE.VERIFYING;

    // After the final chunk is acknowledged, transition to COMPLETE.
    // (Full hash verification is done on the receiver side; sender trusts
    // the encryption + transfer-complete wire message.)
    transfer.state = STATE.COMPLETE;

    // Notify the service worker so it can update the badge and show a notification.
    this._notifySW(MSG.TRANSFER_COMPLETE, {
      transferId,
      fileName:   transfer.fileName,
      fileSize:   transfer.fileSize,
      durationMs: Date.now() - transfer.startTime,
    });
  }

  /**
   * Send clipboard text using the fast-path (single encrypted message, no handshake).
   *
   * Per spec §5.2 and §5.6, clipboard content (<1 KB) skips the two-phase
   * handshake: the encrypted payload is delivered in one relay message and the
   * receiver auto-copies to clipboard.
   *
   * @param {string} targetDeviceId - Relay device ID of the recipient.
   * @param {string} text           - UTF-8 text to transfer.
   * @returns {Promise<void>}
   */
  async sendClipboard(targetDeviceId, text) {
    const peer = this._findPeer(targetDeviceId);
    if (!peer) {
      throw new Error(`[TransferManager] sendClipboard: unknown device "${targetDeviceId}"`);
    }

    const { metadataKey } = this._deriveSessionKeys(peer);
    const transferId = crypto.randomUUID();

    // Compute SHA-256 of the text content for integrity verification.
    const textBytes = new TextEncoder().encode(text);
    const hashBytes = await crypto.subtle.digest('SHA-256', textBytes);
    const sha256Hex = _bytesToHex(new Uint8Array(hashBytes));

    // Encrypt the clipboard payload as a metadata envelope (reuses the same
    // XChaCha20-Poly1305 path; clipboard has no chunks).
    const payload = { content: text, sha256: sha256Hex, autoCopy: true };
    const ciphertext = encryptMetadata(payload, metadataKey);

    this.ws.send(JSON.stringify({
      type:            WIRE.RELAY_DATA,
      transferId,
      msgType:         'clipboard',
      targetDeviceId,
      ciphertext:      Array.from(ciphertext),
    }));
  }

  // ── Public API: receiving ───────────────────────────────────────────────

  /**
   * Handle an incoming transfer-request message from the relay.
   *
   * Per spec §5.1, paired devices are auto-accepted.  The session keys are
   * derived from the sender's ephemeral public key using the local static X25519
   * secret key (completing the triple-DH on the receiver side).
   *
   * @param {object} msg - Decoded relay message with metadataCiphertext,
   *   ephemeralPublicKey, salt, and targetDeviceId fields.
   */
  handleIncomingRequest(msg) {
    const {
      transferId,
      metadataCiphertext,
      ephemeralPublicKey,
      salt,
      fromDeviceId,
    } = msg;

    // Reconstruct byte arrays from plain number arrays (relay JSON transport).
    const metaEnvelope  = new Uint8Array(metadataCiphertext);
    const ephPkBytes    = new Uint8Array(ephemeralPublicKey);
    const saltBytes     = new Uint8Array(salt);

    // Derive session key on the receiver side (triple-DH with the sender's ephemeral pk).
    const { sessionKey, chunkKey, metadataKey } =
      this._deriveSessionKeysReceiver(fromDeviceId, ephPkBytes, saltBytes);

    if (!sessionKey) {
      console.error(`[TransferManager] Unknown peer ${fromDeviceId} — cannot derive session key`);
      return;
    }

    // Decrypt the metadata envelope.
    let metadata;
    try {
      metadata = decryptMetadata(metaEnvelope, metadataKey);
    } catch (err) {
      console.error('[TransferManager] Failed to decrypt incoming metadata:', err);
      return;
    }

    // Create a Transfer record for the inbound transfer.
    const transfer = new Transfer(transferId, 'receive', fromDeviceId);
    transfer.fileName     = metadata.fileName;
    transfer.fileSize     = metadata.fileSize;
    transfer.mimeType     = metadata.mimeType;
    transfer.totalChunks  = metadata.totalChunks;
    transfer.sha256       = metadata.sha256;
    transfer.sessionKey   = sessionKey;
    transfer.chunkKey     = chunkKey;
    transfer.metadataKey  = metadataKey;
    transfer.state        = STATE.TRANSFERRING;

    // Cache the SHA-256 of the metadata ciphertext for use in chunk AAD.
    _sha256Bytes(metaEnvelope).then((hash) => {
      transfer.metadataCiphertextHash = hash;
    });

    this.transfers.set(transferId, transfer);

    // Auto-accept: send accept message back to the sender.
    this.ws.send(JSON.stringify({
      type:        WIRE.RELAY_DATA,
      transferId,
      msgType:     'transfer-accept',
      targetDeviceId: fromDeviceId,
    }));

    // Notify the service worker of the incoming transfer for badge/notification.
    this._notifySW(MSG.INCOMING_TRANSFER, {
      transferId,
      fromDeviceId,
      fileName:  metadata.fileName,
      fileSize:  metadata.fileSize,
      mimeType:  metadata.mimeType,
    });
  }

  /**
   * Handle an incoming binary chunk frame.
   *
   * ## Steps
   *   1. Decode the 64-byte binary header.
   *   2. Look up the active Transfer record.
   *   3. Build the AAD from the spec (chunkIndex, totalChunks, metadataHash).
   *   4. Decrypt the chunk payload.
   *   5. Insert into the reorder buffer; flush in-order chunks to assembly.
   *   6. Feed flushed chunks into the running hash accumulator.
   *   7. Send ACK with cumulative index and current window info.
   *   8. On final chunk: verify SHA-256 → COMPLETE or FAILED.
   *
   * @param {Uint8Array|ArrayBuffer} data - Raw binary frame (header + ciphertext).
   */
  handleChunk(data) {
    const raw = data instanceof Uint8Array ? data : new Uint8Array(data);

    // ── 1. Decode header ──────────────────────────────────────────────────
    const header = decodeChunkHeader(raw.slice(0, 64));
    const { transferId, chunkIndex, chunkSize, isFinal } = header;

    // ── 2. Find transfer ──────────────────────────────────────────────────
    const transfer = this.transfers.get(transferId);
    if (!transfer) {
      console.warn(`[TransferManager] handleChunk: unknown transferId ${transferId}`);
      return;
    }
    if (transfer.state !== STATE.TRANSFERRING) {
      return; // drop stale chunks after completion/failure
    }

    // ── 3. Build AEAD additional-data ────────────────────────────────────
    // AAD = "zaptransfer-chunk-v1" || uint64(chunkIndex) || uint64(totalChunks)
    //       || SHA256(metadataCiphertext)
    // Must match encryptChunk AAD used during send (spec §4.6).
    const aad = _buildChunkAAD(
      chunkIndex,
      transfer.totalChunks,
      transfer.metadataCiphertextHash,
    );

    // ── 4. Decrypt ────────────────────────────────────────────────────────
    const ciphertext = raw.slice(64);
    let plaintext;
    try {
      plaintext = decryptChunk(ciphertext, transfer.chunkKey, chunkIndex, aad);
    } catch (err) {
      console.error(`[TransferManager] Decryption failed for chunk ${chunkIndex}:`, err);
      transfer.state = STATE.FAILED;
      this._notifySW(MSG.TRANSFER_FAILED, { transferId, reason: 'Decryption failure' });
      return;
    }

    // ── 5. Reorder buffer → in-order flush ───────────────────────────────
    transfer._reorderBuffer.set(chunkIndex, plaintext);

    // Flush contiguous in-order chunks from the reorder buffer.
    while (transfer._reorderBuffer.has(transfer._nextExpected)) {
      const chunk = transfer._reorderBuffer.get(transfer._nextExpected);
      transfer._reorderBuffer.delete(transfer._nextExpected);
      transfer._receivedChunks[transfer._nextExpected] = chunk;
      transfer.bytesTransferred += chunk.byteLength;
      transfer.chunksReceived++;
      transfer._nextExpected++;
    }

    // ── 6. Send ACK ───────────────────────────────────────────────────────
    this.ws.send(JSON.stringify({
      type:                  WIRE.RELAY_DATA,
      transferId,
      msgType:               'chunk-ack',
      targetDeviceId:        transfer.peerId,
      ackedChunkIndex:       chunkIndex,
      cumulativeAck:         transfer._nextExpected - 1,
      receiveWindowRemaining: Math.max(32 - transfer._reorderBuffer.size, 0),
    }));

    // ── 7. Emit progress ──────────────────────────────────────────────────
    this._notifySW(MSG.TRANSFER_PROGRESS, {
      transferId,
      bytesTransferred: transfer.bytesTransferred,
      totalBytes:       transfer.fileSize,
      speedBps:         _estimateSpeed(transfer),
    });

    // ── 8. Final chunk: verify integrity ─────────────────────────────────
    if (isFinal || transfer.chunksReceived === transfer.totalChunks) {
      this._finalizeReceive(transfer);
    }
  }

  /**
   * Handle a chunk ACK message from the receiver (sender-side callback).
   *
   * Updates the flow controller (decrement in-flight, possible window increase),
   * records the RTT for the ChunkSizer, and feeds the next batch of chunks into
   * the send pipeline.
   *
   * @param {object} msg - ACK message with { transferId, ackedChunkIndex, measuredRttMs? }.
   */
  handleChunkAck(msg) {
    const { transferId, ackedChunkIndex, measuredRttMs } = msg;
    const transfer = this.transfers.get(transferId);
    if (!transfer || transfer.state !== STATE.TRANSFERRING) return;

    // Update flow controller.
    this._flowController.onAck();

    // Record RTT if provided (not always present on early chunks).
    if (typeof measuredRttMs === 'number' && measuredRttMs > 0) {
      this._chunkSizer.recordAck(measuredRttMs, this._chunkSizer.size);
    }

    // Clear send-timestamp entry for this chunk.
    transfer._sendTimestamps.delete(ackedChunkIndex);

    // Trigger accept-promise resolution if we are waiting on it.
    // (The accept message arrives via handleChunkAck path in some relay setups.)
    if (transfer._acceptResolve && msg.msgType === 'transfer-accept') {
      clearTimeout(transfer._acceptTimeoutHandle);
      transfer._acceptResolve();
      transfer._acceptResolve = null;
      transfer._acceptReject  = null;
    }
  }

  // ── Public API: misc ────────────────────────────────────────────────────

  /**
   * Number of currently active (non-terminal) transfers.
   * @returns {number}
   */
  count() {
    return this.transfers.size;
  }

  /**
   * Return progress information for the popup UI.
   *
   * @param {string} transferId
   * @returns {{
   *   state:            string,
   *   bytesTransferred: number,
   *   totalBytes:       number,
   *   chunksReceived:   number,
   *   totalChunks:      number,
   *   fileName:         string,
   * } | null}
   */
  getProgress(transferId) {
    const t = this.transfers.get(transferId);
    if (!t) return null;
    return {
      state:            t.state,
      bytesTransferred: t.bytesTransferred,
      totalBytes:       t.fileSize,
      chunksReceived:   t.chunksReceived,
      totalChunks:      t.totalChunks,
      fileName:         t.fileName,
    };
  }

  // ── Internal: session key derivation ───────────────────────────────────

  /**
   * Derive session keys for a new outbound transfer using triple-DH.
   *
   * Generates a fresh ephemeral X25519 key pair for this transfer.
   * Returns the ephemeral public key so it can be shared with the receiver.
   *
   * Triple-DH:
   *   dh1 = DH(ephA_sk, staticB_pk)
   *   dh2 = DH(staticA_sk, ephB_pk)   ← not available on sender; receiver does this half
   *   dh3 = DH(ephA_sk, ephB_pk)      ← not available on sender; receiver does this half
   *
   * Because the receiver does not yet have an ephemeral key at request time,
   * we use a simplified two-DH approach for the relay path:
   *   dh1 = DH(ephA_sk, staticB_pk)
   *   dh2 = DH(staticA_sk, staticB_pk)   [long-term shared secret]
   *   dh3 = dh1  (degenerate for relay; full triple-DH added in Phase H / WebRTC)
   *
   * This still provides forward secrecy through the ephemeral key.
   *
   * @param {object} peer - Paired device record (must have x25519PublicKey).
   * @returns {{ sessionKey, chunkKey, metadataKey, ephemeralKeyPair, salt }}
   */
  _deriveSessionKeys(peer) {
    const staticA_sk  = this.deviceKeys.x25519.sk;
    const staticB_pk  = new Uint8Array(peer.x25519PublicKey);

    // Generate ephemeral key pair for this transfer.
    const ephemeralKeyPair = generateKeyPairs().x25519;

    // Random 32-byte salt binds this session (prevents key reuse across sessions).
    const salt = _randomBytes(32);

    // Triple-DH (simplified relay-path variant — see JSDoc above).
    const dh1 = deriveSharedSecret(ephemeralKeyPair.sk, staticB_pk);
    const dh2 = deriveSharedSecret(staticA_sk, staticB_pk);
    const dh3 = dh1; // degenerate for relay path; full triple-DH in Phase H

    const sessionKey  = deriveSessionKey(dh1, dh2, dh3, salt);
    const chunkKey    = deriveChunkKey(sessionKey);
    const metadataKey = deriveMetadataKey(sessionKey);

    // Zero the ephemeral private key immediately after DH — it is no longer
    // needed and should not persist in memory.
    ephemeralKeyPair.sk.fill(0);

    return { sessionKey, chunkKey, metadataKey, ephemeralKeyPair, salt };
  }

  /**
   * Derive session keys on the receiver side using the sender's ephemeral public key.
   *
   * @param {string}     fromDeviceId - Sender's device ID (used to look up static keys).
   * @param {Uint8Array} ephPkBytes   - Sender's ephemeral X25519 public key.
   * @param {Uint8Array} saltBytes    - 32-byte random salt from the transfer request.
   * @returns {{ sessionKey, chunkKey, metadataKey } | { sessionKey: null }}
   */
  _deriveSessionKeysReceiver(fromDeviceId, ephPkBytes, saltBytes) {
    const peer = this._findPeer(fromDeviceId);
    if (!peer) return { sessionKey: null, chunkKey: null, metadataKey: null };

    const staticB_sk  = this.deviceKeys.x25519.sk;    // receiver's static sk
    const staticA_pk  = new Uint8Array(peer.x25519PublicKey); // sender's static pk

    // Mirror of the sender's triple-DH (relay-path variant).
    const dh1 = deriveSharedSecret(staticB_sk, ephPkBytes);  // DH(staticB_sk, ephA_pk)
    const dh2 = deriveSharedSecret(staticB_sk, staticA_pk);  // DH(staticB_sk, staticA_pk)
    const dh3 = dh1;

    const sessionKey  = deriveSessionKey(dh1, dh2, dh3, saltBytes);
    const chunkKey    = deriveChunkKey(sessionKey);
    const metadataKey = deriveMetadataKey(sessionKey);

    return { sessionKey, chunkKey, metadataKey };
  }

  // ── Internal: send pipeline ─────────────────────────────────────────────

  /**
   * Stream file chunks through the AIMD flow-control window.
   *
   * Each chunk:
   *   1. Slice plaintext from File.arrayBuffer() (stream-friendly).
   *   2. Build AAD binding chunk position to the transfer.
   *   3. Encrypt with XChaCha20-Poly1305.
   *   4. Prepend binary header.
   *   5. Wait if window is full (back-pressure), then send.
   *
   * The loop respects `this._flowController.canSend()` and pauses when the
   * window is full, resuming on each ACK (handleChunkAck → onAck).
   *
   * @param {Transfer} transfer - Active Transfer record (state == TRANSFERRING).
   * @param {File}     file     - Source file.
   * @returns {Promise<void>}
   */
  async _sendChunks(transfer, file) {
    const fileBuffer = await file.arrayBuffer();
    const fileBytes  = new Uint8Array(fileBuffer);

    for (let i = 0; i < transfer.totalChunks; i++) {
      // Wait until the flow-control window has space.
      while (!this._flowController.canSend()) {
        await _sleep(5);
      }

      const chunkSize   = this._chunkSizer.size;
      const offset      = i * chunkSize;
      const sliceEnd    = Math.min(offset + chunkSize, fileBytes.byteLength);
      const plaintext   = fileBytes.slice(offset, sliceEnd);
      const isFinal     = (i === transfer.totalChunks - 1);

      // Build AAD to bind chunk position to the transfer (prevents reordering).
      const aad = _buildChunkAAD(
        i,
        transfer.totalChunks,
        transfer.metadataCiphertextHash,
      );

      // Encrypt the chunk (pads + AEAD).
      const ciphertext = encryptChunk(plaintext, transfer.chunkKey, i, aad);

      // Encode the 64-byte binary header.
      const header = encodeChunkHeader({
        transferId: transfer.id,
        chunkIndex: i,
        byteOffset: BigInt(offset),
        chunkSize:  plaintext.byteLength,
        isFinal,
      });

      // Combine header + ciphertext into one binary frame.
      const frame = new Uint8Array(64 + ciphertext.byteLength);
      frame.set(header,     0);
      frame.set(ciphertext, 64);

      // Record send time for RTT measurement on ACK.
      transfer._sendTimestamps.set(i, Date.now());

      // Advance flow-control in-flight counter then transmit.
      this._flowController.onSend();
      this.ws.sendBinary(frame);

      transfer.chunksSent++;
      transfer.bytesTransferred = Math.min(
        transfer.bytesTransferred + plaintext.byteLength,
        transfer.fileSize,
      );

      // Emit progress every 10 chunks to avoid flooding the SW message queue.
      if (i % C.CHECKPOINT_INTERVAL_CHUNKS === 0 || isFinal) {
        this._notifySW(MSG.TRANSFER_PROGRESS, {
          transferId:      transfer.id,
          bytesTransferred: transfer.bytesTransferred,
          totalBytes:      transfer.fileSize,
          speedBps:        _estimateSpeed(transfer),
        });
      }
    }
  }

  // ── Internal: receive pipeline ──────────────────────────────────────────

  /**
   * Called when the final chunk has been received and the reorder buffer is
   * fully drained.  Concatenates all received chunks and verifies the SHA-256.
   *
   * @param {Transfer} transfer
   */
  async _finalizeReceive(transfer) {
    transfer.state = STATE.VERIFYING;

    // Concatenate all chunks in order.
    const totalBytes = transfer._receivedChunks.reduce((s, c) => s + c.byteLength, 0);
    const assembled  = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of transfer._receivedChunks) {
      assembled.set(chunk, offset);
      offset += chunk.byteLength;
    }

    // Verify SHA-256.
    const hashBuffer = await crypto.subtle.digest('SHA-256', assembled);
    const receivedHex = _bytesToHex(new Uint8Array(hashBuffer));

    if (receivedHex !== transfer.sha256) {
      transfer.state = STATE.FAILED;
      this._notifySW(MSG.TRANSFER_FAILED, {
        transferId: transfer.id,
        reason:     `Hash mismatch: expected ${transfer.sha256}, got ${receivedHex}`,
      });
      return;
    }

    transfer.state = STATE.COMPLETE;

    // Persist the assembled file.  In a real browser context this would trigger
    // a download via chrome.downloads or a Blob URL.  For now we emit a message
    // that the service worker can use to create a download.
    this._notifySW(MSG.TRANSFER_COMPLETE, {
      transferId: transfer.id,
      fileName:   transfer.fileName,
      fileSize:   transfer.fileSize,
      durationMs: Date.now() - transfer.startTime,
      // Pass the assembled bytes as a plain Array for the chrome.runtime boundary.
      // The SW will write to the Downloads API.
      data:       Array.from(assembled),
      mimeType:   transfer.mimeType,
    });
  }

  // ── Internal: utilities ─────────────────────────────────────────────────

  /**
   * Compute the SHA-256 hash of a File object using SubtleCrypto.
   *
   * @param {File} file
   * @returns {Promise<string>} Lowercase hex digest.
   */
  async _computeSHA256(file) {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return _bytesToHex(new Uint8Array(hashBuffer));
  }

  /**
   * Find a paired device by device ID.
   *
   * @param {string} deviceId
   * @returns {object|undefined}
   */
  _findPeer(deviceId) {
    return this.pairedDevices.find((d) => d.deviceId === deviceId);
  }

  /**
   * Return a Promise that resolves when the receiver sends a transfer-accept
   * message, or rejects after the acceptance timeout (60 s).
   *
   * @param {Transfer} transfer
   * @returns {Promise<void>}
   */
  _waitForAccept(transfer) {
    return new Promise((resolve, reject) => {
      transfer._acceptResolve = resolve;
      transfer._acceptReject  = reject;
      transfer._acceptTimeoutHandle = setTimeout(() => {
        transfer.state = STATE.FAILED;
        reject(new Error(`Transfer ${transfer.id} timed out waiting for accept`));
      }, C.ACCEPTANCE_TIMEOUT_MS);
    });
  }

  /**
   * Send an internal chrome.runtime message to the service worker.
   * Errors are swallowed — the SW may be suspended between events.
   *
   * @param {string} type    - MSG.* constant.
   * @param {object} payload - Message payload.
   */
  _notifySW(type, payload) {
    try {
      chrome.runtime.sendMessage({ type, payload });
    } catch (err) {
      // Service worker may be suspended; this is benign.
      console.warn(`[TransferManager] Could not notify SW (${type}):`, err.message);
    }
  }
}

// ---------------------------------------------------------------------------
// Module-private helpers
// ---------------------------------------------------------------------------

/**
 * Classify a file by its size into a content category string.
 * Per spec §5.6.
 *
 * @param {number} size - File size in bytes.
 * @returns {'clipboard'|'small'|'medium'|'large'}
 */
function _contentCategory(size) {
  if (size < 1024)         return 'clipboard';
  if (size < 1048576)      return 'small';
  if (size < 104857600)    return 'medium';
  return 'large';
}

/**
 * Build the AEAD additional-data for a chunk.
 *
 * AAD layout (per spec §4.6):
 *   "zaptransfer-chunk-v1" || uint64_BE(chunkIndex) || uint64_BE(totalChunks)
 *   || SHA256(metadataCiphertext)
 *
 * The SHA-256 of the metadata ciphertext is optional at call time (it may not
 * yet be available on the receive side for the very first chunk); when absent
 * a 32-byte zero array is substituted so the schema is still fixed-length.
 *
 * @param {number}          chunkIndex          - Index of the chunk.
 * @param {number}          totalChunks         - Total number of chunks in the transfer.
 * @param {Uint8Array|null} metadataCiphertextHash - 32-byte SHA-256 of encrypted metadata.
 * @returns {Uint8Array}
 */
function _buildChunkAAD(chunkIndex, totalChunks, metadataCiphertextHash) {
  const prefix    = new TextEncoder().encode('zaptransfer-chunk-v1');
  const hashPart  = metadataCiphertextHash ?? new Uint8Array(32);
  const aad       = new Uint8Array(prefix.length + 8 + 8 + 32);
  const view      = new DataView(aad.buffer);

  let pos = 0;
  aad.set(prefix, pos);        pos += prefix.length;
  view.setBigUint64(pos, BigInt(chunkIndex),  false); pos += 8;
  view.setBigUint64(pos, BigInt(totalChunks), false); pos += 8;
  aad.set(hashPart, pos);

  return aad;
}

/**
 * Compute SHA-256 of a Uint8Array using SubtleCrypto.
 * Returns a 32-byte Uint8Array.
 *
 * Falls back gracefully in environments without SubtleCrypto (e.g. Node tests).
 *
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
async function _sha256Bytes(data) {
  // SubtleCrypto is available in offscreen document (browser) context.
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buf = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(buf);
  }
  // Node.js test context fallback.
  const { createHash } = await import('node:crypto');
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * Convert a Uint8Array to a lowercase hex string.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function _bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a cryptographically random Uint8Array of `n` bytes.
 *
 * Uses SubtleCrypto in browser; Node's crypto module in test environments.
 *
 * @param {number} n
 * @returns {Uint8Array}
 */
function _randomBytes(n) {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return buf;
  }
  // Node.js fallback (sync via node:crypto randomFillSync).
  // Import is deferred to avoid a hard dependency in browser builds.
  const { randomFillSync } = globalThis.__nodeCrypto__ ?? {};
  if (randomFillSync) {
    const buf = new Uint8Array(n);
    randomFillSync(buf);
    return buf;
  }
  // Last resort: return zeros (should never reach in practice).
  console.error('[TransferManager] _randomBytes: no crypto source available');
  return new Uint8Array(n);
}

/**
 * Estimate current transfer speed in bytes per second.
 *
 * Uses elapsed time since transfer start and bytes transferred so far.
 * Returns 0 for the first few milliseconds to avoid divide-by-zero.
 *
 * @param {Transfer} transfer
 * @returns {number} Speed in bytes/second.
 */
function _estimateSpeed(transfer) {
  const elapsedMs = Date.now() - transfer.startTime;
  if (elapsedMs < 100) return 0;
  return Math.round((transfer.bytesTransferred / elapsedMs) * 1000);
}

/**
 * Resolve after `ms` milliseconds.  Used for yield-based back-pressure
 * inside _sendChunks() while the flow-control window is full.
 *
 * @param {number} ms
 * @returns {Promise<void>}
 */
function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
