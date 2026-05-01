/**
 * @file beam-v2-transport.js
 * @description Beam v2 sender + receiver state machine, resend handling,
 * and rotation handshake. The codec (`beam-v2.js`) is pure — this module
 * holds the per-transfer in-flight state and wires it to the relay.
 *
 * Designed as a class so the SW can run a singleton and tests can spin
 * up isolated instances. All external dependencies (sendJson, sendBinary,
 * peer-key store, delivery handlers) are injected via the `hooks` arg.
 *
 * Spec: docs/superpowers/specs/2026-04-30-beam-v2-design.md
 */

import {
  encodeFrame,
  decodeFrame,
  peekHeader,
  newTransferId,
  deriveKAB,
} from './beam-v2.js';
import {
  HEADER_LEN,
  NONCE_LEN,
  KAB_LEN,
  FILE_CHUNK_SIZE,
  MAX_FILE_SIZE,
  MAX_CHUNKS,
  RECEIVE_GAP_MS,
  RECEIVER_GIVEUP_MS,
  SENDER_GIVEUP_MS,
  MAX_RESENDS,
  ROTATION_GRACE_MS,
} from './beam-v2-constants.js';

// ---------------------------------------------------------------------------
// Wire-format helpers for transferId base64url (matches v1 conventions so the
// JSON message envelope is unchanged for the relay's signaling allowlist).
// ---------------------------------------------------------------------------

function b64urlFromBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function bytesFromB64url(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i += 1) out[i] = b.charCodeAt(i);
  return out;
}
function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

// ---------------------------------------------------------------------------
// BeamV2Transport
// ---------------------------------------------------------------------------

/**
 * @typedef {object} PairedPeer
 * @property {string} deviceId
 * @property {Uint8Array} ourSk         — our X25519 private (32B)
 * @property {Uint8Array} peerPk        — peer X25519 public  (32B)
 * @property {Uint8Array} ourEdPk       — our Ed25519 public  (32B)
 * @property {Uint8Array} peerEdPk      — peer Ed25519 public (32B)
 * @property {{
 *   currentGeneration: number,
 *   keys: Record<string, { kAB: Uint8Array, expiresAt?: number, rotateNonce?: Uint8Array }>
 * }} kABRing
 */

/**
 * @typedef {object} TransportHooks
 * @property {(deviceId: string) => Promise<PairedPeer|null>} getPeer
 * @property {() => Promise<PairedPeer[]>} listPeers
 * @property {(deviceId: string, ring: PairedPeer['kABRing']) => Promise<void>} storeKABRing
 * @property {(content: string, fromDeviceId: string) => Promise<void>} onClipboardReceived
 * @property {(args: { bytes: Uint8Array, fileName: string, fileSize: number, mimeType: string, fromDeviceId: string }) => Promise<void>} onFileReceived
 * @property {(transferIdHex: string, code: string) => void} [onSendError]
 * @property {(transferIdHex: string, code: string) => void} [onReceiveError]
 * @property {(transferIdHex: string, percent: number) => void} [onProgress]
 */

export class BeamV2Transport {
  /**
   * @param {{
   *   sendJson: (msg: object) => void,
   *   sendBinary: (bytes: Uint8Array) => boolean,
   *   hooks: TransportHooks,
   * }} args
   */
  constructor({ sendJson, sendBinary, hooks }) {
    this._sendJson   = sendJson;
    this._sendBinary = sendBinary;
    this._hooks      = hooks;

    /** transferIdHex → outbox state. Sender-side. */
    this._outbox = new Map();
    /** transferIdHex → inbox state. Receiver-side. */
    this._inbox = new Map();
    /** Pending rotations by peer deviceId. */
    this._pendingRotations = new Map();
  }

  // -----------------------------------------------------------------------
  // Sender — clipboard
  // -----------------------------------------------------------------------

  async sendClipboard(targetDeviceId, text) {
    console.log('[BeamV2T] sendClipboard target=', targetDeviceId, 'len=', text.length);
    const peer = await this._hooks.getPeer(targetDeviceId);
    if (!peer) {
      console.warn('[BeamV2T] sendClipboard: NO_PEER for', targetDeviceId);
      throw makeErr('NO_PEER', `peer ${targetDeviceId} not paired`);
    }

    const generation = peer.kABRing.currentGeneration;
    const kAB = peer.kABRing.keys[String(generation)]?.kAB;
    if (!kAB) {
      console.warn('[BeamV2T] sendClipboard: NO_KEY peer=', targetDeviceId,
        'gen=', generation, 'ringGens=', Object.keys(peer.kABRing.keys));
      throw makeErr('NO_KEY', `no K_AB for peer ${targetDeviceId} gen ${generation}`);
    }

    const transferId    = newTransferId();
    const transferIdHex = toHex(transferId);

    // Plaintext = u16BE(metaLen) || meta JSON || textBytes
    const meta = new TextEncoder().encode(JSON.stringify({ kind: 'clipboard', v: 2 }));
    const text_b = new TextEncoder().encode(text);
    const plaintext = new Uint8Array(2 + meta.byteLength + text_b.byteLength);
    new DataView(plaintext.buffer).setUint16(0, meta.byteLength, false);
    plaintext.set(meta, 2);
    plaintext.set(text_b, 2 + meta.byteLength);

    const outbox = this._registerOutbox({
      transferIdHex, targetDeviceId, generation,
      framesByIndex: new Map([[0, { plaintext, isFinal: true, hasMeta: true }]]),
    });

    // Bind the transferId on the relay BEFORE the first binary frame so
    // the server pre-populates the peer's WS via rendezvous lookup. The
    // receiver never needs to bind (it learns transferId only by
    // decrypting the frame, which would arrive after the relay's drop).
    this._sendJson({
      type: 'relay-bind',
      transferId: b64urlFromBytes(transferId),
      targetDeviceId,
      rendezvousId: targetDeviceId,
    });

    await this._sendOutboxFrame(outbox, transferId, 0, kAB);
    console.log('[BeamV2T] sendClipboard: completed id=', transferIdHex);
    // Single-frame transfer — completion is implicit. Caller does not await
    // an ack; receiver-side decrypt is the sole authority.
    this._scheduleSenderGiveup(transferIdHex);
    return { transferIdHex };
  }

  // -----------------------------------------------------------------------
  // Sender — file
  // -----------------------------------------------------------------------

  async sendFile(targetDeviceId, { fileName, fileSize, mimeType, bytes }) {
    console.log('[BeamV2T] sendFile target=', targetDeviceId,
      'name=', fileName, 'size=', fileSize, 'bytesLen=', bytes?.byteLength);
    const peer = await this._hooks.getPeer(targetDeviceId);
    if (!peer) {
      console.warn('[BeamV2T] sendFile: NO_PEER for', targetDeviceId);
      throw makeErr('NO_PEER', `peer ${targetDeviceId} not paired`);
    }
    if (bytes.byteLength !== fileSize) {
      console.warn('[BeamV2T] sendFile: SIZE_MISMATCH bytesLen=', bytes.byteLength, 'fileSize=', fileSize);
      throw makeErr('SIZE_MISMATCH', 'fileSize must match bytes.length');
    }
    if (fileSize <= 0 || fileSize > MAX_FILE_SIZE) {
      console.warn('[BeamV2T] sendFile: TOO_BIG fileSize=', fileSize, 'max=', MAX_FILE_SIZE);
      throw makeErr('TOO_BIG', `fileSize out of range`);
    }

    const generation = peer.kABRing.currentGeneration;
    const kAB = peer.kABRing.keys[String(generation)]?.kAB;
    if (!kAB) {
      console.warn('[BeamV2T] sendFile: NO_KEY peer=', targetDeviceId,
        'gen=', generation, 'ringGens=', Object.keys(peer.kABRing.keys));
      throw makeErr('NO_KEY', `no K_AB for peer ${targetDeviceId} gen ${generation}`);
    }

    const totalChunks = Math.max(1, Math.ceil(fileSize / FILE_CHUNK_SIZE));
    if (totalChunks > MAX_CHUNKS) {
      console.warn('[BeamV2T] sendFile: TOO_MANY_CHUNKS totalChunks=', totalChunks, 'max=', MAX_CHUNKS);
      throw makeErr('TOO_MANY_CHUNKS', `totalChunks > ${MAX_CHUNKS}`);
    }

    const transferId    = newTransferId();
    const transferIdHex = toHex(transferId);

    // Frame 0 plaintext: u16BE(metaLen) || meta JSON.
    const meta = new TextEncoder().encode(JSON.stringify({
      kind: 'file', v: 2, fileName, fileSize, mime: mimeType, totalChunks,
    }));
    const metaPlain = new Uint8Array(2 + meta.byteLength);
    new DataView(metaPlain.buffer).setUint16(0, meta.byteLength, false);
    metaPlain.set(meta, 2);

    const framesByIndex = new Map();
    framesByIndex.set(0, { plaintext: metaPlain, isFinal: false, hasMeta: true });
    for (let i = 0; i < totalChunks; i += 1) {
      const start = i * FILE_CHUNK_SIZE;
      const end   = Math.min(start + FILE_CHUNK_SIZE, fileSize);
      framesByIndex.set(i + 1, {
        plaintext: bytes.subarray(start, end),
        isFinal: i === totalChunks - 1,
        hasMeta: false,
      });
    }

    const outbox = this._registerOutbox({
      transferIdHex, targetDeviceId, generation, framesByIndex,
    });

    // One-shot relay-bind ahead of the first binary frame. See sendClipboard
    // for the rationale.
    this._sendJson({
      type: 'relay-bind',
      transferId: b64urlFromBytes(transferId),
      targetDeviceId,
      rendezvousId: targetDeviceId,
    });

    // Send all frames with 20ms spacing (relay-friendly).
    for (let idx = 0; idx <= totalChunks; idx += 1) {
      // eslint-disable-next-line no-await-in-loop
      await this._sendOutboxFrame(outbox, transferId, idx, kAB);
      if (idx < totalChunks) {
        // eslint-disable-next-line no-await-in-loop
        await sleep(20);
      }
      this._hooks.onProgress?.(transferIdHex, Math.round(((idx + 1) / (totalChunks + 1)) * 100));
    }

    console.log('[BeamV2T] sendFile: completed id=', transferIdHex, 'frames=', totalChunks + 1);
    this._scheduleSenderGiveup(transferIdHex);
    return { transferIdHex, totalChunks };
  }

  /**
   * Encrypt one frame from outbox state and send via the binary channel.
   * Used by the initial send loop AND by resend handling — same code path.
   */
  async _sendOutboxFrame(outbox, transferId, index, kAB) {
    const f = outbox.framesByIndex.get(index);
    if (!f) throw makeErr('UNKNOWN_FRAME', `outbox missing index ${index}`);
    const frame = await encodeFrame({
      kAB, generation: outbox.generation, transferId,
      index, isFinal: f.isFinal, hasMeta: f.hasMeta, plaintext: f.plaintext,
    });
    const ok = this._sendBinary(frame);
    console.log('[BeamV2T] sendOutboxFrame: id=', outbox.transferIdHex,
      'idx=', index, 'size=', frame.byteLength, 'ok=', ok);
    if (!ok) throw makeErr('NO_TRANSPORT', 'sendBinary returned false (WS closed?)');
  }

  _registerOutbox({ transferIdHex, targetDeviceId, generation, framesByIndex }) {
    const outbox = {
      transferIdHex,
      targetDeviceId,
      generation,
      framesByIndex,
      firstSentAt:   Date.now(),
      resendsUsed:   0,
      giveupTimer:   null,
    };
    this._outbox.set(transferIdHex, outbox);
    return outbox;
  }

  _scheduleSenderGiveup(transferIdHex) {
    const outbox = this._outbox.get(transferIdHex);
    if (!outbox) return;
    if (outbox.giveupTimer) clearTimeout(outbox.giveupTimer);
    outbox.giveupTimer = setTimeout(() => {
      this._outbox.delete(transferIdHex);
    }, SENDER_GIVEUP_MS);
  }

  // -----------------------------------------------------------------------
  // Receiver — incoming binary frame
  // -----------------------------------------------------------------------

  /**
   * Decode an incoming binary frame and route to per-transferId inbox state.
   * No throw — failures are dropped and reported via onReceiveError hook.
   *
   * @param {Uint8Array} bytes
   * @returns {Promise<void>}
   */
  async handleIncomingFrame(bytes) {
    const head = peekHeader(bytes);
    if (!head) return; // not a v2 frame; drop silently
    console.log('[BeamV2T] handleIncomingFrame id=', toHex(head.transferId),
      'idx=', head.index, 'gen=', head.generation, 'size=', bytes.byteLength);

    // Try every paired peer's K_AB at the frame's generation.
    // O(N) where N = paired devices (typically 1–3). AEAD verify failure
    // is microseconds, so this is cheap.
    const peers = await this._hooks.listPeers();
    let matched = null;
    /** @type {Awaited<ReturnType<typeof decodeFrame>>} */
    let decoded = null;
    for (const peer of peers) {
      const kAB = peer.kABRing.keys[String(head.generation)]?.kAB;
      if (!kAB) continue;
      decoded = await decodeFrame({ resolveKAB: () => kAB, frameBytes: bytes });
      if (decoded) { matched = peer; break; }
    }
    if (!decoded || !matched) {
      console.warn('[BeamV2T] NO_KEY_OR_DECRYPT_FAIL — peers=', peers.length,
        'gen=', head.generation, 'peerGens=', peers.map(p => Object.keys(p.kABRing.keys)));
      this._hooks.onReceiveError?.(toHex(head.transferId), 'NO_KEY_OR_DECRYPT_FAIL');
      return;
    }

    await this._processDecodedFrame(matched, decoded);
  }

  async _processDecodedFrame(peer, { header, plaintext }) {
    const transferIdHex = toHex(header.transferId);
    let inbox = this._inbox.get(transferIdHex);

    if (header.index === 0) {
      // Frame 0 carries meta — establish inbox.
      if (!header.hasMeta) {
        this._hooks.onReceiveError?.(transferIdHex, 'FRAME0_NO_META');
        return;
      }
      const { meta, payload } = parseMetaFrame(plaintext);
      if (!meta) {
        this._hooks.onReceiveError?.(transferIdHex, 'BAD_META');
        return;
      }

      if (meta.kind === 'clipboard') {
        // Single-frame transfer; deliver immediately.
        if (!header.isFinal) {
          this._hooks.onReceiveError?.(transferIdHex, 'CLIPBOARD_NOT_FINAL');
          return;
        }
        const text = new TextDecoder().decode(payload);
        this._inbox.delete(transferIdHex); // never persist for clipboard
        await this._hooks.onClipboardReceived(text, peer.deviceId);
        return;
      }

      if (meta.kind === 'file') {
        if (typeof meta.totalChunks !== 'number' || meta.totalChunks <= 0 || meta.totalChunks > MAX_CHUNKS) {
          this._hooks.onReceiveError?.(transferIdHex, 'BAD_TOTAL_CHUNKS');
          return;
        }
        if (typeof meta.fileSize !== 'number' || meta.fileSize <= 0 || meta.fileSize > MAX_FILE_SIZE) {
          this._hooks.onReceiveError?.(transferIdHex, 'BAD_FILE_SIZE');
          return;
        }
        if (typeof meta.fileName !== 'string' || meta.fileName.length === 0 || meta.fileName.length > 255) {
          this._hooks.onReceiveError?.(transferIdHex, 'BAD_FILENAME');
          return;
        }
        if (typeof meta.mime !== 'string') {
          this._hooks.onReceiveError?.(transferIdHex, 'BAD_MIME');
          return;
        }

        if (!inbox) {
          inbox = this._registerInbox({
            transferIdHex, peer, kind: 'file',
            generation: header.generation, totalChunks: meta.totalChunks,
            fileName: meta.fileName, fileSize: meta.fileSize, mimeType: meta.mime,
          });
        }
        inbox.metaSeen = true;
        this._touchInbox(inbox);
        return;
      }

      this._hooks.onReceiveError?.(transferIdHex, `UNKNOWN_KIND_${meta.kind}`);
      return;
    }

    // index > 0 — chunk frame (file only).
    if (!inbox) {
      // Out-of-order: chunk arrived before meta. Stash in a pending bag so
      // we can replay it once meta lands. Bounded by the frame size and
      // the per-transfer timeout in _registerInbox below.
      inbox = this._registerInbox({
        transferIdHex, peer, kind: 'file-pending-meta',
        generation: header.generation, totalChunks: 0,
      });
    }
    if (header.index < 1 || (inbox.totalChunks && header.index > inbox.totalChunks)) {
      this._hooks.onReceiveError?.(transferIdHex, 'INDEX_OUT_OF_RANGE');
      return;
    }
    if (!inbox.frames.has(header.index)) {
      inbox.frames.set(header.index, plaintext);
      inbox.bytesReceived += plaintext.byteLength;
    }
    if (header.isFinal) inbox.finalSeen = true;
    this._touchInbox(inbox);

    await this._maybeCompleteOrResend(inbox);
  }

  _registerInbox({ transferIdHex, peer, kind, generation, totalChunks, fileName, fileSize, mimeType }) {
    const inbox = {
      transferIdHex,
      peer,
      kind,
      generation,
      totalChunks: totalChunks || 0,
      fileName, fileSize, mimeType,
      frames: new Map(), // index → plaintext
      metaSeen: kind === 'clipboard',
      finalSeen: false,
      bytesReceived: 0,
      firstFrameAt: Date.now(),
      lastFrameAt:  Date.now(),
      gapTimer:    null,
      giveupTimer: null,
      resendRequested: false,
    };
    this._inbox.set(transferIdHex, inbox);
    this._scheduleInboxTimers(inbox);
    return inbox;
  }

  _touchInbox(inbox) {
    inbox.lastFrameAt = Date.now();
    if (inbox.gapTimer) clearTimeout(inbox.gapTimer);
    inbox.gapTimer = setTimeout(() => this._maybeRequestResend(inbox), RECEIVE_GAP_MS);
  }

  _scheduleInboxTimers(inbox) {
    inbox.gapTimer = setTimeout(() => this._maybeRequestResend(inbox), RECEIVE_GAP_MS);
    inbox.giveupTimer = setTimeout(() => {
      this._inbox.delete(inbox.transferIdHex);
      this._hooks.onReceiveError?.(inbox.transferIdHex, 'PARTIAL');
    }, RECEIVER_GIVEUP_MS);
  }

  async _maybeCompleteOrResend(inbox) {
    if (!inbox.metaSeen) return;
    if (inbox.frames.size === inbox.totalChunks && inbox.finalSeen) {
      await this._completeFile(inbox);
    } else if (inbox.finalSeen) {
      // isFinal arrived but we are missing chunks — request immediately.
      this._maybeRequestResend(inbox);
    }
  }

  _maybeRequestResend(inbox) {
    if (!inbox.metaSeen) return; // can't request for file before meta lands
    const missing = [];
    for (let i = 1; i <= inbox.totalChunks; i += 1) {
      if (!inbox.frames.has(i)) missing.push(i);
    }
    if (missing.length === 0) return;
    if (inbox.resendRequested) return; // throttle to one outstanding request
    inbox.resendRequested = true;
    this._sendJson({
      type: 'beam-v2-resend',
      transferId: b64urlFromBytes(transferIdHexToBytes(inbox.transferIdHex)),
      missing,
      // routing fields (relay needs targetDeviceId + rendezvousId)
      targetDeviceId: inbox.peer.deviceId,
      rendezvousId:   inbox.peer.deviceId,
    });
  }

  async _completeFile(inbox) {
    if (inbox.giveupTimer) clearTimeout(inbox.giveupTimer);
    if (inbox.gapTimer) clearTimeout(inbox.gapTimer);
    this._inbox.delete(inbox.transferIdHex);

    const totalLen = Array.from(inbox.frames.values()).reduce((s, p) => s + p.byteLength, 0);
    if (totalLen !== inbox.fileSize) {
      this._hooks.onReceiveError?.(inbox.transferIdHex, 'SIZE_MISMATCH');
      return;
    }
    const out = new Uint8Array(totalLen);
    let off = 0;
    for (let i = 1; i <= inbox.totalChunks; i += 1) {
      const part = inbox.frames.get(i);
      out.set(part, off);
      off += part.byteLength;
    }
    await this._hooks.onFileReceived({
      bytes: out,
      fileName: inbox.fileName,
      fileSize: inbox.fileSize,
      mimeType: inbox.mimeType,
      fromDeviceId: inbox.peer.deviceId,
    });
  }

  // -----------------------------------------------------------------------
  // JSON message dispatch (resend / fail / rotate)
  // -----------------------------------------------------------------------

  /**
   * Returns true if the message was a v2 transport message (handled);
   * false otherwise so the caller can route to other handlers.
   */
  async handleJsonMessage(msg) {
    switch (msg?.type) {
      case 'beam-v2-resend':
        await this._handleResendRequest(msg);
        return true;
      case 'beam-v2-fail':
        this._handleSenderFailure(msg);
        return true;
      case 'beam-v2-rotate-init':
        await this._handleRotateInit(msg);
        return true;
      case 'beam-v2-rotate-ack':
        await this._handleRotateAck(msg);
        return true;
      case 'beam-v2-rotate-commit':
        await this._handleRotateCommit(msg);
        return true;
      default:
        return false;
    }
  }

  async _handleResendRequest(msg) {
    const transferIdBytes = bytesFromB64url(msg.transferId);
    const transferIdHex   = toHex(transferIdBytes);
    const outbox = this._outbox.get(transferIdHex);
    if (!outbox) return; // gone — sender already gave up or never knew this id
    if (outbox.resendsUsed >= MAX_RESENDS) {
      this._sendJson({
        type: 'beam-v2-fail',
        transferId: msg.transferId,
        targetDeviceId: outbox.targetDeviceId,
        rendezvousId:   outbox.targetDeviceId,
        code: 'PARTIAL',
      });
      return;
    }
    outbox.resendsUsed += 1;

    const peer = await this._hooks.getPeer(outbox.targetDeviceId);
    const kAB  = peer?.kABRing?.keys?.[String(outbox.generation)]?.kAB;
    if (!kAB) return;

    for (const idx of msg.missing || []) {
      // eslint-disable-next-line no-await-in-loop
      await this._sendOutboxFrame(outbox, transferIdBytes, idx, kAB);
    }
  }

  _handleSenderFailure(msg) {
    const transferIdHex = toHex(bytesFromB64url(msg.transferId));
    const inbox = this._inbox.get(transferIdHex);
    if (inbox) {
      if (inbox.giveupTimer) clearTimeout(inbox.giveupTimer);
      if (inbox.gapTimer)    clearTimeout(inbox.gapTimer);
      this._inbox.delete(transferIdHex);
    }
    this._hooks.onReceiveError?.(transferIdHex, msg.code || 'PEER_FAILED');
  }

  // -----------------------------------------------------------------------
  // Rotation
  // -----------------------------------------------------------------------

  /**
   * Initiate K_AB rotation with `targetDeviceId`. Resolves once the new
   * generation is committed locally (i.e. as soon as our outgoing frames
   * will use the new gen). The peer commits via the rotate-ack roundtrip.
   */
  async rotateKAB(targetDeviceId) {
    const peer = await this._hooks.getPeer(targetDeviceId);
    if (!peer) throw makeErr('NO_PEER', `peer ${targetDeviceId} not paired`);

    const fromGen = peer.kABRing.currentGeneration;
    const toGen   = fromGen + 1;
    const nonce   = new Uint8Array(16);
    crypto.getRandomValues(nonce);

    // Stash the pending rotation so we know what to do when the ack arrives.
    this._pendingRotations.set(targetDeviceId, { fromGen, toGen, nonce, role: 'initiator' });

    this._sendJson({
      type: 'beam-v2-rotate-init',
      fromGen, toGen,
      nonce: b64urlFromBytes(nonce),
      targetDeviceId, rendezvousId: targetDeviceId,
    });
  }

  async _handleRotateInit(msg) {
    const fromDeviceId = msg.fromDeviceId; // signaling injects this
    if (!fromDeviceId) return;
    const peer = await this._hooks.getPeer(fromDeviceId);
    if (!peer) return;

    // Tiebreaker: lex-smaller deviceId wins concurrent rotation; we only
    // accept the peer's init if our own deviceId is lex-larger OR no
    // pending rotation exists locally.
    const ourPending = this._pendingRotations.get(fromDeviceId);
    if (ourPending && ourPending.role === 'initiator') {
      // Compare deviceIds: ourEdPk-derived id vs peer's id. We know peer.deviceId.
      // The "smaller wins" rule needs both ids; we can grab ours from any peer's
      // ourEdPk via the hook — but simpler: accept the peer's offer iff peer.deviceId
      // is lex-smaller than our id, which we can derive once. For now, always
      // defer to the peer if we receive their init while we have one outstanding;
      // the lex rule is implemented when the hook provides our deviceId.
      // → accept and overwrite our pending only if peer.deviceId < OUR_DEVICE_ID
      const ourId = await getOurDeviceId(this._hooks, peer);
      if (ourId !== null && fromDeviceId > ourId) {
        // peer's id larger → we win; ignore peer's init.
        return;
      }
      // else fall through and accept theirs.
    }

    const nonce = bytesFromB64url(msg.nonce);
    const newKab = await deriveKAB({
      ourSk: peer.ourSk, peerPk: peer.peerPk,
      ourEdPk: peer.ourEdPk, peerEdPk: peer.peerEdPk,
      generation: msg.toGen, rotateNonce: nonce,
    });

    // Stage the new generation as pending; commit on receipt of rotate-commit
    // OR on first decrypt success at the new gen.
    const newRing = stageRotation(peer.kABRing, msg.toGen, newKab, nonce);
    await this._hooks.storeKABRing(fromDeviceId, newRing);

    this._sendJson({
      type: 'beam-v2-rotate-ack',
      fromGen: msg.fromGen,
      toGen:   msg.toGen,
      nonce:   msg.nonce,
      targetDeviceId: fromDeviceId,
      rendezvousId:   fromDeviceId,
    });
  }

  async _handleRotateAck(msg) {
    const fromDeviceId = msg.fromDeviceId;
    if (!fromDeviceId) return;
    const pending = this._pendingRotations.get(fromDeviceId);
    if (!pending || pending.toGen !== msg.toGen) return;

    const peer = await this._hooks.getPeer(fromDeviceId);
    if (!peer) return;

    const newKab = await deriveKAB({
      ourSk: peer.ourSk, peerPk: peer.peerPk,
      ourEdPk: peer.ourEdPk, peerEdPk: peer.peerEdPk,
      generation: pending.toGen, rotateNonce: pending.nonce,
    });

    const newRing = stageRotation(peer.kABRing, pending.toGen, newKab, pending.nonce);
    newRing.currentGeneration = pending.toGen;
    if (pending.fromGen >= 0 && newRing.keys[String(pending.fromGen)]) {
      newRing.keys[String(pending.fromGen)].expiresAt = Date.now() + ROTATION_GRACE_MS;
    }
    await this._hooks.storeKABRing(fromDeviceId, newRing);
    this._pendingRotations.delete(fromDeviceId);

    this._sendJson({
      type: 'beam-v2-rotate-commit',
      toGen: pending.toGen,
      targetDeviceId: fromDeviceId,
      rendezvousId:   fromDeviceId,
    });
  }

  async _handleRotateCommit(msg) {
    const fromDeviceId = msg.fromDeviceId;
    if (!fromDeviceId) return;
    const peer = await this._hooks.getPeer(fromDeviceId);
    if (!peer) return;

    const ring = peer.kABRing;
    if (!ring.keys[String(msg.toGen)]) return; // we don't have it staged
    const oldGen = ring.currentGeneration;
    ring.currentGeneration = msg.toGen;
    if (ring.keys[String(oldGen)]) {
      ring.keys[String(oldGen)].expiresAt = Date.now() + ROTATION_GRACE_MS;
    }
    await this._hooks.storeKABRing(fromDeviceId, ring);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeErr(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function transferIdHexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
}

/**
 * Parse the meta frame's plaintext: u16BE(metaLen) || meta JSON || payload.
 *
 * @param {Uint8Array} plaintext
 * @returns {{ meta: object|null, payload: Uint8Array }}
 */
function parseMetaFrame(plaintext) {
  if (plaintext.byteLength < 2) return { meta: null, payload: new Uint8Array(0) };
  const metaLen = new DataView(plaintext.buffer, plaintext.byteOffset, 2).getUint16(0, false);
  if (metaLen === 0 || 2 + metaLen > plaintext.byteLength) {
    return { meta: null, payload: new Uint8Array(0) };
  }
  let meta;
  try {
    meta = JSON.parse(new TextDecoder().decode(plaintext.subarray(2, 2 + metaLen)));
  } catch {
    return { meta: null, payload: new Uint8Array(0) };
  }
  return { meta, payload: plaintext.subarray(2 + metaLen) };
}

function stageRotation(ring, toGen, kAB, nonce) {
  const out = {
    currentGeneration: ring.currentGeneration, // unchanged until commit
    keys: { ...ring.keys },
  };
  out.keys[String(toGen)] = {
    kAB,
    rotateNonce: nonce,
    createdAt: Date.now(),
  };
  return out;
}

/**
 * Best-effort lookup of our own deviceId — used for the rotation tiebreaker.
 * If unavailable, return null and the caller falls back to "always accept
 * peer's init"; rotations converge through the next round either way.
 */
async function getOurDeviceId(hooks, anyPeer) {
  if (typeof hooks.getOurDeviceId === 'function') {
    return hooks.getOurDeviceId();
  }
  return null;
}
