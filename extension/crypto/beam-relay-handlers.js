// Beam E2E encryption — handshake + binary frame handling for the Chrome SW.
//
// Called from background-relay.js when:
//   * a transfer-init / transfer-accept / transfer-reject JSON message arrives
//   * a binary frame arrives that starts with the 'BEAM' magic
//   * the caller wants to send an encrypted clipboard / file
//
// Wire format for the Beam binary frame (on top of pairing WebSocket binary):
//
//   [0..4]   'B' 'E' 'A' 'M'          magic (0x42 0x45 0x41 0x4D)
//   [4..20]  transferId               16 raw bytes
//   [20..24] u32_be chunk index       0 for clipboard, 1..N for file chunks
//   [24..]   ciphertext               AEAD output (libsodium combined mode)
//
// The magic prefix disambiguates Beam frames from the legacy plaintext
// file-chunk path (which sends raw file bytes — no magic, no transferId).
// Existing file transfers continue to work unchanged in Task 7; Task 8
// will migrate them onto this framed path.

import {
  encryptClipboard,
  decryptClipboard,
  encryptFileMetadata,
  decryptFileMetadata,
  encryptFileChunk,
  decryptFileChunk,
  toHex,
  fromHex,
} from './beam-crypto.js';
import { STATE, ERROR_CODES } from './session-registry.js';
import { getCryptoContext } from './beam-crypto-context.js';

// File chunks are 200 KB of plaintext, matching the legacy file path.
// After AEAD + power-of-2 padding the on-the-wire frame is ~256 KB which
// comfortably stays under the relay's MAX_BINARY_SIZE.
const FILE_CHUNK_SIZE = 200 * 1024;

// Receiver-side caps on incoming file metadata. These must be validated
// before any per-transfer buffer is allocated to prevent a malicious
// paired peer from causing OOM via an oversized `fileSize` or
// `totalChunks` declaration in the encrypted metadata envelope.
//
// MAX_FILE_SIZE matches the server's existing SESSION_LIMIT (500 MB in
// server/src/relay.js), so no legitimate transfer that would succeed
// against the server is blocked here. MAX_CHUNKS is sized for the
// 500 MB budget at ~175 KB effective per chunk.
export const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
export const MAX_CHUNKS    = 3000;
// 20ms spacing between file chunk sends — gives the relay breathing room
// and prevents OkHttp / browser WebSocket buffers from spiking.
const CHUNK_SEND_SPACING_MS = 20;

// On-the-wire transferId encoding: 16 raw bytes → base64url (no padding).
// All Beam wire messages (transfer-init, transfer-accept, transfer-reject,
// relay-bind, relay-release) MUST use this encoding so that the relay can
// pair messages by exact string match and so Android ↔ Chrome interoperate.
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

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

const BEAM_MAGIC = new Uint8Array([0x42, 0x45, 0x41, 0x4d]); // 'BEAM'
const BEAM_HEADER_LEN = 4 + 16 + 4; // magic + transferId + index = 24

export function isBeamFrame(bytes) {
  return (
    bytes.byteLength >= BEAM_HEADER_LEN &&
    bytes[0] === BEAM_MAGIC[0] &&
    bytes[1] === BEAM_MAGIC[1] &&
    bytes[2] === BEAM_MAGIC[2] &&
    bytes[3] === BEAM_MAGIC[3]
  );
}

export function encodeBeamFrame(transferId, index, ciphertext) {
  if (transferId.byteLength !== 16) {
    throw new Error('transferId must be 16 bytes');
  }
  const out = new Uint8Array(BEAM_HEADER_LEN + ciphertext.byteLength);
  out.set(BEAM_MAGIC, 0);
  out.set(transferId, 4);
  new DataView(out.buffer, out.byteOffset + 20, 4).setUint32(0, index >>> 0, false);
  out.set(ciphertext, BEAM_HEADER_LEN);
  return out;
}

export function decodeBeamFrame(bytes) {
  if (!isBeamFrame(bytes)) throw new Error('not a Beam frame');
  const transferId = bytes.slice(4, 20);
  const index = new DataView(bytes.buffer, bytes.byteOffset + 20, 4).getUint32(0, false);
  const ciphertext = bytes.slice(BEAM_HEADER_LEN);
  return { transferId, index, ciphertext };
}

// ---------------------------------------------------------------------------
// Pending sender-side accept waiters.
// Maps transferIdHex → { resolve, reject, timer }.
// ---------------------------------------------------------------------------

const pendingAccepts = new Map();

function registerAcceptWaiter(transferIdHex, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingAccepts.delete(transferIdHex);
      reject(Object.assign(new Error('transfer-accept timeout'), {
        code: ERROR_CODES.TIMEOUT,
      }));
    }, timeoutMs);
    pendingAccepts.set(transferIdHex, { resolve, reject, timer });
  });
}

function resolveAcceptWaiter(transferIdHex, session) {
  const w = pendingAccepts.get(transferIdHex);
  if (!w) return false;
  pendingAccepts.delete(transferIdHex);
  clearTimeout(w.timer);
  w.resolve(session);
  return true;
}

function rejectAcceptWaiter(transferIdHex, err) {
  const w = pendingAccepts.get(transferIdHex);
  if (!w) return false;
  pendingAccepts.delete(transferIdHex);
  clearTimeout(w.timer);
  w.reject(err);
  return true;
}

// ---------------------------------------------------------------------------
// Outbound: encrypted clipboard
// ---------------------------------------------------------------------------

/**
 * Send `text` to `targetDeviceId` as an end-to-end encrypted clipboard
 * payload. Runs the Beam Triple-DH handshake, encrypts the text as a
 * single AEAD chunk, and emits the ciphertext on the pairing WebSocket.
 *
 * @param {{
 *   targetDeviceId: string,
 *   rendezvousId: string,
 *   content: string,
 *   sendJson: (msg: object) => void,
 *   sendBinary: (data: ArrayBuffer|Uint8Array) => boolean,
 * }} args
 * @returns {Promise<{transferIdHex: string}>}
 */
export async function sendClipboardEncrypted({
  targetDeviceId,
  rendezvousId,
  content,
  sendJson,
  sendBinary,
}) {
  const ctx = await getCryptoContext();
  const peerStaticPk = ctx.peerStaticPk(targetDeviceId);
  if (!peerStaticPk) {
    throw Object.assign(new Error(`no X25519 key for peer ${targetDeviceId}`), {
      code: ERROR_CODES.INTERNAL,
    });
  }

  const { wireMessage, transferIdHex } = await ctx.registry.startInit({
    peerId: targetDeviceId,
    peerStaticPk,
    kind: 'clipboard',
  });

  // Register waiter BEFORE sending so we can't miss an instant accept.
  const accepted = registerAcceptWaiter(transferIdHex);

  // The wireMessage already carries transferId as base64url — reuse it so
  // every downstream message references the identical string.
  const transferIdWire = wireMessage.transferId;

  sendJson({
    ...wireMessage,
    targetDeviceId,
    rendezvousId,
  });
  sendJson({
    type: 'relay-bind',
    transferId: transferIdWire,
    targetDeviceId,
    rendezvousId,
  });

  let session;
  try {
    session = await accepted;
  } catch (err) {
    // Handshake failed — tell the peer we gave up and drop the session.
    try {
      sendJson({
        type: 'transfer-reject',
        transferId: transferIdWire,
        targetDeviceId,
        rendezvousId,
        errorCode: err.code || ERROR_CODES.TIMEOUT,
      });
    } catch (_) { /* ignore */ }
    try { sendJson({ type: 'relay-release', transferId: transferIdWire }); } catch (_) {}
    await ctx.registry.destroy(fromHex(transferIdHex), err.code || ERROR_CODES.TIMEOUT);
    throw err;
  }

  try {
    const plaintextBytes = new TextEncoder().encode(content);
    const { ciphertext } = await encryptClipboard({
      plaintext: plaintextBytes,
      chunkKey: session.chunkKey,
      transcript: session.transcript,
    });
    const frame = encodeBeamFrame(session.transferId, 0, ciphertext);
    sendBinary(frame);
  } finally {
    try { sendJson({ type: 'relay-release', transferId: transferIdWire }); } catch (_) {}
    await ctx.registry.destroy(session.transferId);
  }

  return { transferIdHex };
}

// ---------------------------------------------------------------------------
// Outbound: encrypted file
// ---------------------------------------------------------------------------

/**
 * Send `rawBytes` to `targetDeviceId` as an end-to-end encrypted file.
 *
 * Wire flow (all sent on the pairing WebSocket):
 *   1. transfer-init (kind=file)   + relay-bind     — JSON
 *   2. ← transfer-accept                            — JSON (awaited)
 *   3. Beam frame index=0: encrypted metadata env.  — binary
 *   4. Beam frames index=1..N: encrypted chunks     — binary
 *   5. file-complete                                — JSON
 *   6. relay-release                                — JSON
 *
 * Truncation protection: `totalChunks` lives inside the encrypted metadata
 * envelope (AEAD-authenticated) AND in the AAD of every chunk, so the relay
 * cannot drop the final chunk without the receiver detecting a mismatch
 * between decrypted chunks and the declared count.
 *
 * @param {{
 *   targetDeviceId: string,
 *   rendezvousId: string,
 *   fileName: string,
 *   fileSize: number,
 *   mimeType: string,
 *   rawBytes: Uint8Array,
 *   sendJson: (msg: object) => void,
 *   sendBinary: (data: ArrayBuffer|Uint8Array) => boolean,
 * }} args
 * @returns {Promise<{transferIdHex: string, totalChunks: number}>}
 */
export async function sendFileEncrypted({
  targetDeviceId,
  rendezvousId,
  fileName,
  fileSize,
  mimeType,
  rawBytes,
  sendJson,
  sendBinary,
}) {
  const ctx = await getCryptoContext();
  const peerStaticPk = ctx.peerStaticPk(targetDeviceId);
  if (!peerStaticPk) {
    throw Object.assign(new Error(`no X25519 key for peer ${targetDeviceId}`), {
      code: ERROR_CODES.INTERNAL,
    });
  }

  const totalChunks = Math.max(1, Math.ceil(rawBytes.byteLength / FILE_CHUNK_SIZE));

  const { wireMessage, transferIdHex } = await ctx.registry.startInit({
    peerId: targetDeviceId,
    peerStaticPk,
    kind: 'file',
  });
  const transferIdWire = wireMessage.transferId;

  // Files take longer than clipboard — give the handshake 15s just in case
  // the relay or the receiver is under load.
  const accepted = registerAcceptWaiter(transferIdHex, 15_000);

  sendJson({
    ...wireMessage,
    targetDeviceId,
    rendezvousId,
  });
  sendJson({
    type: 'relay-bind',
    transferId: transferIdWire,
    targetDeviceId,
    rendezvousId,
  });

  let session;
  try {
    session = await accepted;
  } catch (err) {
    try {
      sendJson({
        type: 'transfer-reject',
        transferId: transferIdWire,
        targetDeviceId,
        rendezvousId,
        errorCode: err.code || ERROR_CODES.TIMEOUT,
      });
    } catch (_) { /* ignore */ }
    try { sendJson({ type: 'relay-release', transferId: transferIdWire }); } catch (_) {}
    await ctx.registry.destroy(fromHex(transferIdHex), err.code || ERROR_CODES.TIMEOUT);
    throw err;
  }

  // Stash on the session so the chunk-encrypt AAD matches the receiver's.
  session.totalChunks = totalChunks;

  try {
    // 1. Encrypted metadata envelope at index 0 under metaKey.
    const metaJson = JSON.stringify({
      fileName,
      fileSize,
      mime: mimeType,
      totalChunks,
    });
    const metaPlaintext = new TextEncoder().encode(metaJson);
    const { ciphertext: metaCiphertext } = await encryptFileMetadata({
      plaintext: metaPlaintext,
      metaKey: session.metaKey,
      transcript: session.transcript,
    });
    const metaFrame = encodeBeamFrame(session.transferId, 0, metaCiphertext);
    sendBinary(metaFrame);

    // 2. Encrypted chunks at indices 1..N under chunkKey.
    for (let i = 0; i < totalChunks; i += 1) {
      const start = i * FILE_CHUNK_SIZE;
      const end = Math.min(start + FILE_CHUNK_SIZE, rawBytes.byteLength);
      const chunkPlain = rawBytes.subarray(start, end);
      const chunkIndex = i + 1; // 1-based per spec
      // eslint-disable-next-line no-await-in-loop
      const { ciphertext: chunkCt } = await encryptFileChunk({
        plaintext: chunkPlain,
        chunkKey: session.chunkKey,
        index: chunkIndex,
        totalChunks,
        transcript: session.transcript,
      });
      const frame = encodeBeamFrame(session.transferId, chunkIndex, chunkCt);
      sendBinary(frame);
      if (i < totalChunks - 1) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, CHUNK_SEND_SPACING_MS));
      }
    }

    // 3. file-complete signal. The receiver treats it as an advisory "sender
    // is done" — the actual completion is driven by chunksReceived === totalChunks.
    sendJson({
      type: 'file-complete',
      transferId: transferIdWire,
      targetDeviceId,
      rendezvousId,
    });
  } finally {
    try { sendJson({ type: 'relay-release', transferId: transferIdWire }); } catch (_) {}
    await ctx.registry.destroy(session.transferId);
  }

  return { transferIdHex, totalChunks };
}

// ---------------------------------------------------------------------------
// Inbound: transfer-init / transfer-accept / transfer-reject
// ---------------------------------------------------------------------------

/**
 * Handle an incoming transfer-init message. Derives session keys, sends
 * back transfer-accept + relay-bind, and registers the session as ACTIVE.
 */
export async function handleTransferInit({ msg, sendJson }) {
  const ctx = await getCryptoContext();
  const fromDeviceId = msg.fromDeviceId;
  const rendezvousId = msg.rendezvousId || fromDeviceId;
  const peerStaticPk = ctx.peerStaticPk(fromDeviceId);
  if (!peerStaticPk) {
    console.warn('[Beam SW] transfer-init: no peerStaticPk for', fromDeviceId);
    sendJson({
      type: 'transfer-reject',
      transferId: msg.transferId,
      targetDeviceId: fromDeviceId,
      rendezvousId,
      errorCode: ERROR_CODES.INTERNAL,
    });
    return;
  }
  try {
    const { wireMessage } = await ctx.registry.onInit({
      peerId: fromDeviceId,
      peerStaticPk,
      wireMessage: msg,
    });
    sendJson({
      ...wireMessage,
      targetDeviceId: fromDeviceId,
      rendezvousId,
    });
    sendJson({
      type: 'relay-bind',
      transferId: msg.transferId,
      targetDeviceId: fromDeviceId,
      rendezvousId,
    });
  } catch (err) {
    const code = err.code || ERROR_CODES.INTERNAL;
    console.warn('[Beam SW] transfer-init failed:', code, err.message);
    sendJson({
      type: 'transfer-reject',
      transferId: msg.transferId,
      targetDeviceId: fromDeviceId,
      rendezvousId,
      errorCode: code,
    });
  }
}

/**
 * Handle an incoming transfer-accept message. Finishes the initiator-side
 * Triple-DH and resolves the pending sendClipboardEncrypted promise.
 */
export async function handleTransferAccept({ msg }) {
  const ctx = await getCryptoContext();
  const fromDeviceId = msg.fromDeviceId;
  try {
    const session = await ctx.registry.onAccept({
      peerId: fromDeviceId,
      wireMessage: msg,
    });
    resolveAcceptWaiter(session.transferIdHex, session);
  } catch (err) {
    console.error('[Beam SW] transfer-accept failed:', err);
    // Best-effort: reject any waiter with a matching id (hex form).
    rejectAcceptWaiter(msg.transferId && toHexFromB64url(msg.transferId), err);
  }
}

/**
 * Handle an incoming transfer-reject message.
 */
export async function handleTransferReject({ msg }) {
  console.warn('[Beam SW] transfer-reject:', msg.errorCode);
  try {
    const ctx = await getCryptoContext();
    const idHex = toHexFromB64url(msg.transferId);
    const err = Object.assign(new Error(`peer rejected transfer: ${msg.errorCode}`), {
      code: msg.errorCode || ERROR_CODES.INTERNAL,
    });
    rejectAcceptWaiter(idHex, err);
    await ctx.registry.destroy(fromHex(idHex), msg.errorCode || ERROR_CODES.INTERNAL);
  } catch (e) {
    console.warn('[Beam SW] transfer-reject handling error:', e);
  }
}

// ---------------------------------------------------------------------------
// Inbound: binary Beam frame
// ---------------------------------------------------------------------------

/**
 * Decrypt a Beam binary frame and deliver the plaintext to the caller-
 * supplied handlers. Returns true if the frame was consumed (Beam frame);
 * false if the bytes are not a Beam frame (caller should fall back to the
 * legacy file receive path).
 *
 * @param {{
 *   bytes: Uint8Array,
 *   onClipboardDecrypted: (content: string, fromDeviceId: string) => Promise<void>|void,
 * }} args
 */
export async function handleIncomingBeamFrame({
  bytes,
  onClipboardDecrypted,
  onFileComplete,
}) {
  if (!isBeamFrame(bytes)) return false;
  const { transferId, index, ciphertext } = decodeBeamFrame(bytes);
  const ctx = await getCryptoContext();
  const session = ctx.registry.getByTransferId(transferId);
  if (!session || session.state !== STATE.ACTIVE) {
    console.warn('[Beam SW] Beam frame for unknown or inactive session', toHex(transferId));
    return true;
  }
  ctx.registry.touch(session);

  if (session.kind === 'clipboard') {
    try {
      const plaintext = await decryptClipboard({
        ciphertext,
        chunkKey: session.chunkKey,
        transcript: session.transcript,
      });
      const content = new TextDecoder().decode(plaintext);
      await onClipboardDecrypted(content, session.peerId);
    } catch (err) {
      console.error('[Beam SW] clipboard decrypt failed:', err);
    } finally {
      await ctx.registry.destroy(session.transferId);
    }
    return true;
  }

  // kind === 'file'
  try {
    if (index === 0) {
      // Encrypted metadata envelope under metaKey.
      const metaBytes = await decryptFileMetadata({
        ciphertext,
        metaKey: session.metaKey,
        transcript: session.transcript,
      });
      const metadata = JSON.parse(new TextDecoder().decode(metaBytes));

      // Validate peer-supplied metadata BEFORE mutating any session state
      // or allocating per-transfer buffers. A malicious paired peer could
      // otherwise declare an oversized fileSize / totalChunks and cause
      // the receiver to OOM once chunks start arriving. AEAD authenticity
      // only guarantees the envelope came from the paired peer — it does
      // not bound the declared values.
      const fileName    = metadata.fileName;
      const fileSize    = metadata.fileSize;
      const mimeType    = metadata.mime;
      const totalChunks = metadata.totalChunks;

      if (typeof fileSize !== 'number' || !Number.isFinite(fileSize) || fileSize <= 0 || fileSize > MAX_FILE_SIZE) {
        console.warn('[Beam SW] rejected file metadata: invalid fileSize', fileSize);
        await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
        return true;
      }
      if (typeof totalChunks !== 'number' || !Number.isInteger(totalChunks) || totalChunks <= 0 || totalChunks > MAX_CHUNKS) {
        console.warn('[Beam SW] rejected file metadata: invalid totalChunks', totalChunks);
        await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
        return true;
      }
      if (typeof fileName !== 'string' || fileName.length === 0 || fileName.length > 255) {
        console.warn('[Beam SW] rejected file metadata: invalid fileName length', fileName?.length);
        await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
        return true;
      }
      if (typeof mimeType !== 'string') {
        console.warn('[Beam SW] rejected file metadata: invalid mime type', mimeType);
        await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
        return true;
      }

      session.fileMetadata = metadata;
      session.totalChunks = totalChunks;
      session.fileChunks = [];
      session.bytesReceivedPlain = 0;
      return true;
    }

    if (!session.fileMetadata) {
      console.error('[Beam SW] file chunk arrived before metadata envelope');
      await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
      return true;
    }
    if (index > session.totalChunks) {
      console.error('[Beam SW] file chunk index exceeds totalChunks:', index, session.totalChunks);
      await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
      return true;
    }

    const chunkPlain = await decryptFileChunk({
      ciphertext,
      chunkKey: session.chunkKey,
      index,
      totalChunks: session.totalChunks,
      transcript: session.transcript,
    });
    session.fileChunks.push(chunkPlain);
    session.bytesReceivedPlain += chunkPlain.byteLength;

    if (session.fileChunks.length === session.totalChunks) {
      // Full file received — assemble and deliver.
      const totalLen = session.fileChunks.reduce((s, c) => s + c.byteLength, 0);
      const combined = new Uint8Array(totalLen);
      let off = 0;
      for (const c of session.fileChunks) {
        combined.set(c, off);
        off += c.byteLength;
      }

      // Size check — the declared fileSize in metadata must match what we
      // actually decrypted. AEAD already guarantees per-chunk integrity;
      // this catches mismatches between plaintext length and claimed size.
      if (totalLen !== session.fileMetadata.fileSize) {
        console.error(
          '[Beam SW] file size mismatch: expected',
          session.fileMetadata.fileSize,
          'got',
          totalLen,
        );
        await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
        return true;
      }

      await onFileComplete({
        bytes: combined,
        fileName: session.fileMetadata.fileName,
        fileSize: session.fileMetadata.fileSize,
        mimeType: session.fileMetadata.mime || 'application/octet-stream',
        fromDeviceId: session.peerId,
      });
      await ctx.registry.destroy(session.transferId);
    }
  } catch (err) {
    console.error('[Beam SW] file frame decrypt failed at index', index, err);
    await ctx.registry.destroy(session.transferId, ERROR_CODES.DECRYPT_FAIL);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toHexFromB64url(b64) {
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/') + pad);
  let hex = '';
  for (let i = 0; i < bin.length; i += 1) {
    hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex;
}
