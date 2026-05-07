/**
 * @file beam-v2-wiring.js
 * @description Construct and configure the singleton `BeamV2Transport` for
 * the Chrome service worker. Bridges the transport's hook surface to
 * `chrome.storage.local` (peer roster + K_AB ring) and to the existing
 * `deliverIncomingClipboard` / `deliverIncomingFile` delivery functions.
 *
 * The transport itself is pure crypto + state-machine; this module is the
 * adapter that makes it speak Chrome storage and the SW delivery UX.
 */

import { BeamV2Transport } from './beam-v2-transport.js';
import { pkcs8X25519SkToRaw } from './beam-crypto.js';
import { getConnectionAuthority } from '../connection/connection-authority-wiring.js';
import { MSG } from '../shared/message-types.js';

/**
 * Coerce whatever shape the popup stored as `deviceKeys.x25519.sk` into a
 * 32-byte raw scalar. The popup uses Web Crypto `exportKey('pkcs8', …)`,
 * which is supposed to produce 48-byte PKCS8 ASN.1 — but Chrome returns
 * differently across versions:
 *
 *   - 48 bytes: proper PKCS8 ASN.1 (spec'd path)
 *   - 32 bytes: raw scalar with no wrapping (current Chrome desktop)
 *   - 64 bytes: seed || publicKey concatenation (Ed25519-style)
 *
 * Treating all three is cheap and means a Chrome change never silently
 * breaks transfers again.
 */
function coerceX25519SkRaw(skBytesOrArray) {
  const sk = skBytesOrArray instanceof Uint8Array
    ? skBytesOrArray
    : new Uint8Array(skBytesOrArray);
  if (sk.byteLength === 48) return pkcs8X25519SkToRaw(sk);
  if (sk.byteLength === 64 || sk.byteLength === 32) return sk.slice(0, 32);
  throw new Error('unsupported X25519 sk byte length: ' + sk.byteLength);
}

/** @type {BeamV2Transport|null} */
let _transport = null;

/**
 * Per-outbound-transfer metadata seeded by the transport's `onSendStart` hook
 * and consumed by `onProgress` to expand the transport's bare
 * `(transferIdHex, percent)` event into the popup's full
 * `MSG.TRANSFER_PROGRESS` and (at 100%) `MSG.TRANSFER_COMPLETE` shapes.
 *
 * Keyed by `transferIdHex` (lower-case hex string).
 *
 * @type {Map<string, {
 *   targetDeviceId: string,
 *   fileName: string,
 *   totalBytes: number,
 *   startedAt: number,
 * }>}
 */
const _outboundMeta = new Map();

/**
 * TEST-ONLY: surface the metadata map for assertion in unit tests. Production
 * code never reads this directly — callers go through the transport's hooks.
 *
 * @returns {Map<string, object>}
 */
export function _getOutboundMetaForTest() {
  return _outboundMeta;
}

/**
 * Build the popup-facing TRANSFER_PROGRESS payload from a transferId + percent
 * pair, looking up the metadata map and computing a rolling speed estimate.
 *
 * Returns `null` if no metadata has been seeded for this transferId — the
 * caller should drop the event in that case (it would have only `transferId`
 * + `percent`, not enough to render meaningfully).
 *
 * @param {string} transferIdHex
 * @param {number} percent  — 0..100, monotonic per the transport's send loop
 * @returns {{
 *   transferId: string, fileName: string,
 *   bytesTransferred: number, totalBytes: number,
 *   speedBps: number, targetDeviceId: string,
 * } | null}
 */
function buildProgressPayload(transferIdHex, percent) {
  const meta = _outboundMeta.get(transferIdHex);
  if (!meta) return null;
  const bytesTransferred = Math.round((percent / 100) * meta.totalBytes);

  // Cumulative average since send start. Mirrors the v1 transfer-manager
  // `_estimateSpeed` shape (bytes/sec) without sharing its module state.
  const elapsedMs = Date.now() - meta.startedAt;
  const speedBps  = elapsedMs < 100 ? 0 : Math.round((bytesTransferred / elapsedMs) * 1000);

  return {
    transferId: transferIdHex,
    fileName:   meta.fileName,
    bytesTransferred,
    totalBytes: meta.totalBytes,
    speedBps,
    targetDeviceId: meta.targetDeviceId,
  };
}

/**
 * Push a chrome.runtime message to the popup. Failures are swallowed —
 * `chrome.runtime.sendMessage` rejects with "Receiving end does not exist"
 * whenever the popup is closed, which is the common case.
 *
 * @param {string} type
 * @param {object} payload
 */
function emitToPopup(type, payload) {
  try {
    const p = chrome?.runtime?.sendMessage?.({ type, payload });
    if (p && typeof p.catch === 'function') p.catch(() => {});
  } catch {
    /* popup closed — drop silently */
  }
}

/**
 * Lazily construct (or return) the singleton transport. The send hooks
 * (`sendBinary`, `sendJson`) are passed in by the caller so we don't depend
 * on `background-relay.js` here — that keeps this module testable and
 * avoids circular imports.
 *
 * @param {{
 *   sendBinary: (bytes: Uint8Array) => boolean,
 *   sendJson:   (msg: object) => void,
 *   onClipboardReceived: (content: string, fromDeviceId: string) => Promise<void>,
 *   onFileReceived: (args: { bytes: Uint8Array, fileName: string, fileSize: number, mimeType: string, fromDeviceId: string }) => Promise<void>,
 * }} args
 * @returns {BeamV2Transport}
 */
export function ensureTransport(args) {
  if (_transport) return _transport;
  _transport = new BeamV2Transport({
    sendBinary: args.sendBinary,
    sendJson:   args.sendJson,
    hooks: {
      getPeer:      (id) => loadPeer(id),
      listPeers:    () => loadAllPeers(),
      storeKABRing: (id, ring) => storeKABRing(id, ring),
      // Wrap the user-supplied delivery callbacks so the ConnectionAuthority
      // observes a successful v2 frame decode (strong proof of peer life)
      // alongside the existing UX delivery. Authority is null until the
      // wiring layer constructs it inside `_doConnect` — `?.` makes the
      // hooks safe to call from tests that bypass the SW startup path.
      onClipboardReceived: async (content, fromDeviceId) => {
        getConnectionAuthority()?.notifyFrameReceived(fromDeviceId);
        await args.onClipboardReceived(content, fromDeviceId);
      },
      onFileReceived: async (a) => {
        getConnectionAuthority()?.notifyFrameReceived(a.fromDeviceId);
        await args.onFileReceived(a);
      },
      // ── Outbound progress wiring (Task 10.5) ───────────────────────────
      // The transport emits `(transferIdHex, percent)` from inside its
      // chunked send loop. We expand it into the popup's full
      // `MSG.TRANSFER_PROGRESS` payload using metadata seeded by
      // `onSendStart` below. Decision: chose Option A from the task plan
      // (an `onSendStart` transport hook) over Option B (pre-compute the
      // transferId outside the transport) because Option A is a 5-line
      // additive change to TransportHooks while Option B would require
      // inverting the transport's transferId ownership model.
      onSendStart: (transferIdHex, sendArgs) => {
        // Only file sends drive a streaming progress UI. Clipboard sends
        // fire `onSendStart` for symmetry, but their single-frame nature
        // means there's no per-chunk progress to surface — skip the seed
        // to avoid leaking entries that nothing will ever clean up.
        if (sendArgs.kind !== 'file') return;
        _outboundMeta.set(transferIdHex, {
          targetDeviceId: sendArgs.targetDeviceId,
          fileName:       sendArgs.fileName ?? 'file',
          totalBytes:     sendArgs.fileSize ?? 0,
          startedAt:      Date.now(),
        });
      },
      onProgress: (transferIdHex, percent) => {
        const payload = buildProgressPayload(transferIdHex, percent);
        if (!payload) return; // unseeded id — drop (e.g. tests that bypass onSendStart)
        emitToPopup(MSG.TRANSFER_PROGRESS, payload);
        // Final tick (`percent === 100` on the final iteration of the send
        // loop) is the cleanup signal AND the success-state trigger for the
        // popup's device-row UI. The popup's MSG.TRANSFER_COMPLETE handler
        // (popup.js) destructures `{ transferId, fileName, fileSize,
        // targetDeviceId }` — match that shape exactly. v1's transfer-
        // manager emits the same on its happy path; this brings v2 to parity.
        if (percent >= 100) {
          const meta = _outboundMeta.get(transferIdHex);
          if (meta) {
            emitToPopup(MSG.TRANSFER_COMPLETE, {
              transferId:     transferIdHex,
              fileName:       meta.fileName,
              fileSize:       meta.totalBytes,
              targetDeviceId: meta.targetDeviceId,
            });
          }
          _outboundMeta.delete(transferIdHex);
        }
      },
      onSendError: (transferIdHex, _code) => {
        _outboundMeta.delete(transferIdHex);
      },
    },
  });
  return _transport;
}

/**
 * Drop the cached transport so the next {@link ensureTransport} call constructs
 * a fresh one. Used by Rung 3 of the recovery ladder (see `background-relay.js`
 * `forceFullReset`) to clear any in-flight per-transfer state machines / cipher
 * caches a stale session may have accumulated.
 *
 * Discipline: callers MUST also tear down the WebSocket and reissue
 * `ensureTransport` with fresh hooks afterwards — we reset the singleton, not
 * the relay's view of us. The transport's chunked-send state for any in-flight
 * transfers is dropped on the floor (Rung 3 is a "give up and start over"
 * recovery, not a graceful close).
 */
export function _resetTransportSingleton() {
  _transport = null;
  // Drop the per-transfer metadata seeded by `onSendStart`. Any progress
  // events that arrive after a Rung-3 reset would target a stale targetDeviceId
  // anyway (the recovery ladder is post-failure cleanup).
  _outboundMeta.clear();
}

// ---------------------------------------------------------------------------
// Hooks: peer roster ↔ chrome.storage.local
// ---------------------------------------------------------------------------

/**
 * @returns {Promise<{
 *   ourSk: Uint8Array, ourPk: Uint8Array, ourEdPk: Uint8Array
 * }|null>}
 */
async function loadOurKeys() {
  const { deviceKeys } = await chrome.storage.local.get('deviceKeys');
  if (!deviceKeys?.x25519?.sk || !deviceKeys?.x25519?.pk || !deviceKeys?.ed25519?.pk) {
    return null;
  }
  return {
    ourSk:   coerceX25519SkRaw(deviceKeys.x25519.sk),
    ourPk:   new Uint8Array(deviceKeys.x25519.pk),
    ourEdPk: new Uint8Array(deviceKeys.ed25519.pk),
  };
}

async function loadPeer(deviceId) {
  const ours = await loadOurKeys();
  if (!ours) return null;
  const { pairedDevices } = await chrome.storage.local.get('pairedDevices');
  const entry = (pairedDevices || []).find((d) => d.deviceId === deviceId);
  if (!entry) return null;
  return toPairedPeer(entry, ours);
}

async function loadAllPeers() {
  const ours = await loadOurKeys();
  if (!ours) return [];
  const { pairedDevices } = await chrome.storage.local.get('pairedDevices');
  return (pairedDevices || [])
    .map((d) => toPairedPeer(d, ours))
    .filter(Boolean);
}

function toPairedPeer(entry, ours) {
  const ring = entry.kABRing;
  if (!ring || typeof ring.currentGeneration !== 'number' || !ring.keys) return null;
  // Decode kAB hex/array into Uint8Array per generation.
  const decodedKeys = {};
  for (const [gen, k] of Object.entries(ring.keys)) {
    if (!k || !k.kAB) continue;
    decodedKeys[gen] = {
      ...k,
      kAB: Array.isArray(k.kAB) ? new Uint8Array(k.kAB) : hexToBytes(k.kAB),
    };
  }
  return {
    deviceId:  entry.deviceId,
    ourSk:     ours.ourSk,
    peerPk:    new Uint8Array(entry.x25519PublicKey),
    ourEdPk:   ours.ourEdPk,
    peerEdPk:  new Uint8Array(entry.ed25519PublicKey),
    kABRing: {
      currentGeneration: ring.currentGeneration,
      keys: decodedKeys,
    },
  };
}

async function storeKABRing(deviceId, ring) {
  const { pairedDevices } = await chrome.storage.local.get('pairedDevices');
  const list = pairedDevices || [];
  const idx = list.findIndex((d) => d.deviceId === deviceId);
  if (idx < 0) return;
  // Re-encode kAB Uint8Arrays as plain arrays for chrome.storage JSON.
  const encodedKeys = {};
  for (const [gen, k] of Object.entries(ring.keys)) {
    if (!k || !k.kAB) continue;
    encodedKeys[gen] = {
      ...k,
      kAB: Array.from(k.kAB),
      rotateNonce: k.rotateNonce ? Array.from(k.rotateNonce) : undefined,
    };
  }
  list[idx] = {
    ...list[idx],
    kABRing: {
      currentGeneration: ring.currentGeneration,
      keys: encodedKeys,
    },
  };
  await chrome.storage.local.set({ pairedDevices: list });
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
}
