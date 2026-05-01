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
      onClipboardReceived: args.onClipboardReceived,
      onFileReceived:      args.onFileReceived,
    },
  });
  return _transport;
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
