// Beam E2E encryption — crypto context (Chrome service worker).
//
// Lazily loads the SW's long-term identity keys and the paired device roster,
// extracts the raw X25519 private scalar from PKCS8, and vends a ready
// SessionRegistry for sendClipboardEncrypted / onTransferInit / etc.
//
// The context is a singleton for the lifetime of the service worker. It is
// invalidated automatically when:
//   * the keys change in chrome.storage.local (e.g. user re-pairs), or
//   * the SW is restarted (everything is reloaded from storage).
//
// Exposes:
//   getCryptoContext() → Promise<{
//     ourDeviceId, ourStaticSk, ourStaticPk,
//     registry,
//     peerStaticPk(deviceId): Uint8Array | null,
//     invalidate()
//   }>

import {
  pkcs8X25519SkToRaw,
  x25519PublicKey,
} from './beam-crypto.js';
import { SessionRegistry } from './session-registry.js';

let _contextPromise = null;

export function invalidateCryptoContext() {
  _contextPromise = null;
}

export async function getCryptoContext() {
  if (!_contextPromise) {
    _contextPromise = _buildContext();
  }
  try {
    return await _contextPromise;
  } catch (err) {
    // Clear the cache on failure so the next call retries instead of
    // sticking to a rejected promise.
    _contextPromise = null;
    throw err;
  }
}

async function _buildContext() {
  const stored = await chrome.storage.local.get([
    'deviceId',
    'deviceKeys',
    'pairedDevices',
  ]);

  if (!stored.deviceId) {
    throw new Error('beam-crypto-context: no deviceId in storage');
  }
  if (!stored.deviceKeys?.x25519?.sk || !stored.deviceKeys?.x25519?.pk) {
    throw new Error('beam-crypto-context: x25519 keys missing');
  }

  const skPkcs8 = new Uint8Array(stored.deviceKeys.x25519.sk);
  const ourStaticSk = pkcs8X25519SkToRaw(skPkcs8);
  const storedPk = new Uint8Array(stored.deviceKeys.x25519.pk);

  // Self-check: derived pk must match the stored pk. If not, the PKCS8
  // parse is wrong or the key pair is corrupt.
  const derivedPk = await x25519PublicKey(ourStaticSk);
  if (derivedPk.byteLength !== storedPk.byteLength ||
      !derivedPk.every((b, i) => b === storedPk[i])) {
    throw new Error('beam-crypto-context: derived pk does not match stored pk');
  }

  // Peer roster — pairedDevices each have { deviceId, x25519PublicKey: number[] }.
  const pairedDevices = Array.isArray(stored.pairedDevices) ? stored.pairedDevices : [];
  const peerMap = new Map();
  for (const d of pairedDevices) {
    if (d && d.deviceId && Array.isArray(d.x25519PublicKey)) {
      peerMap.set(d.deviceId, new Uint8Array(d.x25519PublicKey));
    }
  }

  const registry = new SessionRegistry({
    ourStaticSk,
    ourStaticPk: derivedPk,
  });
  registry.startSweep();

  const context = {
    ourDeviceId: stored.deviceId,
    ourStaticSk,
    ourStaticPk: derivedPk,
    registry,
    peerStaticPk(deviceId) {
      return peerMap.get(deviceId) || null;
    },
    invalidate: invalidateCryptoContext,
  };

  return context;
}

// Invalidate the cached context whenever stored keys or paired devices change
// so a re-pair or fresh device immediately takes effect.
if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.deviceKeys || changes.deviceId || changes.pairedDevices) {
      invalidateCryptoContext();
    }
  });
}
