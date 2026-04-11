// Beam crypto: libsodium loader for the MV3 service worker.
//
// Primary strategy: static ES module import of the sumo build from
// extension/lib/sodium-esm/, which gives the SW direct access to the
// crypto_* functions without any cross-context messaging.
//
// If this fails in MV3 (module resolution, WASM instantiation, etc.),
// sodium-loader.spike.md documents the failure and this module is
// rewritten to proxy to the offscreen document (fallback path).

import sodium from '../lib/sodium-esm/libsodium-wrappers.mjs';

let _readyPromise = null;

/**
 * Resolve to the initialized libsodium sumo module.
 * Safe to call repeatedly; initialization happens once.
 */
export function loadSodium() {
  if (!_readyPromise) {
    _readyPromise = sodium.ready.then(() => sodium);
  }
  return _readyPromise;
}
