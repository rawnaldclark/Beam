/**
 * @file connection-authority-wiring.js
 * @description Singleton accessor for the {@link ConnectionAuthority} instance.
 *
 * The Chrome service worker constructs at most one authority per SW lifetime;
 * `background-relay.js` and `beam-v2-wiring.js` import these helpers to wire
 * the authority's notify-methods into the WS lifecycle, peer presence
 * messages, and v2 frame decode/send events.
 *
 * The hooks supplied to {@link ensureConnectionAuthority} let the authority
 * (a) send JSON over the live WS via the wiring's `sendJson`, and (b) know
 * its own deviceId so peer-ping frames carry the correct `rendezvousId`.
 *
 * Tasks 8 and 11 will extend the hook bag with reconnect / full-reset
 * triggers; Task 6 only wires the inputs.
 */

import { ConnectionAuthority } from './connection-authority.js';

/** @type {ConnectionAuthority|null} */
let _authority = null;

/**
 * Lazy singleton accessor. Constructs the authority on first call and
 * returns the same instance on every subsequent call (the `hooks` argument
 * is ignored after the first call).
 *
 * @param {{
 *   sendJson: (msg: object) => void,
 *   ownDeviceId: string,
 * }} hooks
 * @returns {ConnectionAuthority}
 */
export function ensureConnectionAuthority(hooks) {
  if (_authority) return _authority;
  _authority = new ConnectionAuthority({ signalingHooks: hooks });
  return _authority;
}

/**
 * Read-only accessor for callers that should not construct the authority
 * themselves. Returns `null` if {@link ensureConnectionAuthority} has not
 * yet been called (e.g. during SW boot before the WS connect path runs).
 *
 * @returns {ConnectionAuthority|null}
 */
export function getConnectionAuthority() {
  return _authority;
}

/**
 * TEST-ONLY: clear the singleton so subsequent tests can inject fresh state
 * with different hooks. Production code paths must never call this.
 */
export function _resetConnectionAuthority() {
  _authority = null;
}
