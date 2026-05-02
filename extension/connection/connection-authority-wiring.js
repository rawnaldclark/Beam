/**
 * @file connection-authority-wiring.js
 * @description Singleton accessor for the {@link ConnectionAuthority} instance.
 *
 * The Chrome service worker constructs at most one authority per SW lifetime;
 * `background-relay.js` and `beam-v2-wiring.js` import these helpers to wire
 * the authority's notify-methods into the WS lifecycle, peer presence
 * messages, and v2 frame decode/send events.
 *
 * The hooks supplied to {@link ensureConnectionAuthority} let the authority:
 *   - (a) send JSON over the live WS via `sendJson`,
 *   - (b) know its own deviceId so peer-ping frames carry the correct
 *         `rendezvousId`,
 *   - (c) trigger a full WS tear-down + reconnect via `forceWsReconnect`
 *         when the recovery ladder's Rung 2 fires (Task 8 declares the
 *         contract; the wiring-layer implementation lands in a follow-up
 *         task — `background-relay.js` will close `pairingWs` and re-enter
 *         `_doConnect`).
 *
 * Task 11 will extend the hook bag further with full-reset triggers for
 * Rung 3.
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
 *   forceWsReconnect?: () => void | Promise<void>,
 *   register?: () => void | Promise<void>,
 * }} hooks
 *   `forceWsReconnect` is optional at the type level: skeleton-mode tests
 *   omit it (Rung 2 surrenders fast in that case), and the wiring-layer
 *   implementation is a follow-up to Task 8. `register` is an optional
 *   alternate to the default `sendJson({type:'register-rendezvous', ...})`
 *   used by Rung 1.
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
