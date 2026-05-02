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
  _popupBroadcasterInstalled = false;
}

// ---------------------------------------------------------------------------
// Popup broadcaster (Task 10)
// ---------------------------------------------------------------------------

/**
 * Single-flight guard so {@link installPopupBroadcaster} cannot subscribe to
 * the same authority observables twice when called from multiple SW boot
 * paths. Resets via {@link _resetConnectionAuthority} for tests.
 *
 * @type {boolean}
 */
let _popupBroadcasterInstalled = false;

/**
 * Subscribe to the authority's `selfState` and `peerHealth` observables and
 * push a `CONNECTION_STATE_CHANGED` chrome.runtime message on every change so
 * the popup can render the latest state without polling.
 *
 * The payload's `peerHealth` is serialised as a plain object
 * (`{[deviceId]: PeerHealthString}`) — Maps do NOT survive the
 * `chrome.runtime.sendMessage` boundary in MV3, so the popup would see an
 * empty Map and the UI would silently fail to update.
 *
 * Send errors are silently absorbed: when no popup is open, the SW's
 * `sendMessage` rejects with "Could not establish connection. Receiving end
 * does not exist." That's the steady state — the popup's `GET_CONNECTION_STATE`
 * fetch on open recovers the latest snapshot. Any other error (e.g. network
 * stack tear-down during a runtime restart) is also non-fatal here.
 *
 * Safe to call multiple times: a `_popupBroadcasterInstalled` guard ensures
 * the subscriptions are wired exactly once per authority. Call from
 * `_doConnect` (or any equivalent boot path) immediately after
 * `ensureConnectionAuthority` returns the singleton.
 *
 * @returns {void}
 */
export function installPopupBroadcaster() {
  if (_popupBroadcasterInstalled) return;
  const authority = _authority;
  // No-op when called before the authority is constructed — defensive only;
  // the wiring layer always calls this AFTER ensureConnectionAuthority.
  if (!authority) return;
  _popupBroadcasterInstalled = true;

  const broadcast = () => {
    const peerHealthObj = {};
    for (const [peerId, health] of authority.peerHealth.value.entries()) {
      peerHealthObj[peerId] = health;
    }
    const payload = {
      selfState: authority.selfState.value,
      peerHealth: peerHealthObj,
    };
    try {
      // Promise-returning chrome.runtime.sendMessage in MV3; .catch absorbs
      // the "Receiving end does not exist" rejection that fires when the
      // popup is closed (the steady state for a background SW).
      const p = chrome.runtime.sendMessage({
        type: 'CONNECTION_STATE_CHANGED',
        payload,
      });
      if (p && typeof p.catch === 'function') p.catch(() => {});
    } catch {
      // Some test environments stub chrome.runtime — swallow synchronously too.
    }
  };

  // Subscribing replays the current value synchronously, which dispatches an
  // initial broadcast. That's harmless: if the popup is closed, the message
  // is dropped; if open, the popup gets a fresh snapshot it would have asked
  // for via GET_CONNECTION_STATE anyway.
  authority.selfState.subscribe(broadcast);
  authority.peerHealth.subscribe(broadcast);
}
