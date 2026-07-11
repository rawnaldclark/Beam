/**
 * router.js — central authenticated-message dispatcher.
 *
 * Extracted from server.js so the REAL routing is importable and testable
 * (server.js listens on import and cannot be loaded in a unit test). Both
 * server.js and integration.test.js build the router from this one factory, so
 * there is no second copy of the switch to drift out of sync — the drift is
 * what let peer-ping/peer-pong/beam-v2-* be dropped in production while their
 * signaling.test.js coverage stayed green.
 *
 * Every authenticated message:
 *   - passes the per-connection message rate limiter (connection closed on
 *     violation);
 *   - triggers presence.heartbeat() so the silence checker stays happy.
 *
 * Routing:
 *   REGISTER_RENDEZVOUS → presence.register()
 *   RELAY_BIND          → bandwidth guard, then dataRelay.handleMessage()
 *   RELAY_RELEASE       → dataRelay.handleMessage()
 *   PING                → handled inside the gateway (no-op here)
 *   everything else     → signaling.handleMessage(), which relays exactly the
 *                         allow-listed SIGNALING_TYPES (SDP/ICE/pairing/transfer
 *                         /peer-ping/peer-pong/beam-v2-*) and returns false for
 *                         genuinely unknown types (already rejected by
 *                         protocol.validate() before dispatch).
 *
 * @param {object} deps
 * @param {import('./ratelimit.js').RateLimiter} deps.rateLimiter
 * @param {Map<object,string>} deps.wsToConnId
 * @param {import('./presence.js').Presence}   deps.presence
 * @param {import('./signaling.js').Signaling} deps.signaling
 * @param {import('./relay.js').DataRelay}     deps.dataRelay
 * @param {import('./gateway.js').Gateway}     deps.gateway
 * @returns {(deviceId: string, msg: object, ws: object) => void}
 */
import { MSG } from './protocol.js';

export function createMessageRouter({ rateLimiter, wsToConnId, presence, signaling, dataRelay, gateway }) {
  return (deviceId, msg, ws) => {
    // --- Rate limit check ---
    const connId = wsToConnId.get(ws) ?? deviceId;
    if (!rateLimiter.allowMessage(connId)) {
      try {
        if (ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({
            type:    MSG.ERROR,
            message: 'Rate limit exceeded: too many messages per second',
          }));
          ws.close();
        }
      } catch { /* ignore */ }
      return;
    }

    // --- Heartbeat (presence keeps device alive) ---
    presence.heartbeat(deviceId);

    // --- Route by message type ---
    switch (msg.type) {
      case MSG.REGISTER_RENDEZVOUS:
        presence.register(deviceId, msg.rendezvousIds);
        return;

      case MSG.RELAY_BIND:
        if (rateLimiter.isRelayDisabled()) {
          gateway.sendTo(ws, {
            type:    MSG.ERROR,
            message: 'Relay unavailable: monthly bandwidth quota nearly exhausted',
          });
          return;
        }
        dataRelay.handleMessage(deviceId, msg, ws);
        return;

      case MSG.RELAY_RELEASE:
        dataRelay.handleMessage(deviceId, msg, ws);
        return;

      case MSG.PING:
        // Already handled inside the gateway (PONG sent before onMessage).
        return;

      default:
        // All allow-listed signaling types route here. handleMessage() enforces
        // rendezvous membership and returns false for non-signaling types.
        signaling.handleMessage(deviceId, msg, ws);
        return;
    }
  };
}
