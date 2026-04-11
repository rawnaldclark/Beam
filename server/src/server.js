/**
 * server.js — Entry point: HTTP server + WebSocket upgrade with full module wiring.
 *
 * Startup sequence:
 *   1. Construct RateLimiter with spec values.
 *   2. Create HTTP server (handles /health).
 *   3. Create WebSocketServer with 256 KB maxPayload and per-IP connection guard
 *      in verifyClient.
 *   4. Construct Gateway, Presence, Signaling, DataRelay — wired together.
 *   5. Register gateway event listeners for 'authenticated' and 'disconnect'.
 *   6. Register gateway.onMessage() dispatcher for all protocol message types.
 *   7. Register gateway 'binary' event for raw relay frames.
 *   8. Start the presence silence checker.
 *   9. Listen on PORT.
 *
 * Message dispatch order (first match wins; handlers return boolean):
 *   REGISTER_RENDEZVOUS  → presence.register()
 *   SDP_OFFER / SDP_ANSWER / ICE_CANDIDATE → signaling.handleMessage()
 *   RELAY_BIND           → bandwidth guard then dataRelay.handleMessage()
 *   RELAY_RELEASE        → dataRelay.handleMessage()
 *   PING                 → handled inside gateway (belt-and-suspenders no-op here)
 *
 * All authenticated messages:
 *   - Trigger presence.heartbeat() so the silence checker stays happy.
 *   - Pass through the per-connection message rate limiter; the connection is
 *     closed if the limit is exceeded.
 *
 * Binary relay frames:
 *   - addBandwidth() called first (accounting).
 *   - Quota checked; frame discarded (with ERROR) if relay is disabled.
 *   - dataRelay.relayBinary() forwards the frame to the peer.
 *
 * IP tracking:
 *   - On each new WS connection: trackConnection(ip) after verifyClient passes.
 *   - On WS close: releaseConnection(ip) + releaseMessageCounter(connId).
 *
 * @module server
 */

import { createServer }    from 'node:http';
import { WebSocketServer } from 'ws';
import { Gateway }         from './gateway.js';
import { Presence }        from './presence.js';
import { Signaling }       from './signaling.js';
import { DataRelay }       from './relay.js';
import { RateLimiter }     from './ratelimit.js';
import { MSG }             from './protocol.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** WebSocket port sourced from environment or default 8080. */
const PORT = parseInt(process.env.PORT ?? '8080', 10);

/**
 * Maximum WebSocket payload size in bytes (512 KB).
 * Sized to accommodate encrypted Beam file chunks: a 200 KB plaintext
 * padded to the next power-of-2 bucket (256 KB) plus the 16-byte
 * Poly1305 tag and 24-byte Beam binary header. Kept identical to
 * MAX_BINARY_SIZE so the ws library rejects over-sized frames before
 * they reach application code.
 */
const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB

// ---------------------------------------------------------------------------
// Rate limiter (singleton, spec values)
// ---------------------------------------------------------------------------

/**
 * Single RateLimiter instance shared by all handlers.
 * Options match the Task 7 spec exactly.
 *
 * @type {RateLimiter}
 */
const rateLimiter = new RateLimiter({
  maxConnectionsPerIp:   5,
  maxMessagesPerSec:     50,
  maxConcurrentDevices:  50,
  monthlyBandwidthBytes: 160 * 1024 ** 3, // 160 GB
  bandwidthWarningRatio: 0.8,
});

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

/**
 * Minimal HTTP server.
 * Routes:
 *   GET /health  — Returns a JSON status snapshot (200).
 *   *            — 404.
 *
 * The /health payload is intentionally lightweight so load-balancer probes
 * add negligible overhead.
 */
const httpServer = createServer((req, res) => {
  if (req.url === '/health') {
    const quota = rateLimiter.quotaInfo();

    /** @type {{ status: string, uptime: number, connections: number, devices: number, sessions: number, bandwidth: object }} */
    const body = {
      status:      'ok',
      uptime:      process.uptime(),
      // gateway and dataRelay are defined below; they are always set by the
      // time any HTTP request arrives (server listens after all modules init).
      connections: gateway.devices.size,
      devices:     gateway.devices.size,
      sessions:    dataRelay.sessions.size,
      bandwidth: {
        usedBytes:  quota.usedBytes,
        limitBytes: quota.limitBytes,
        usedRatio:  quota.usedRatio,
      },
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
    return;
  }

  res.writeHead(404);
  res.end();
});

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------

/**
 * WebSocketServer with two transport-level safeguards:
 *   1. maxPayload rejects over-sized frames at the ws library level.
 *   2. verifyClient enforces the per-IP connection limit before the TCP
 *      handshake completes, minimising resource consumption for abusive clients.
 *
 * verifyClient is called synchronously during the HTTP upgrade; returning false
 * closes the socket with a 429 Too Many Requests response.
 */
const wss = new WebSocketServer({
  server:     httpServer,
  maxPayload: MAX_PAYLOAD_BYTES,

  /**
   * @param {{ req: import('node:http').IncomingMessage }} info
   * @param {(result: boolean, code?: number, message?: string) => void} cb
   */
  verifyClient(info, cb) {
    // Extract the real client IP, respecting common reverse-proxy headers.
    const ip =
      (info.req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() ||
      info.req.socket.remoteAddress ||
      'unknown';

    if (!rateLimiter.allowConnection(ip)) {
      // Reject: too many connections from this IP.
      cb(false, 429, 'Too Many Connections');
      return;
    }

    // Accept: attach the resolved IP to the request so the connection handler
    // can retrieve it without repeating the header-parsing logic.
    info.req._clientIp = ip;
    cb(true);
  },
});

// ---------------------------------------------------------------------------
// Application modules
// ---------------------------------------------------------------------------

/**
 * Gateway — manages the WebSocket lifecycle and auth handshake.
 * Constructed without passing `wss` to the constructor so we can wire the
 * 'connection' event ourselves and intercept the IP for rate-limit tracking.
 *
 * @type {Gateway}
 */
const gateway = new Gateway({ authTimeoutMs: 30_000 });

/**
 * Presence — tracks online/offline status and rendezvous groups.
 * @type {Presence}
 */
const presence = new Presence({ gateway });

/**
 * Signaling — relays SDP and ICE messages between rendezvous peers.
 * @type {Signaling}
 */
const signaling = new Signaling(gateway, presence);

/**
 * DataRelay — manages binary relay sessions with backpressure and byte caps.
 * @type {DataRelay}
 */
const dataRelay = new DataRelay({ gateway });

// ---------------------------------------------------------------------------
// WebSocket connection wiring
// ---------------------------------------------------------------------------

/**
 * Map from WebSocket → client IP.
 * Used to call releaseConnection() on close without re-parsing headers.
 *
 * @type {Map<import('ws').WebSocket, string>}
 */
const wsToIp = new Map();

/**
 * Map from WebSocket → stable connection ID used for message rate limiting.
 * We use a simple incrementing integer converted to a string. This gives
 * O(1) lookup without requiring a UUID library.
 *
 * @type {Map<import('ws').WebSocket, string>}
 */
const wsToConnId = new Map();

/** Monotonically incrementing counter for generating connection IDs. */
let _nextConnId = 0;

// Intercept the 'connection' event at the wss level to:
//   a) record the IP in wsToIp so releaseConnection() works on close.
//   b) assign a stable connId for the message rate limiter.
//   c) forward the connection into the Gateway for auth processing.
//   d) install a close handler for cleanup.
wss.on('connection', (ws, req) => {
  // The IP was resolved and attached by verifyClient.
  const ip = req._clientIp ?? req.socket.remoteAddress ?? 'unknown';

  // Record the accepted connection and assign a stable ID.
  rateLimiter.trackConnection(ip);
  wsToIp.set(ws, ip);

  const connId = String(_nextConnId++);
  wsToConnId.set(ws, connId);

  // Delegate the connection to the gateway for the auth handshake.
  // Gateway._onConnection() sets up message/close handlers on ws internally.
  gateway._onConnection(ws);

  // Close handler: clean up rate-limiter state for this connection.
  // Note: gateway._onClose() is also registered by _onConnection(); both fire
  // on the same 'close' event — order is insertion order, which is fine here.
  ws.on('close', () => {
    rateLimiter.releaseConnection(ip);
    rateLimiter.releaseMessageCounter(connId);
    wsToIp.delete(ws);
    wsToConnId.delete(ws);
  });
});

// ---------------------------------------------------------------------------
// Gateway event listeners
// ---------------------------------------------------------------------------

/**
 * 'authenticated' — fired by Gateway after a successful auth handshake.
 *
 * Checks the concurrent device ceiling. If the limit would be exceeded the
 * connection is closed immediately with an ERROR frame.  Otherwise the device
 * is registered with the rate limiter.
 */
gateway.on('authenticated', (deviceId, ws) => {
  if (!rateLimiter.allowDevice()) {
    // Send an informative error before closing so the client can display a
    // meaningful message rather than a bare WebSocket close code.
    try {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type:    MSG.ERROR,
          message: 'Server at capacity: maximum concurrent devices reached',
        }));
      }
    } catch { /* ignore send errors during forced close */ }

    ws.close();
    return;
  }

  rateLimiter.trackDevice(deviceId);
});

/**
 * 'disconnect' — fired by Gateway when an authenticated device's WebSocket closes.
 *
 * Cleans up presence registration, device rate-limit slot, and relay sessions.
 */
gateway.on('disconnect', (deviceId) => {
  presence.unregister(deviceId);
  rateLimiter.releaseDevice(deviceId);
  dataRelay.handleDisconnect(deviceId);
});

// ---------------------------------------------------------------------------
// Message dispatcher
// ---------------------------------------------------------------------------

/**
 * Central message router registered via gateway.onMessage().
 *
 * Every call:
 *   1. Looks up the connId for the WebSocket (for rate limiting).
 *   2. Enforces the per-connection message rate limit; closes on violation.
 *   3. Updates the presence heartbeat so the silence checker stays happy.
 *   4. Routes to the appropriate sub-handler based on msg.type.
 *
 * @param {string} deviceId - Authenticated device ID.
 * @param {object} msg      - Validated protocol message.
 * @param {import('ws').WebSocket} ws - Sender's WebSocket.
 */
gateway.onMessage((deviceId, msg, ws) => {
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

    // Peer discovery registration
    case MSG.REGISTER_RENDEZVOUS:
      presence.register(deviceId, msg.rendezvousIds);
      break;

    // WebRTC signaling + pairing — Signaling.handleMessage() returns true when handled.
    case MSG.SDP_OFFER:
    case MSG.SDP_ANSWER:
    case MSG.ICE_CANDIDATE:
    case MSG.PAIRING_REQUEST:
    case MSG.PAIRING_ACK:
    case MSG.CLIPBOARD_TRANSFER:
    case MSG.FILE_OFFER:
    case MSG.FILE_ACCEPT:
    case MSG.FILE_COMPLETE:
    case MSG.TRANSFER_INIT:
    case MSG.TRANSFER_ACCEPT:
    case MSG.TRANSFER_REJECT:
      signaling.handleMessage(deviceId, msg, ws);
      break;

    // Relay session binding — check bandwidth quota before accepting.
    case MSG.RELAY_BIND:
      if (rateLimiter.isRelayDisabled()) {
        gateway.sendTo(ws, {
          type:    MSG.ERROR,
          message: 'Relay unavailable: monthly bandwidth quota nearly exhausted',
        });
        break;
      }
      dataRelay.handleMessage(deviceId, msg, ws);
      break;

    // Relay session release — no quota check needed.
    case MSG.RELAY_RELEASE:
      dataRelay.handleMessage(deviceId, msg, ws);
      break;

    // PING is already handled inside Gateway (which sends PONG and returns
    // before calling onMessage).  This case is a belt-and-suspenders no-op
    // for any future path where PING might propagate here.
    case MSG.PING:
      // Already handled; nothing to do.
      break;

    default:
      // Unknown types are caught by protocol.validate() before reaching here;
      // this default is a defensive no-op.
      break;
  }
});

// ---------------------------------------------------------------------------
// Binary relay frames
// ---------------------------------------------------------------------------

/**
 * 'binary' event from the Gateway (forwarded from the ws 'message' event when
 * the payload is a Buffer rather than a string).
 *
 * Note: the current Gateway implementation does not emit a dedicated 'binary'
 * event — all frames arrive via onMessage() after JSON.parse().  Binary relay
 * data is therefore handled by the DataRelay module directly via relayBinary().
 *
 * To support true binary passthrough (bypassing JSON) we listen on the raw wss
 * 'connection' event above and attach a per-socket 'message' listener that
 * intercepts Buffer frames before the Gateway's JSON parser sees them.
 *
 * This listener is installed inside the wss 'connection' handler below.
 */
wss.on('connection', (ws) => {
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return; // text frames are handled by the gateway

    // Attribute the frame to the authenticated device.
    const deviceId = gateway.wsToDevice.get(ws);
    if (!deviceId) return; // not yet authenticated — discard binary frames

    // Bandwidth accounting (always, even if relay is about to be disabled).
    const byteLength = Buffer.isBuffer(data) ? data.length : data.byteLength;
    rateLimiter.addBandwidth(byteLength);

    // Quota gate — if relay is disabled, send an error and discard.
    if (rateLimiter.isRelayDisabled()) {
      gateway.sendTo(ws, {
        type:    MSG.ERROR,
        message: 'Relay unavailable: monthly bandwidth quota nearly exhausted',
      });
      return;
    }

    // Forward to the relay module.
    dataRelay.relayBinary(deviceId, data, ws);
  });
});

// ---------------------------------------------------------------------------
// Presence silence checker
// ---------------------------------------------------------------------------

/**
 * Start the background sweep that unregisters devices that have gone silent.
 * The timer is unref()d inside Presence so it does not prevent clean shutdown.
 */
presence.startSilenceChecker();

// ---------------------------------------------------------------------------
// Start listening
// ---------------------------------------------------------------------------

httpServer.listen(PORT, () => {
  console.log(`ZapTransfer relay listening on :${PORT}`);
});

// ---------------------------------------------------------------------------
// Exports (used by integration tests and health check)
// ---------------------------------------------------------------------------

export { httpServer, wss, gateway, presence, signaling, dataRelay, rateLimiter };
