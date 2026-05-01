/**
 * @file relay-fixture.js
 * @description Spins up a real ZapTransfer relay (Gateway + Presence +
 * Signaling + DataRelay) on a random local port for extension E2E tests.
 *
 * Mirrors the wiring in `server/src/server.js` exactly, minus the origin
 * allowlist (tests connect from a Node process with no Origin header).
 * Exposes the module instances on the returned handle so a test can
 * inspect server-side state — e.g. `gateway.devices.size` after a race.
 */

import http from 'node:http';
import { WebSocketServer } from 'ws';

import { Gateway }     from '../../../server/src/gateway.js';
import { Presence }    from '../../../server/src/presence.js';
import { Signaling }   from '../../../server/src/signaling.js';
import { DataRelay }   from '../../../server/src/relay.js';
import { RateLimiter } from '../../../server/src/ratelimit.js';
import { MSG }         from '../../../server/src/protocol.js';

/**
 * Start a relay on `127.0.0.1:<random>` and return a handle.
 *
 * @returns {Promise<{
 *   url: string,
 *   port: number,
 *   gateway: Gateway,
 *   presence: Presence,
 *   dataRelay: DataRelay,
 *   close: () => Promise<void>,
 * }>}
 */
export function startTestRelay() {
  return new Promise((resolve, reject) => {
    const rateLimiter = new RateLimiter({
      maxConnectionsPerIp:   50, // generous for tests
      maxMessagesPerSec:     5_000,
      maxConcurrentDevices:  500,
      monthlyBandwidthBytes: 160 * 1024 ** 3,
      bandwidthWarningRatio: 0.8,
    });

    const httpServer = http.createServer((_req, res) => {
      res.writeHead(404); res.end();
    });

    const wss = new WebSocketServer({
      server:     httpServer,
      maxPayload: 512 * 1024,
      verifyClient(info, cb) {
        const ip = info.req.socket.remoteAddress || 'test';
        if (!rateLimiter.allowConnection(ip)) {
          cb(false, 429, 'Too Many Connections');
          return;
        }
        info.req._clientIp = ip;
        cb(true);
      },
    });

    const gateway   = new Gateway({ authTimeoutMs: 10_000 });
    const presence  = new Presence({ gateway });
    const signaling = new Signaling(gateway, presence);
    const dataRelay = new DataRelay({ gateway });

    const wsToConnId = new Map();
    let _nextConnId = 0;

    wss.on('connection', (ws, req) => {
      const ip = req._clientIp ?? 'test';
      const connId = String(_nextConnId++);
      rateLimiter.trackConnection(ip);
      wsToConnId.set(ws, connId);

      gateway._onConnection(ws, req);

      ws.on('close', () => {
        rateLimiter.releaseConnection(ip);
        rateLimiter.releaseMessageCounter(connId);
        wsToConnId.delete(ws);
      });
    });

    gateway.on('authenticated', (deviceId, ws) => {
      if (!rateLimiter.allowDevice()) {
        try { ws.close(); } catch { /* ignore */ }
        return;
      }
      rateLimiter.trackDevice(deviceId);
    });

    gateway.on('disconnect', (deviceId) => {
      presence.unregister(deviceId);
      rateLimiter.releaseDevice(deviceId);
      dataRelay.handleDisconnect(deviceId);
    });

    gateway.onMessage((deviceId, msg, ws) => {
      const connId = wsToConnId.get(ws) ?? deviceId;
      if (!rateLimiter.allowMessage(connId)) {
        try { ws.close(); } catch { /* ignore */ }
        return;
      }
      presence.heartbeat(deviceId);

      switch (msg.type) {
        case MSG.REGISTER_RENDEZVOUS:
          presence.register(deviceId, msg.rendezvousIds);
          break;
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
        case MSG.RELAY_BIND:
        case MSG.RELAY_RELEASE:
          dataRelay.handleMessage(deviceId, msg, ws);
          break;
        default:
          break;
      }
    });

    wss.on('connection', (ws) => {
      ws.on('message', (data, isBinary) => {
        if (!isBinary) return;
        const deviceId = gateway.wsToDevice.get(ws);
        if (!deviceId) return;
        rateLimiter.addBandwidth(Buffer.isBuffer(data) ? data.length : data.byteLength);
        dataRelay.relayBinary(deviceId, data, ws);
      });
    });

    presence.startSilenceChecker();

    httpServer.listen(0, '127.0.0.1', () => {
      const { port } = httpServer.address();
      const url = `ws://127.0.0.1:${port}`;
      const close = () => new Promise((res) => {
        for (const client of wss.clients) client.terminate();
        presence.destroy();
        wss.close(() => httpServer.close(() => res()));
      });
      resolve({ url, port, gateway, presence, dataRelay, close });
    });

    httpServer.on('error', reject);
  });
}
