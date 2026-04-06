/**
 * integration.test.js — Full end-to-end integration test for the ZapTransfer relay.
 *
 * Spins up a real HTTP + WebSocket server with all modules wired together
 * (identical to server.js) and drives two mock clients through the complete
 * transfer flow:
 *
 *   1. Server starts (HTTP + WS + all modules wired)
 *   2. Two WS clients connect
 *   3. Both authenticate with Ed25519 (keypair → challenge → sign → auth-ok)
 *   4. Both register a shared rendezvous ID
 *   5. Each receives PEER_ONLINE for the other
 *   6. Client A sends SDP_OFFER → client B receives it with fromDeviceId
 *   7. Client B sends SDP_ANSWER → client A receives it
 *   8. Client A sends ICE_CANDIDATE → client B receives it
 *   9. Both send RELAY_BIND for same transferId → session created
 *  10. Client A sends binary chunks → client B receives them
 *  11. bytesRelayed is tracked in the session
 *  12. Client A sends RELAY_RELEASE → session destroyed (client B gets release)
 *  13. Both close → devices cleaned up
 *  14. GET /health returns 200 with JSON status body
 *
 * @module integration.test
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

import { Gateway }     from '../src/gateway.js';
import { Presence }    from '../src/presence.js';
import { Signaling }   from '../src/signaling.js';
import { DataRelay }   from '../src/relay.js';
import { RateLimiter } from '../src/ratelimit.js';
import { MSG }         from '../src/protocol.js';

// ---------------------------------------------------------------------------
// Wire @noble/ed25519 v2 synchronous SHA-512 for sign() calls
// ---------------------------------------------------------------------------
ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Poll interval in milliseconds for waitFor / waitForBinary helpers. */
const POLL_INTERVAL_MS = 10;

/** Maximum total wait time in milliseconds before a waitFor times out. */
const WAIT_TIMEOUT_MS = 5_000;

/** Number of binary chunks to send in the relay test. */
const BINARY_CHUNK_COUNT = 3;

/** Size of each binary chunk in bytes. */
const BINARY_CHUNK_SIZE = 64;

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

/**
 * Generates an Ed25519 keypair and derives the device ID.
 *
 * deviceId = base64url( SHA-256(pubKey)[0:16] )
 *
 * @returns {{ privKey: Uint8Array, pubKey: Uint8Array, deviceId: string }}
 */
function generateIdentity() {
  const privKey  = ed.utils.randomPrivateKey();
  const pubKey   = ed.getPublicKey(privKey);
  const hash     = sha256(pubKey);
  const deviceId = Buffer.from(hash.slice(0, 16)).toString('base64url');
  return { privKey, pubKey, deviceId };
}

/**
 * Signs the challenge payload for the auth handshake.
 *
 * Payload = challengeBytes || UTF-8(String(timestamp))
 *
 * @param {Uint8Array} privKey        - Ed25519 private key
 * @param {string}     challengeHex  - 64-char hex challenge from the server
 * @param {number}     timestamp     - Unix milliseconds (Date.now())
 * @returns {string} Base64-encoded Ed25519 signature
 */
function signChallenge(privKey, challengeHex, timestamp) {
  const challengeBytes = Buffer.from(challengeHex, 'hex');
  const timestampBytes = Buffer.from(String(timestamp));
  const payload        = Buffer.concat([challengeBytes, timestampBytes]);
  // ed.sign is synchronous when sha512Sync is configured (no signSync method)
  const sig = ed.sign(payload, privKey);
  return Buffer.from(sig).toString('base64');
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

/**
 * Connects a WebSocket client to the test server and returns a handle that
 * accumulates incoming JSON messages and raw binary frames separately.
 *
 * @param {number} port - Local port the test server is bound to
 * @returns {Promise<{ ws: WebSocket, messages: object[], binaryMessages: Buffer[] }>}
 */
function connectClient(port) {
  return new Promise((resolve, reject) => {
    const ws             = new WebSocket(`ws://127.0.0.1:${port}`);
    /** @type {object[]} Accumulated JSON messages in arrival order. */
    const messages       = [];
    /** @type {Buffer[]} Accumulated raw binary frames in arrival order. */
    const binaryMessages = [];

    ws.on('open', () => resolve({ ws, messages, binaryMessages }));
    ws.on('error', reject);

    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        binaryMessages.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
      } else {
        try {
          messages.push(JSON.parse(data.toString()));
        } catch {
          // Ignore un-parseable text frames (should not occur in normal operation)
        }
      }
    });
  });
}

/**
 * Polls `messages` until `predicate(msg)` returns true for some element,
 * then returns that element.  Rejects after WAIT_TIMEOUT_MS.
 *
 * @param {object[]} messages              - Mutable array of received messages
 * @param {(msg: object) => boolean} predicate
 * @returns {Promise<object>}
 */
function waitFor(messages, predicate) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + WAIT_TIMEOUT_MS;

    const check = () => {
      const found = messages.find(predicate);
      if (found) {
        resolve(found);
        return;
      }
      if (Date.now() >= deadline) {
        reject(new Error(
          `waitFor timed out after ${WAIT_TIMEOUT_MS} ms.\n` +
          `Messages seen: ${JSON.stringify(messages, null, 2)}`
        ));
        return;
      }
      setTimeout(check, POLL_INTERVAL_MS);
    };

    check();
  });
}

/**
 * Polls `binaryMessages` until at least `count` frames have arrived,
 * then resolves with the full array.  Rejects after WAIT_TIMEOUT_MS.
 *
 * @param {Buffer[]} binaryMessages - Mutable array of received binary frames
 * @param {number}   count          - Minimum frame count to wait for
 * @returns {Promise<Buffer[]>}
 */
function waitForBinary(binaryMessages, count) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + WAIT_TIMEOUT_MS;

    const check = () => {
      if (binaryMessages.length >= count) {
        resolve(binaryMessages);
        return;
      }
      if (Date.now() >= deadline) {
        reject(new Error(
          `waitForBinary timed out after ${WAIT_TIMEOUT_MS} ms. ` +
          `Expected ${count} frames, got ${binaryMessages.length}.`
        ));
        return;
      }
      setTimeout(check, POLL_INTERVAL_MS);
    };

    check();
  });
}

/**
 * Executes the full Ed25519 authentication handshake for a connected client.
 *
 * Steps:
 *   1. Wait for the CHALLENGE message
 *   2. Sign the challenge with the device's private key
 *   3. Send AUTH message
 *   4. Wait for AUTH_OK
 *
 * @param {{ ws: WebSocket, messages: object[] }} client
 * @param {{ privKey: Uint8Array, pubKey: Uint8Array, deviceId: string }} identity
 * @returns {Promise<void>}
 */
async function authenticate(client, identity) {
  const { ws, messages } = client;
  const { privKey, pubKey, deviceId } = identity;

  // Step 1: Wait for challenge
  const challengeMsg = await waitFor(messages, (m) => m.type === MSG.CHALLENGE);

  // Step 2: Sign challenge
  const timestamp = Date.now();
  const signature = signChallenge(privKey, challengeMsg.challenge, timestamp);

  // Step 3: Send AUTH
  ws.send(JSON.stringify({
    type:      MSG.AUTH,
    deviceId,
    publicKey: Buffer.from(pubKey).toString('base64'),
    signature,
    timestamp,
  }));

  // Step 4: Wait for AUTH_OK
  await waitFor(messages, (m) => m.type === MSG.AUTH_OK);
}

// ---------------------------------------------------------------------------
// Test server factory (mirrors server.js wiring exactly)
// ---------------------------------------------------------------------------

/**
 * Creates and starts a test server that mirrors the server.js module wiring.
 *
 * Returned handle exposes all module instances so tests can inspect internal
 * state (e.g. dataRelay.sessions.size).
 *
 * @returns {Promise<{
 *   httpServer: http.Server,
 *   wss: WebSocketServer,
 *   gateway: Gateway,
 *   presence: Presence,
 *   signaling: Signaling,
 *   dataRelay: DataRelay,
 *   rateLimiter: RateLimiter,
 *   port: number,
 *   close: () => Promise<void>,
 * }>}
 */
function createTestServer() {
  return new Promise((resolve, reject) => {
    // --- Rate limiter (spec values identical to server.js) ---
    const rateLimiter = new RateLimiter({
      maxConnectionsPerIp:   5,
      maxMessagesPerSec:     50,
      maxConcurrentDevices:  50,
      monthlyBandwidthBytes: 160 * 1024 ** 3,
      bandwidthWarningRatio: 0.8,
    });

    // --- HTTP server ---
    const httpServer = http.createServer((req, res) => {
      if (req.url === '/health') {
        const quota = rateLimiter.quotaInfo();
        const body = {
          status:      'ok',
          uptime:      process.uptime(),
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

    // --- WebSocket server ---
    const wss = new WebSocketServer({
      server:     httpServer,
      maxPayload: 256 * 1024,
      verifyClient(info, cb) {
        const ip =
          (info.req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() ||
          info.req.socket.remoteAddress ||
          'unknown';
        if (!rateLimiter.allowConnection(ip)) {
          cb(false, 429, 'Too Many Connections');
          return;
        }
        info.req._clientIp = ip;
        cb(true);
      },
    });

    // --- Application modules ---
    const gateway   = new Gateway({ authTimeoutMs: 30_000 });
    const presence  = new Presence({ gateway });
    const signaling = new Signaling(gateway, presence);
    const dataRelay = new DataRelay({ gateway });

    // IP / connId tracking maps (mirrors server.js)
    const wsToIp     = new Map();
    const wsToConnId = new Map();
    let _nextConnId  = 0;

    // --- WS connection handler ---
    wss.on('connection', (ws, req) => {
      const ip     = req._clientIp ?? req.socket.remoteAddress ?? 'unknown';
      const connId = String(_nextConnId++);

      rateLimiter.trackConnection(ip);
      wsToIp.set(ws, ip);
      wsToConnId.set(ws, connId);

      gateway._onConnection(ws);

      ws.on('close', () => {
        rateLimiter.releaseConnection(ip);
        rateLimiter.releaseMessageCounter(connId);
        wsToIp.delete(ws);
        wsToConnId.delete(ws);
      });
    });

    // --- Gateway events ---
    gateway.on('authenticated', (deviceId, ws) => {
      if (!rateLimiter.allowDevice()) {
        try {
          if (ws.readyState === ws.OPEN) {
            ws.send(JSON.stringify({
              type:    MSG.ERROR,
              message: 'Server at capacity: maximum concurrent devices reached',
            }));
          }
        } catch { /* ignore */ }
        ws.close();
        return;
      }
      rateLimiter.trackDevice(deviceId);
    });

    gateway.on('disconnect', (deviceId) => {
      presence.unregister(deviceId);
      rateLimiter.releaseDevice(deviceId);
      dataRelay.handleDisconnect(deviceId);
    });

    // --- Message dispatcher ---
    gateway.onMessage((deviceId, msg, ws) => {
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

      presence.heartbeat(deviceId);

      switch (msg.type) {
        case MSG.REGISTER_RENDEZVOUS:
          presence.register(deviceId, msg.rendezvousIds);
          break;

        case MSG.SDP_OFFER:
        case MSG.SDP_ANSWER:
        case MSG.ICE_CANDIDATE:
          signaling.handleMessage(deviceId, msg, ws);
          break;

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

        case MSG.RELAY_RELEASE:
          dataRelay.handleMessage(deviceId, msg, ws);
          break;

        case MSG.PING:
          break; // handled inside gateway

        default:
          break;
      }
    });

    // --- Binary relay (second wss 'connection' handler, like server.js) ---
    wss.on('connection', (ws) => {
      ws.on('message', (data, isBinary) => {
        if (!isBinary) return;

        const deviceId = gateway.wsToDevice.get(ws);
        if (!deviceId) return;

        const byteLength = Buffer.isBuffer(data) ? data.length : data.byteLength;
        rateLimiter.addBandwidth(byteLength);

        if (rateLimiter.isRelayDisabled()) {
          gateway.sendTo(ws, {
            type:    MSG.ERROR,
            message: 'Relay unavailable: monthly bandwidth quota nearly exhausted',
          });
          return;
        }

        dataRelay.relayBinary(deviceId, data, ws);
      });
    });

    // --- Presence silence checker ---
    presence.startSilenceChecker();

    // --- Listen on OS-assigned port ---
    httpServer.listen(0, '127.0.0.1', () => {
      const { port } = httpServer.address();

      /**
       * Gracefully closes the server and all active WS connections.
       * @returns {Promise<void>}
       */
      const close = () => new Promise((res) => {
        // Terminate all open WS connections first
        for (const client of wss.clients) {
          client.terminate();
        }
        presence.destroy();
        wss.close(() => httpServer.close(res));
      });

      resolve({
        httpServer, wss, gateway, presence, signaling, dataRelay, rateLimiter,
        port, close,
      });
    });

    httpServer.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('Integration: full two-client transfer flow', () => {
  /** @type {Awaited<ReturnType<typeof createTestServer>>} */
  let server;
  /** @type {{ ws: WebSocket, messages: object[], binaryMessages: Buffer[] }} */
  let clientA;
  /** @type {{ ws: WebSocket, messages: object[], binaryMessages: Buffer[] }} */
  let clientB;
  /** @type {{ privKey: Uint8Array, pubKey: Uint8Array, deviceId: string }} */
  let identityA;
  /** @type {{ privKey: Uint8Array, pubKey: Uint8Array, deviceId: string }} */
  let identityB;

  /** Shared rendezvous ID used by both clients. */
  const RENDEZVOUS_ID = 'test-rendezvous-abc123';

  /** Transfer ID used for the relay session. */
  const TRANSFER_ID = 'xfer-001';

  // -------------------------------------------------------------------------
  // Setup: start server and connect both clients before all tests run
  // -------------------------------------------------------------------------

  before(async () => {
    server = await createTestServer();
    identityA = generateIdentity();
    identityB = generateIdentity();

    // Connect both clients concurrently
    [clientA, clientB] = await Promise.all([
      connectClient(server.port),
      connectClient(server.port),
    ]);
  });

  // -------------------------------------------------------------------------
  // Teardown: close clients and server after all tests finish
  // -------------------------------------------------------------------------

  after(async () => {
    // Close WebSocket connections if still open
    if (clientA?.ws.readyState === WebSocket.OPEN) clientA.ws.close();
    if (clientB?.ws.readyState === WebSocket.OPEN) clientB.ws.close();
    await server.close();
  });

  // -------------------------------------------------------------------------
  // Test 1: /health returns 200 with valid JSON body
  // -------------------------------------------------------------------------

  it('GET /health returns 200 with status:ok and expected fields', async () => {
    const body = await new Promise((resolve, reject) => {
      const req = http.get(
        `http://127.0.0.1:${server.port}/health`,
        (res) => {
          assert.equal(res.statusCode, 200, '/health must return HTTP 200');
          assert.match(
            res.headers['content-type'] ?? '',
            /application\/json/,
            'content-type must be application/json'
          );

          let raw = '';
          res.on('data', (chunk) => { raw += chunk; });
          res.on('end', () => {
            try { resolve(JSON.parse(raw)); }
            catch (e) { reject(e); }
          });
        }
      );
      req.on('error', reject);
    });

    assert.equal(body.status, 'ok',            'status field must be "ok"');
    assert.equal(typeof body.uptime, 'number', 'uptime must be a number');
    assert.ok('connections' in body,           'body must include connections');
    assert.ok('devices'     in body,           'body must include devices');
    assert.ok('sessions'    in body,           'body must include sessions');
    assert.ok(body.bandwidth,                  'body must include bandwidth object');
    assert.equal(typeof body.bandwidth.usedBytes,  'number', 'bandwidth.usedBytes must be number');
    assert.equal(typeof body.bandwidth.limitBytes, 'number', 'bandwidth.limitBytes must be number');
    assert.equal(typeof body.bandwidth.usedRatio,  'number', 'bandwidth.usedRatio must be number');
  });

  // -------------------------------------------------------------------------
  // Test 2: Both clients receive a CHALLENGE on connection
  // -------------------------------------------------------------------------

  it('both clients receive a challenge on connect', async () => {
    const [challA, challB] = await Promise.all([
      waitFor(clientA.messages, (m) => m.type === MSG.CHALLENGE),
      waitFor(clientB.messages, (m) => m.type === MSG.CHALLENGE),
    ]);

    // Challenge is 32 bytes → 64 hex characters
    assert.match(challA.challenge, /^[0-9a-f]{64}$/, 'challenge A must be 64 hex chars');
    assert.match(challB.challenge, /^[0-9a-f]{64}$/, 'challenge B must be 64 hex chars');
    assert.notEqual(challA.challenge, challB.challenge, 'challenges must be unique per connection');
  });

  // -------------------------------------------------------------------------
  // Test 3: Both clients authenticate successfully
  // -------------------------------------------------------------------------

  it('both clients authenticate with Ed25519 and receive AUTH_OK', async () => {
    await Promise.all([
      authenticate(clientA, identityA),
      authenticate(clientB, identityB),
    ]);

    // Verify gateway has registered both devices
    assert.ok(
      server.gateway.devices.has(identityA.deviceId),
      'gateway must register device A after auth'
    );
    assert.ok(
      server.gateway.devices.has(identityB.deviceId),
      'gateway must register device B after auth'
    );
  });

  // -------------------------------------------------------------------------
  // Test 4 + 5: Register rendezvous and receive PEER_ONLINE for each other
  // -------------------------------------------------------------------------

  it('both clients register shared rendezvous and receive PEER_ONLINE for each other', async () => {
    // Send register-rendezvous from both clients
    clientA.ws.send(JSON.stringify({
      type:          MSG.REGISTER_RENDEZVOUS,
      rendezvousIds: [RENDEZVOUS_ID],
    }));

    // Wait for client B to receive PEER_ONLINE for device A (A registered first)
    // then register B
    await waitFor(clientA.messages, (m) => m.type === MSG.AUTH_OK); // already done; belt-and-suspenders

    clientB.ws.send(JSON.stringify({
      type:          MSG.REGISTER_RENDEZVOUS,
      rendezvousIds: [RENDEZVOUS_ID],
    }));

    // After B registers, both should receive PEER_ONLINE for the other
    const [peerOnlineForA, peerOnlineForB] = await Promise.all([
      waitFor(clientA.messages, (m) => m.type === MSG.PEER_ONLINE && m.deviceId === identityB.deviceId),
      waitFor(clientB.messages, (m) => m.type === MSG.PEER_ONLINE && m.deviceId === identityA.deviceId),
    ]);

    assert.equal(
      peerOnlineForA.deviceId,
      identityB.deviceId,
      'client A must see PEER_ONLINE for device B'
    );
    assert.equal(
      peerOnlineForB.deviceId,
      identityA.deviceId,
      'client B must see PEER_ONLINE for device A'
    );
  });

  // -------------------------------------------------------------------------
  // Test 6: SDP_OFFER from A → B with fromDeviceId
  // -------------------------------------------------------------------------

  it('client A sends SDP_OFFER and client B receives it with fromDeviceId', async () => {
    clientA.ws.send(JSON.stringify({
      type:           MSG.SDP_OFFER,
      targetDeviceId: identityB.deviceId,
      rendezvousId:   RENDEZVOUS_ID,
      sdp:            'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n',
    }));

    const offer = await waitFor(
      clientB.messages,
      (m) => m.type === MSG.SDP_OFFER
    );

    assert.equal(offer.fromDeviceId, identityA.deviceId, 'offer must carry fromDeviceId of A');
    assert.equal(offer.sdp, 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n', 'SDP payload must be preserved');
    // targetDeviceId is stripped by the signaling module
    assert.equal(offer.targetDeviceId, undefined, 'targetDeviceId must be stripped from relayed offer');
  });

  // -------------------------------------------------------------------------
  // Test 7: SDP_ANSWER from B → A with fromDeviceId
  // -------------------------------------------------------------------------

  it('client B sends SDP_ANSWER and client A receives it with fromDeviceId', async () => {
    clientB.ws.send(JSON.stringify({
      type:           MSG.SDP_ANSWER,
      targetDeviceId: identityA.deviceId,
      rendezvousId:   RENDEZVOUS_ID,
      sdp:            'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n',
    }));

    const answer = await waitFor(
      clientA.messages,
      (m) => m.type === MSG.SDP_ANSWER
    );

    assert.equal(answer.fromDeviceId, identityB.deviceId, 'answer must carry fromDeviceId of B');
    assert.equal(answer.sdp, 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n', 'SDP payload must be preserved');
    assert.equal(answer.targetDeviceId, undefined, 'targetDeviceId must be stripped from relayed answer');
  });

  // -------------------------------------------------------------------------
  // Test 8: ICE_CANDIDATE from A → B
  // -------------------------------------------------------------------------

  it('client A sends ICE_CANDIDATE and client B receives it with fromDeviceId', async () => {
    const icePayload = { candidate: 'candidate:1 1 UDP 2122252543 192.168.1.1 50000 typ host', sdpMid: '0', sdpMLineIndex: 0 };

    clientA.ws.send(JSON.stringify({
      type:           MSG.ICE_CANDIDATE,
      targetDeviceId: identityB.deviceId,
      rendezvousId:   RENDEZVOUS_ID,
      candidate:      icePayload,
    }));

    const ice = await waitFor(
      clientB.messages,
      (m) => m.type === MSG.ICE_CANDIDATE
    );

    assert.equal(ice.fromDeviceId, identityA.deviceId, 'ICE message must carry fromDeviceId of A');
    assert.deepEqual(ice.candidate, icePayload, 'ICE candidate payload must be preserved');
    assert.equal(ice.targetDeviceId, undefined, 'targetDeviceId must be stripped from relayed ICE');
  });

  // -------------------------------------------------------------------------
  // Test 9: Both clients send RELAY_BIND → session created
  // -------------------------------------------------------------------------

  it('both clients send RELAY_BIND and a session is created', async () => {
    // Sender side (A) binds first
    clientA.ws.send(JSON.stringify({
      type:           MSG.RELAY_BIND,
      transferId:     TRANSFER_ID,
      targetDeviceId: identityB.deviceId,
      rendezvousId:   RENDEZVOUS_ID,
    }));

    // Receiver side (B) binds second — completes the session pair
    clientB.ws.send(JSON.stringify({
      type:           MSG.RELAY_BIND,
      transferId:     TRANSFER_ID,
      targetDeviceId: identityA.deviceId,
      rendezvousId:   RENDEZVOUS_ID,
    }));

    // Poll until the session is fully established (both WebSockets set)
    await new Promise((resolve, reject) => {
      const deadline = Date.now() + WAIT_TIMEOUT_MS;
      const check = () => {
        const session = server.dataRelay.sessions.get(TRANSFER_ID);
        if (session && session.senderWs && session.receiverWs) {
          resolve();
          return;
        }
        if (Date.now() >= deadline) {
          reject(new Error('Timed out waiting for relay session to be fully bound'));
          return;
        }
        setTimeout(check, POLL_INTERVAL_MS);
      };
      check();
    });

    assert.equal(server.dataRelay.sessions.size, 1, 'exactly one relay session must exist');
    const session = server.dataRelay.sessions.get(TRANSFER_ID);
    assert.ok(session, 'session must be stored under the transferId');
    assert.ok(session.senderWs,   'session must have senderWs set');
    assert.ok(session.receiverWs, 'session must have receiverWs set');
  });

  // -------------------------------------------------------------------------
  // Test 10 + 11: Client A sends binary chunks → B receives them, bytesRelayed tracked
  // -------------------------------------------------------------------------

  it('client A sends binary chunks; client B receives them and bytesRelayed is tracked', async () => {
    const chunks = Array.from({ length: BINARY_CHUNK_COUNT }, (_, i) =>
      Buffer.alloc(BINARY_CHUNK_SIZE, i + 1) // fill each chunk with a distinct byte value
    );

    // Send all chunks as binary frames
    for (const chunk of chunks) {
      clientA.ws.send(chunk); // ws sends Buffer as binary (isBinary = true)
    }

    // Wait until client B has received all chunks
    await waitForBinary(clientB.binaryMessages, BINARY_CHUNK_COUNT);

    assert.equal(
      clientB.binaryMessages.length,
      BINARY_CHUNK_COUNT,
      `client B must have received exactly ${BINARY_CHUNK_COUNT} binary chunks`
    );

    // Verify contents are forwarded unmodified
    for (let i = 0; i < BINARY_CHUNK_COUNT; i++) {
      assert.deepEqual(
        clientB.binaryMessages[i],
        chunks[i],
        `chunk ${i} payload must be forwarded unmodified`
      );
    }

    // Verify bytesRelayed is tracked inside the session
    const session = server.dataRelay.sessions.get(TRANSFER_ID);
    const expectedBytes = BINARY_CHUNK_COUNT * BINARY_CHUNK_SIZE;
    assert.equal(
      session.bytesRelayed,
      expectedBytes,
      `session.bytesRelayed must equal ${expectedBytes} after transferring ${BINARY_CHUNK_COUNT} chunks`
    );
  });

  // -------------------------------------------------------------------------
  // Test 12: RELAY_RELEASE destroys session; peer receives notification
  // -------------------------------------------------------------------------

  it('client A sends RELAY_RELEASE; session is destroyed and client B is notified', async () => {
    clientA.ws.send(JSON.stringify({
      type:       MSG.RELAY_RELEASE,
      transferId: TRANSFER_ID,
    }));

    // Client B should receive a RELAY_RELEASE notification from the server
    await waitFor(
      clientB.messages,
      (m) => m.type === MSG.RELAY_RELEASE && m.transferId === TRANSFER_ID
    );

    assert.equal(
      server.dataRelay.sessions.size,
      0,
      'relay session must be removed after RELAY_RELEASE'
    );
  });

  // -------------------------------------------------------------------------
  // Test 13: Both clients close → devices cleaned up in gateway
  // -------------------------------------------------------------------------

  it('both clients close; gateway cleans up registered devices', async () => {
    await new Promise((resolve) => {
      let closed = 0;
      const onClose = () => { if (++closed === 2) resolve(); };

      clientA.ws.once('close', onClose);
      clientB.ws.once('close', onClose);

      clientA.ws.close();
      clientB.ws.close();
    });

    // Allow the gateway's _onClose handler to run (next event loop tick)
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.ok(
      !server.gateway.devices.has(identityA.deviceId),
      'gateway must remove device A after WS close'
    );
    assert.ok(
      !server.gateway.devices.has(identityB.deviceId),
      'gateway must remove device B after WS close'
    );
  });
});
