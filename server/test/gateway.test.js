/**
 * gateway.test.js — TDD tests for the WebSocket Gateway with Ed25519 auth.
 *
 * Test order follows the happy-path-first convention, then failure modes:
 *   1. Challenge is sent on connection (64 hex chars = 32 bytes)
 *   2. Valid auth succeeds → AUTH_OK
 *   3. Wrong signature → AUTH_FAIL with "signature" in reason
 *   4. Mismatched device ID → AUTH_FAIL with "device" in reason
 *   5. Stale timestamp (60 s old) → AUTH_FAIL with "timestamp" in reason
 *   6. Pre-auth non-auth message → ERROR with "not authenticated"
 *   7. Authenticated device appears in gateway.devices, removed on close
 *   8. Auth timeout — connection closed if no auth within authTimeoutMs
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

import { Gateway } from '../src/gateway.js';

// ---------------------------------------------------------------------------
// Wire noble-ed25519 v2 synchronous SHA-512 (required for signSync / etc.)
// ---------------------------------------------------------------------------
ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

/**
 * Generates an Ed25519 keypair.
 * @returns {{ privKey: Uint8Array, pubKey: Uint8Array }}
 */
function generateKeypair() {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = ed.getPublicKey(privKey);
  return { privKey, pubKey };
}

/**
 * Derives the device ID from an Ed25519 public key.
 * deviceId = base64url( SHA256(pubKey)[0:16] )
 *
 * @param {Uint8Array} pubKey
 * @returns {string}
 */
function deriveDeviceId(pubKey) {
  const hash = sha256(pubKey);
  return Buffer.from(hash.slice(0, 16)).toString('base64url');
}

/**
 * Signs the auth payload: challenge_bytes || timestamp_string_bytes.
 * The timestamp is encoded as its decimal UTF-8 string representation to
 * avoid any endianness ambiguity.
 *
 * @param {string} challengeHex - 64-char hex string from server
 * @param {number} timestamp    - Unix milliseconds
 * @param {Uint8Array} privKey
 * @returns {string} base64-encoded signature
 */
function signAuth(challengeHex, timestamp, privKey) {
  const challengeBytes = Buffer.from(challengeHex, 'hex');
  const timestampBytes = Buffer.from(String(timestamp));
  const payload = Buffer.concat([challengeBytes, timestampBytes]);
  const sig = ed.sign(payload, privKey);
  return Buffer.from(sig).toString('base64');
}

// ---------------------------------------------------------------------------
// Test server helpers
// ---------------------------------------------------------------------------

/**
 * Creates an HTTP server bound to a random OS-assigned port, attaches a
 * WebSocketServer and a Gateway instance, then starts listening.
 *
 * @param {object} [gatewayOpts] - Options forwarded to Gateway constructor
 * @returns {Promise<{ server: http.Server, wss: WebSocketServer, gateway: Gateway, port: number }>}
 */
function createTestServer(gatewayOpts = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    const wss = new WebSocketServer({ server });
    const gateway = new Gateway({ wss, ...gatewayOpts });

    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, wss, gateway, port });
    });
    server.once('error', reject);
  });
}

/**
 * Closes the HTTP server and all open WS connections, returning a promise.
 * @param {http.Server} server
 * @returns {Promise<void>}
 */
function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

/**
 * Opens a WebSocket to the test server and collects up to `count` JSON
 * messages, then closes the socket.
 *
 * @param {number} port
 * @param {number} count     - How many messages to wait for
 * @param {number} [timeout] - Max wait in ms (default 2000)
 * @returns {Promise<object[]>} Parsed JSON objects
 */
function collectMessages(port, count, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const messages = [];
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    const timer = setTimeout(() => {
      ws.close();
      resolve(messages); // return whatever arrived
    }, timeout);

    ws.on('message', (data) => {
      try {
        messages.push(JSON.parse(data.toString()));
      } catch {
        /* ignore non-JSON frames */
      }
      if (messages.length >= count) {
        clearTimeout(timer);
        ws.close();
        resolve(messages);
      }
    });

    ws.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Opens a WS, waits for the initial challenge, sends an auth message, and
 * returns the WS instance plus the challenge-message object.
 *
 * @param {number} port
 * @returns {Promise<{ ws: WebSocket, challenge: string }>}
 */
function connectAndGetChallenge(port) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    ws.once('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return reject(new Error('Non-JSON first frame')); }
      if (msg.type !== 'challenge') return reject(new Error(`Expected challenge, got ${msg.type}`));
      resolve({ ws, challenge: msg.challenge });
    });
    ws.on('error', reject);
  });
}

/**
 * Sends a message on a WS and returns the next JSON message received.
 * @param {WebSocket} ws
 * @param {object}   payload
 * @param {number}   [timeout]
 * @returns {Promise<object>}
 */
function sendAndReceive(ws, payload, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout waiting for response')), timeout);
    ws.once('message', (data) => {
      clearTimeout(timer);
      try { resolve(JSON.parse(data.toString())); } catch { reject(new Error('Non-JSON response')); }
    });
    ws.send(JSON.stringify(payload));
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Gateway', () => {
  /** @type {{ server: http.Server, wss: WebSocketServer, gateway: Gateway, port: number }} */
  let ctx;

  before(async () => {
    ctx = await createTestServer();
  });

  after(async () => {
    await closeServer(ctx.server);
  });

  // -------------------------------------------------------------------------
  // Test 1 — Challenge on connection
  // -------------------------------------------------------------------------
  it('sends a 32-byte challenge (64 hex chars) on connection', async () => {
    const messages = await collectMessages(ctx.port, 1);
    assert.equal(messages.length, 1, 'expected exactly one message');
    const msg = messages[0];
    assert.equal(msg.type, 'challenge', 'first message type must be "challenge"');
    assert.match(msg.challenge, /^[0-9a-f]{64}$/i, 'challenge must be 64 lowercase hex chars');
  });

  // -------------------------------------------------------------------------
  // Test 2 — Valid auth → AUTH_OK
  // -------------------------------------------------------------------------
  it('accepts a valid auth message and responds with auth-ok', async () => {
    const { privKey, pubKey } = generateKeypair();
    const deviceId = deriveDeviceId(pubKey);
    const { ws, challenge } = await connectAndGetChallenge(ctx.port);

    const timestamp = Date.now();
    const signature = signAuth(challenge, timestamp, privKey);
    const publicKey = Buffer.from(pubKey).toString('base64');

    const reply = await sendAndReceive(ws, {
      type: 'auth',
      deviceId,
      publicKey,
      signature,
      timestamp,
    });

    ws.close();
    assert.equal(reply.type, 'auth-ok', `expected auth-ok, got: ${JSON.stringify(reply)}`);
  });

  // -------------------------------------------------------------------------
  // Test 3 — Wrong signature → AUTH_FAIL with "signature" in reason
  // -------------------------------------------------------------------------
  it('rejects an invalid signature with AUTH_FAIL containing "signature"', async () => {
    const { privKey, pubKey } = generateKeypair();
    const deviceId = deriveDeviceId(pubKey);
    const { ws, challenge } = await connectAndGetChallenge(ctx.port);

    const timestamp = Date.now();
    // Corrupt: sign with a different challenge value
    const badSignature = signAuth('ff'.repeat(32), timestamp, privKey);
    const publicKey = Buffer.from(pubKey).toString('base64');

    const reply = await sendAndReceive(ws, {
      type: 'auth',
      deviceId,
      publicKey,
      signature: badSignature,
      timestamp,
    });

    ws.close();
    assert.equal(reply.type, 'auth-fail', `expected auth-fail, got: ${JSON.stringify(reply)}`);
    assert.match(reply.reason, /signature/i, 'reason must mention "signature"');
  });

  // -------------------------------------------------------------------------
  // Test 4 — Mismatched device ID → AUTH_FAIL with "device" in reason
  // -------------------------------------------------------------------------
  it('rejects a mismatched deviceId with AUTH_FAIL containing "device"', async () => {
    const { privKey, pubKey } = generateKeypair();
    const { ws, challenge } = await connectAndGetChallenge(ctx.port);

    const timestamp = Date.now();
    const signature = signAuth(challenge, timestamp, privKey);
    const publicKey = Buffer.from(pubKey).toString('base64');

    const reply = await sendAndReceive(ws, {
      type: 'auth',
      deviceId: 'AAAAAAAAAAAAAAAAAAAAAA', // wrong device ID
      publicKey,
      signature,
      timestamp,
    });

    ws.close();
    assert.equal(reply.type, 'auth-fail', `expected auth-fail, got: ${JSON.stringify(reply)}`);
    assert.match(reply.reason, /device/i, 'reason must mention "device"');
  });

  // -------------------------------------------------------------------------
  // Test 5 — Stale timestamp (60 s old) → AUTH_FAIL with "timestamp" in reason
  // -------------------------------------------------------------------------
  it('rejects a stale timestamp with AUTH_FAIL containing "timestamp"', async () => {
    const { privKey, pubKey } = generateKeypair();
    const deviceId = deriveDeviceId(pubKey);
    const { ws, challenge } = await connectAndGetChallenge(ctx.port);

    const timestamp = Date.now() - 60_000; // 60 seconds old — outside 30 s window
    const signature = signAuth(challenge, timestamp, privKey);
    const publicKey = Buffer.from(pubKey).toString('base64');

    const reply = await sendAndReceive(ws, {
      type: 'auth',
      deviceId,
      publicKey,
      signature,
      timestamp,
    });

    ws.close();
    assert.equal(reply.type, 'auth-fail', `expected auth-fail, got: ${JSON.stringify(reply)}`);
    assert.match(reply.reason, /timestamp/i, 'reason must mention "timestamp"');
  });

  // -------------------------------------------------------------------------
  // Test 6 — Pre-auth non-auth message → ERROR "not authenticated"
  // -------------------------------------------------------------------------
  it('returns ERROR "not authenticated" for pre-auth non-auth messages', async () => {
    const { ws } = await connectAndGetChallenge(ctx.port);

    const reply = await sendAndReceive(ws, { type: 'ping' });

    ws.close();
    assert.equal(reply.type, 'error', `expected error, got: ${JSON.stringify(reply)}`);
    assert.match(reply.message, /not authenticated/i, 'error message must say "not authenticated"');
  });

  // -------------------------------------------------------------------------
  // Test 7 — Device tracked in gateway.devices, removed on close
  // -------------------------------------------------------------------------
  it('registers authenticated device in gateway.devices and removes it on close', async () => {
    const { privKey, pubKey } = generateKeypair();
    const deviceId = deriveDeviceId(pubKey);
    const { ws, challenge } = await connectAndGetChallenge(ctx.port);

    const timestamp = Date.now();
    const signature = signAuth(challenge, timestamp, privKey);
    const publicKey = Buffer.from(pubKey).toString('base64');

    const reply = await sendAndReceive(ws, {
      type: 'auth',
      deviceId,
      publicKey,
      signature,
      timestamp,
    });
    assert.equal(reply.type, 'auth-ok');

    // Device must appear in the map immediately after auth-ok
    assert.ok(ctx.gateway.devices.has(deviceId), 'devices map should contain the authenticated deviceId');

    // After closing, wait for the gateway's 'disconnect' event which fires
    // only after the server-side close handler has cleaned up the maps.
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timeout waiting for disconnect event')), 2000);
      ctx.gateway.once('disconnect', (disconnectedId) => {
        if (disconnectedId === deviceId) {
          clearTimeout(timer);
          resolve();
        }
      });
      ws.close();
    });

    assert.ok(!ctx.gateway.devices.has(deviceId), 'devices map should not contain deviceId after close');
  });

  // -------------------------------------------------------------------------
  // Test 8 — Auth timeout closes the connection
  // -------------------------------------------------------------------------
  it('closes unauthenticated connections after authTimeoutMs', async () => {
    // Create a separate server with a very short timeout (150 ms) for this test
    const fastCtx = await createTestServer({ authTimeoutMs: 150 });

    try {
      const { ws } = await connectAndGetChallenge(fastCtx.port);

      const closed = await new Promise((resolve) => {
        ws.once('close', () => resolve(true));
        // If still open after 500 ms, something is wrong
        setTimeout(() => resolve(false), 500);
      });

      assert.ok(closed, 'connection should have been closed by auth timeout');
    } finally {
      await closeServer(fastCtx.server);
    }
  });
});
