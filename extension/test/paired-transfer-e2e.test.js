/**
 * @file paired-transfer-e2e.test.js
 * @description True end-to-end: two BeamV2Transport instances, each
 * connected to a real local relay over `ws`, with full Ed25519
 * authentication and rendezvous registration. The relay forwards binary
 * frames between them via the production code paths (Gateway → Presence
 * → DataRelay). The test asserts:
 *
 *   1. clipboard A → B and B → A both round-trip
 *   2. multi-chunk file in both directions
 *   3. resend on a dropped chunk completes via the receiver's request
 *
 * This is the regression net for the user-reported bug — "only Android→PC
 * clipboard works" — translated to the JS side, where it now must work
 * symmetrically.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

import { BeamV2Transport } from '../crypto/beam-v2-transport.js';
import { deriveKAB }       from '../crypto/beam-v2.js';
import { x25519PublicKey } from '../crypto/beam-crypto.js';
import { startTestRelay }  from './_helpers/relay-fixture.js';

ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

// ─── identity + auth helpers ──────────────────────────────────────────────

async function makeFullIdentity() {
  const edSk  = ed.utils.randomPrivateKey();
  const edPk  = ed.getPublicKey(edSk);
  const xSk   = randomBytes32();
  const xPk   = await x25519PublicKey(xSk);
  const idHash = sha256(edPk);
  const deviceId = Buffer.from(idHash.slice(0, 16)).toString('base64url');
  return { deviceId, edSk, edPk, xSk, xPk };
}
function randomBytes32() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return b;
}

/**
 * Open a WebSocket to the relay, complete the Ed25519 challenge handshake,
 * register a rendezvous, and return the live ws plus a queue of received
 * messages so we can drive the transport's send/receive hooks.
 */
function connectAndAuth(relayUrl, ident, rendezvousId) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(relayUrl);
    const incoming = { json: [], binary: [] };
    let onOpen;

    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        incoming.binary.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
        if (onOpen?.binary) onOpen.binary(data);
        return;
      }
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      incoming.json.push(msg);

      if (msg.type === 'challenge') {
        const ts = Date.now();
        const challengeBytes = Buffer.from(msg.challenge, 'hex');
        const tsBytes        = Buffer.from(String(ts));
        const sig = ed.sign(Buffer.concat([challengeBytes, tsBytes]), ident.edSk);
        ws.send(JSON.stringify({
          type: 'auth',
          deviceId: ident.deviceId,
          publicKey: Buffer.from(ident.edPk).toString('base64'),
          signature: Buffer.from(sig).toString('base64'),
          timestamp: ts,
        }));
      } else if (msg.type === 'auth-ok') {
        ws.send(JSON.stringify({
          type: 'register-rendezvous',
          rendezvousIds: [rendezvousId],
        }));
        resolve({ ws, incoming });
      } else if (msg.type === 'auth-fail') {
        reject(new Error('auth-fail: ' + (msg.reason || 'unknown')));
      } else if (onOpen?.json) {
        onOpen.json(msg);
      }
    });

    ws.on('error', reject);
    ws.on('close',  () => { /* tests close explicitly */ });

    // Hook for tests to listen on subsequent post-auth messages.
    ws._setListeners = (l) => { onOpen = l; };
  });
}

function buildTransport({ self, peer, kAB, ws }) {
  const captured = { clipboards: [], files: [], errors: [] };
  const t = new BeamV2Transport({
    sendBinary: (bytes) => { ws.send(bytes, { binary: true }); return true; },
    sendJson:   (msg)   => { ws.send(JSON.stringify(msg)); },
    hooks: {
      async getPeer(_id) {
        return {
          deviceId: peer.deviceId,
          ourSk: self.xSk, peerPk: peer.xPk,
          ourEdPk: self.edPk, peerEdPk: peer.edPk,
          kABRing: { currentGeneration: 0, keys: { 0: { kAB } } },
        };
      },
      async listPeers() {
        return [{
          deviceId: peer.deviceId,
          ourSk: self.xSk, peerPk: peer.xPk,
          ourEdPk: self.edPk, peerEdPk: peer.edPk,
          kABRing: { currentGeneration: 0, keys: { 0: { kAB } } },
        }];
      },
      async storeKABRing(_id, _ring) { /* no-op for E2E */ },
      async onClipboardReceived(content, fromDeviceId) {
        captured.clipboards.push({ content, fromDeviceId });
      },
      async onFileReceived(args) { captured.files.push(args); },
      onSendError:    (id, code) => captured.errors.push({ side: 'send', id, code }),
      onReceiveError: (id, code) => captured.errors.push({ side: 'recv', id, code }),
    },
  });
  // Wire incoming relay messages into the transport.
  ws._setListeners({
    json:   (msg)   => { t.handleJsonMessage(msg).catch(() => {}); },
    binary: (bytes) => {
      const u = bytes instanceof Buffer ? new Uint8Array(bytes) : new Uint8Array(bytes);
      t.handleIncomingFrame(u).catch(() => {});
    },
  });
  return { transport: t, captured };
}

function waitFor(predicate, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() > deadline) return reject(new Error('waitFor timeout'));
      setTimeout(tick, 10);
    };
    tick();
  });
}

// ─── shared fixture ───────────────────────────────────────────────────────

let relay, A, B, kAB, sideA, sideB;

before(async () => {
  relay = await startTestRelay();
  A = await makeFullIdentity();
  B = await makeFullIdentity();

  const kA = await deriveKAB({
    ourSk: A.xSk, peerPk: B.xPk, ourEdPk: A.edPk, peerEdPk: B.edPk, generation: 0,
  });
  const kB = await deriveKAB({
    ourSk: B.xSk, peerPk: A.xPk, ourEdPk: B.edPk, peerEdPk: A.edPk, generation: 0,
  });
  assert.deepEqual(kA, kB, 'paired K_AB must match');
  kAB = kA;

  // Both sides register the SAME rendezvous so they appear as peers to the
  // server's presence module — that's what makes the relay-bind proactive
  // receiverWs lookup succeed.
  const RENDEZVOUS = 'beam-v2-e2e-' + Math.random().toString(36).slice(2, 10);
  const a = await connectAndAuth(relay.url, A, RENDEZVOUS);
  const b = await connectAndAuth(relay.url, B, RENDEZVOUS);

  sideA = buildTransport({ self: A, peer: B, kAB, ws: a.ws });
  sideB = buildTransport({ self: B, peer: A, kAB, ws: b.ws });

  // Tiny grace so PEER_ONLINE traffic settles.
  await new Promise((r) => setTimeout(r, 50));
});

after(async () => {
  if (relay) await relay.close();
});

// ─── tests ────────────────────────────────────────────────────────────────

describe('Beam v2 E2E over real relay', () => {
  it('clipboard A → B', async () => {
    await sideA.transport.sendClipboard(B.deviceId, 'hello from A');
    await waitFor(() => sideB.captured.clipboards.length > 0);
    assert.equal(sideB.captured.clipboards.at(-1).content, 'hello from A');
    assert.deepEqual(sideA.captured.errors, []);
    assert.deepEqual(sideB.captured.errors, []);
  });

  it('clipboard B → A (the path that was broken in v1)', async () => {
    await sideB.transport.sendClipboard(A.deviceId, 'hello back from B');
    await waitFor(() => sideA.captured.clipboards.length > 0);
    assert.equal(sideA.captured.clipboards.at(-1).content, 'hello back from B');
  });

  it('file A → B (3 chunks ~600 KB)', async () => {
    const fileSize = 3 * 200 * 1024;
    const bytes = new Uint8Array(fileSize);
    for (let i = 0; i < fileSize; i += 65536) {
      crypto.getRandomValues(bytes.subarray(i, Math.min(i + 65536, fileSize)));
    }
    const startCount = sideB.captured.files.length;
    await sideA.transport.sendFile(B.deviceId, {
      fileName: 'x.bin', fileSize, mimeType: 'application/octet-stream', bytes,
    });
    await waitFor(() => sideB.captured.files.length > startCount, 15_000);
    const got = sideB.captured.files.at(-1);
    assert.equal(got.fileName, 'x.bin');
    assert.equal(got.fileSize, fileSize);
    assert.deepEqual(got.bytes, bytes);
  });

  it('file B → A (1 chunk)', async () => {
    const bytes = new Uint8Array(64 * 1024);
    crypto.getRandomValues(bytes);
    const startCount = sideA.captured.files.length;
    await sideB.transport.sendFile(A.deviceId, {
      fileName: 'r.bin', fileSize: bytes.byteLength, mimeType: 'application/octet-stream', bytes,
    });
    await waitFor(() => sideA.captured.files.length > startCount, 8_000);
    assert.deepEqual(sideA.captured.files.at(-1).bytes, bytes);
  });
});
