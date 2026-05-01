/**
 * @file beam-v2-transport.test.js
 * @description End-to-end coverage of the v2 transport using two instances
 * paired with each other. No relay needed — the test wires `sendBinary`
 * from each side to the other's `handleIncomingFrame`, and `sendJson` to
 * the other's `handleJsonMessage`.
 *
 * Run: node --test test/beam-v2-transport.test.js
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { BeamV2Transport } from '../crypto/beam-v2-transport.js';
import { deriveKAB }       from '../crypto/beam-v2.js';
import { x25519PublicKey } from '../crypto/beam-crypto.js';
import {
  RECEIVE_GAP_MS,
  RECEIVER_GIVEUP_MS,
} from '../crypto/beam-v2-constants.js';

// ─── pair fixture ─────────────────────────────────────────────────────────

async function makePairedFixture() {
  const a = await makeIdentity('A');
  const b = await makeIdentity('B');

  // Both sides derive K_AB from the same DH inputs at gen=0.
  const k_a = await deriveKAB({
    ourSk: a.x_sk, peerPk: b.x_pk, ourEdPk: a.ed_pk, peerEdPk: b.ed_pk, generation: 0,
  });
  const k_b = await deriveKAB({
    ourSk: b.x_sk, peerPk: a.x_pk, ourEdPk: b.ed_pk, peerEdPk: a.ed_pk, generation: 0,
  });
  assert.deepEqual(k_a, k_b, 'K_AB must match on both sides');

  a.peer = { ...b, kABRing: { currentGeneration: 0, keys: { 0: { kAB: k_a } } } };
  b.peer = { ...a, kABRing: { currentGeneration: 0, keys: { 0: { kAB: k_b } } } };
  return { a, b };
}

async function makeIdentity(label) {
  const x_sk  = randomBytes32();
  const x_pk  = await x25519PublicKey(x_sk);
  const ed_pk = randomBytes32(); // We don't sign in transport tests; placeholder is fine.
  const id = label + '_' + Buffer.from(ed_pk.slice(0, 8)).toString('hex');
  return { deviceId: id, x_sk, x_pk, ed_pk };
}
function randomBytes32() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return b;
}

/**
 * Wire two transports together so each side's send goes to the other's
 * handle. Returns delivery counters and captured artifacts for assertions.
 */
function wirePair(aPeer, bPeer) {
  const captured = {
    aReceivedClipboard: [],
    bReceivedClipboard: [],
    aReceivedFile: [],
    bReceivedFile: [],
    aErrors: [],
    bErrors: [],
  };
  /** @type {{ a: BeamV2Transport, b: BeamV2Transport }} */
  const t = {};

  t.a = makeTransport({
    self: aPeer, peer: bPeer,
    deliverBinary: (bytes) => t.b.handleIncomingFrame(bytes),
    deliverJson:   (msg)   => t.b.handleJsonMessage({ ...msg, fromDeviceId: aPeer.deviceId }),
    onClipboard:   (text, from) => captured.aReceivedClipboard.push({ text, from }),
    onFile:        (f) => captured.aReceivedFile.push(f),
    onError:       (id, code) => captured.aErrors.push({ id, code }),
  });
  t.b = makeTransport({
    self: bPeer, peer: aPeer,
    deliverBinary: (bytes) => t.a.handleIncomingFrame(bytes),
    deliverJson:   (msg)   => t.a.handleJsonMessage({ ...msg, fromDeviceId: bPeer.deviceId }),
    onClipboard:   (text, from) => captured.bReceivedClipboard.push({ text, from }),
    onFile:        (f) => captured.bReceivedFile.push(f),
    onError:       (id, code) => captured.bErrors.push({ id, code }),
  });

  return { ...t, captured };
}

function makeTransport({ self, peer, deliverBinary, deliverJson, onClipboard, onFile, onError }) {
  return new BeamV2Transport({
    sendBinary: (bytes) => { setImmediate(() => deliverBinary(bytes)); return true; },
    sendJson:   (msg)   => { setImmediate(() => deliverJson(msg)); },
    hooks: {
      async getPeer(_id) { return self.peer; },
      async listPeers() { return [self.peer]; },
      async storeKABRing(_id, _ring) { /* no-op */ },
      async onClipboardReceived(content, fromDeviceId) {
        onClipboard(content, fromDeviceId);
      },
      async onFileReceived(args) { onFile(args); },
      onSendError:    (id, code) => onError(id, code),
      onReceiveError: (id, code) => onError(id, code),
    },
  });
}

function waitFor(predicate, timeoutMs = 2_000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() > deadline) return reject(new Error('waitFor timeout'));
      setTimeout(tick, 5);
    };
    tick();
  });
}

// ─── tests ────────────────────────────────────────────────────────────────

describe('BeamV2Transport — paired round-trip', () => {
  it('clipboard A → B', async () => {
    const { a, b } = await makePairedFixture();
    const { a: ta, b: tb, captured } = wirePair(a, b);

    await ta.sendClipboard(b.deviceId, 'hello world');
    await waitFor(() => captured.bReceivedClipboard.length > 0);

    assert.equal(captured.bReceivedClipboard.length, 1);
    assert.equal(captured.bReceivedClipboard[0].text, 'hello world');
    assert.equal(captured.bReceivedClipboard[0].from, a.deviceId);
    assert.deepEqual(captured.aErrors, []);
    assert.deepEqual(captured.bErrors, []);
  });

  it('clipboard B → A (the path that was broken in v1)', async () => {
    const { a, b } = await makePairedFixture();
    const { a: ta, b: tb, captured } = wirePair(a, b);

    await tb.sendClipboard(a.deviceId, 'reply from B');
    await waitFor(() => captured.aReceivedClipboard.length > 0);

    assert.equal(captured.aReceivedClipboard[0].text, 'reply from B');
  });

  it('file A → B (multi-chunk, ~3 chunks)', async () => {
    const { a, b } = await makePairedFixture();
    const { a: ta, captured } = wirePair(a, b);

    const fileSize = 500 * 1024; // 3 chunks at 200 KB
    const bytes = new Uint8Array(fileSize);
    for (let i = 0; i < fileSize; i += 65536) {
      crypto.getRandomValues(bytes.subarray(i, Math.min(i + 65536, fileSize)));
    }

    await ta.sendFile(b.deviceId, {
      fileName: 'test.bin', fileSize, mimeType: 'application/octet-stream', bytes,
    });
    await waitFor(() => captured.bReceivedFile.length > 0, 5_000);

    const got = captured.bReceivedFile[0];
    assert.equal(got.fileName, 'test.bin');
    assert.equal(got.fileSize, fileSize);
    assert.equal(got.mimeType, 'application/octet-stream');
    assert.equal(got.bytes.byteLength, fileSize);
    assert.deepEqual(got.bytes, bytes);
  });

  it('file B → A round-trip with bidirectional delivery', async () => {
    const { a, b } = await makePairedFixture();
    const { b: tb, captured } = wirePair(a, b);

    const bytes = new Uint8Array(64 * 1024); // 1 chunk
    crypto.getRandomValues(bytes);

    await tb.sendFile(a.deviceId, {
      fileName: 'reply.dat', fileSize: bytes.byteLength, mimeType: 'application/octet-stream', bytes,
    });
    await waitFor(() => captured.aReceivedFile.length > 0, 3_000);
    assert.equal(captured.aReceivedFile[0].fileName, 'reply.dat');
    assert.deepEqual(captured.aReceivedFile[0].bytes, bytes);
  });
});

describe('BeamV2Transport — resend', () => {
  it('receiver requests missing chunks; sender re-sends', async () => {
    const { a, b } = await makePairedFixture();

    // Wire with a "lossy" delivery for B that drops index 2 once.
    let dropOnceForIndex2 = true;
    const captured = {
      aReceivedClipboard: [], bReceivedClipboard: [],
      aReceivedFile: [],      bReceivedFile: [],
      aErrors: [],            bErrors: [],
    };
    /** @type {{ a: BeamV2Transport, b: BeamV2Transport }} */
    const t = {};

    t.a = makeTransport({
      self: a, peer: b,
      deliverBinary: (bytes) => {
        // Read the index from the header (offset 24, u32 BE) — drop frame index 2 once.
        const idx = new DataView(bytes.buffer, bytes.byteOffset + 24, 4).getUint32(0, false);
        if (idx === 2 && dropOnceForIndex2) {
          dropOnceForIndex2 = false;
          return; // drop on the wire
        }
        setImmediate(() => t.b.handleIncomingFrame(bytes));
      },
      deliverJson: (msg) => setImmediate(() => t.b.handleJsonMessage({ ...msg, fromDeviceId: a.deviceId })),
      onClipboard: (text, from) => captured.aReceivedClipboard.push({ text, from }),
      onFile:      (f) => captured.aReceivedFile.push(f),
      onError:     (id, code) => captured.aErrors.push({ id, code }),
    });
    t.b = makeTransport({
      self: b, peer: a,
      deliverBinary: (bytes) => setImmediate(() => t.a.handleIncomingFrame(bytes)),
      deliverJson:   (msg) => setImmediate(() => t.a.handleJsonMessage({ ...msg, fromDeviceId: b.deviceId })),
      onClipboard:   (text, from) => captured.bReceivedClipboard.push({ text, from }),
      onFile:        (f) => captured.bReceivedFile.push(f),
      onError:       (id, code) => captured.bErrors.push({ id, code }),
    });

    const fileSize = 3 * 200 * 1024; // 3 chunks
    const bytes = new Uint8Array(fileSize);
    for (let i = 0; i < fileSize; i += 65536) {
      crypto.getRandomValues(bytes.subarray(i, Math.min(i + 65536, fileSize)));
    }

    await t.a.sendFile(b.deviceId, {
      fileName: 'lossy.bin', fileSize, mimeType: 'application/octet-stream', bytes,
    });
    // The receiver triggers resend after RECEIVE_GAP_MS or after isFinal+missing,
    // whichever fires first. Allow generous time for the round-trip.
    await waitFor(() => captured.bReceivedFile.length > 0, RECEIVE_GAP_MS + 5_000);

    assert.equal(captured.bReceivedFile.length, 1);
    assert.deepEqual(captured.bReceivedFile[0].bytes, bytes);
  });
});
