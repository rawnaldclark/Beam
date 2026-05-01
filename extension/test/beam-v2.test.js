/**
 * @file beam-v2.test.js
 * @description Unit coverage for the Beam v2 codec.
 *
 * Run:  node --test test/beam-v2.test.js
 *
 * Each test exercises a property the spec promises and the implementation
 * MUST preserve across both Chrome and Android. If any of these break,
 * cross-platform interop has regressed.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveKAB,
  encodeFrame,
  decodeFrame,
  buildHeader,
  peekHeader,
  newTransferId,
} from '../crypto/beam-v2.js';
import {
  HEADER_LEN,
  NONCE_LEN,
  KAB_LEN,
  MAGIC,
  VERSION,
  FLAG_IS_FINAL,
  FLAG_HAS_META,
} from '../crypto/beam-v2-constants.js';

// ─── shared fixtures ──────────────────────────────────────────────────────

/**
 * Build two paired identities with deterministic-ish keys (still uses
 * libsodium internally but the test re-derives K_AB so determinism is
 * about the function not about RNG state).
 */
async function makePair() {
  const { x25519PublicKey } = await import('../crypto/beam-crypto.js');
  const a_sk = randomBytes32();
  const b_sk = randomBytes32();
  const a_pk = await x25519PublicKey(a_sk);
  const b_pk = await x25519PublicKey(b_sk);
  const a_ed = randomBytes32();
  const b_ed = randomBytes32();
  return { a_sk, a_pk, a_ed, b_sk, b_pk, b_ed };
}

function randomBytes32() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return b;
}

// ─── deriveKAB ────────────────────────────────────────────────────────────

describe('deriveKAB', () => {
  it('produces identical K_AB on both sides', async () => {
    const { a_sk, a_pk, a_ed, b_sk, b_pk, b_ed } = await makePair();
    const kA = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed, generation: 0,
    });
    const kB = await deriveKAB({
      ourSk: b_sk, peerPk: a_pk, ourEdPk: b_ed, peerEdPk: a_ed, generation: 0,
    });
    assert.equal(kA.byteLength, KAB_LEN);
    assert.deepEqual(kA, kB, 'both sides must derive the same K_AB');
  });

  it('different generations produce different keys', async () => {
    const { a_sk, b_pk, a_ed, b_ed } = await makePair();
    const k0 = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed, generation: 0,
    });
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    const k1 = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed,
      generation: 1, rotateNonce: nonce,
    });
    assert.notDeepEqual(k0, k1);
  });

  it('rotation requires a 16-byte nonce', async () => {
    const { a_sk, b_pk, a_ed, b_ed } = await makePair();
    await assert.rejects(
      deriveKAB({ ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed, generation: 1 }),
      /rotateNonce/,
    );
  });

  it('different rotation nonces produce different keys at the same gen', async () => {
    const { a_sk, b_pk, a_ed, b_ed } = await makePair();
    const n1 = new Uint8Array(16); crypto.getRandomValues(n1);
    const n2 = new Uint8Array(16); crypto.getRandomValues(n2);
    const k1 = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed,
      generation: 1, rotateNonce: n1,
    });
    const k2 = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed,
      generation: 1, rotateNonce: n2,
    });
    assert.notDeepEqual(k1, k2);
  });
});

// ─── header ───────────────────────────────────────────────────────────────

describe('header layout', () => {
  it('header is exactly 48 bytes with magic + version + reserved zeros', () => {
    const tid = newTransferId();
    const h = buildHeader({
      transferId: tid, index: 7, isFinal: true, hasMeta: false, generation: 3,
    });
    assert.equal(h.byteLength, HEADER_LEN);
    for (let i = 0; i < 4; i++) assert.equal(h[i], MAGIC[i]);
    assert.equal(h[4], VERSION);
    assert.equal(h[5], FLAG_IS_FINAL);
    assert.equal(h[6], 0);
    assert.equal(h[7], 0);
    for (let i = 32; i < 48; i++) assert.equal(h[i], 0, `reserved byte ${i} must be zero`);
  });

  it('round-trips through peekHeader', () => {
    const tid = newTransferId();
    const h = buildHeader({
      transferId: tid, index: 0xDEADBEEF, isFinal: false, hasMeta: true, generation: 42,
    });
    const parsed = peekHeader(h);
    assert.ok(parsed);
    assert.deepEqual(parsed.transferId, tid);
    assert.equal(parsed.index, 0xDEADBEEF);
    assert.equal(parsed.isFinal, false);
    assert.equal(parsed.hasMeta, true);
    assert.equal(parsed.generation, 42);
  });

  it('peekHeader rejects a bad magic', () => {
    const h = buildHeader({
      transferId: newTransferId(), index: 0, isFinal: true, hasMeta: true, generation: 0,
    });
    h[0] = 0;
    assert.equal(peekHeader(h), null);
  });

  it('peekHeader rejects unknown version', () => {
    const h = buildHeader({
      transferId: newTransferId(), index: 0, isFinal: true, hasMeta: true, generation: 0,
    });
    h[4] = 0x99;
    assert.equal(peekHeader(h), null);
  });

  it('peekHeader rejects reserved-bit violations in flags', () => {
    const h = buildHeader({
      transferId: newTransferId(), index: 0, isFinal: true, hasMeta: true, generation: 0,
    });
    h[5] = 0xFF;
    assert.equal(peekHeader(h), null);
  });

  it('peekHeader rejects non-zero reserved trailing bytes', () => {
    const h = buildHeader({
      transferId: newTransferId(), index: 0, isFinal: true, hasMeta: true, generation: 0,
    });
    h[40] = 1;
    assert.equal(peekHeader(h), null);
  });
});

// ─── round-trip ───────────────────────────────────────────────────────────

describe('encode/decode round-trip', () => {
  /** @type {Uint8Array} */
  let kAB;
  before(async () => {
    const { a_sk, b_pk, a_ed, b_ed } = await makePair();
    kAB = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed, generation: 0,
    });
  });

  for (const size of [1, 32, 1024, 200 * 1024]) {
    it(`round-trips a ${size}-byte plaintext`, async () => {
      const tid = newTransferId();
      const plaintext = new Uint8Array(size);
      // crypto.getRandomValues caps at 65536 — fill in chunks for large sizes.
      for (let off = 0; off < size; off += 65536) {
        crypto.getRandomValues(plaintext.subarray(off, Math.min(off + 65536, size)));
      }
      const frame = await encodeFrame({
        kAB, generation: 0, transferId: tid, index: 0,
        isFinal: true, hasMeta: true, plaintext,
      });
      const out = await decodeFrame({
        resolveKAB: (g) => (g === 0 ? kAB : null),
        frameBytes: frame,
      });
      assert.ok(out);
      assert.deepEqual(out.plaintext, plaintext);
      assert.deepEqual(out.header.transferId, tid);
      assert.equal(out.header.index, 0);
      assert.equal(out.header.isFinal, true);
      assert.equal(out.header.hasMeta, true);
      assert.equal(out.header.generation, 0);
    });
  }
});

// ─── tamper resistance ────────────────────────────────────────────────────

describe('tamper resistance', () => {
  /** @type {Uint8Array} */
  let kAB;
  /** @type {Uint8Array} */
  let frame;

  before(async () => {
    const { a_sk, b_pk, a_ed, b_ed } = await makePair();
    kAB = await deriveKAB({
      ourSk: a_sk, peerPk: b_pk, ourEdPk: a_ed, peerEdPk: b_ed, generation: 0,
    });
    const plaintext = new TextEncoder().encode('the quick brown fox');
    frame = await encodeFrame({
      kAB, generation: 0, transferId: newTransferId(),
      index: 0, isFinal: true, hasMeta: true, plaintext,
    });
  });

  it('flips a ciphertext byte → decrypt fails', async () => {
    const tampered = frame.slice();
    tampered[HEADER_LEN + NONCE_LEN + 5] ^= 0x01;
    const out = await decodeFrame({ resolveKAB: () => kAB, frameBytes: tampered });
    assert.equal(out, null);
  });

  it('flips a header byte (bound by AAD) → decrypt fails', async () => {
    const tampered = frame.slice();
    tampered[24] ^= 0x01; // index byte
    const out = await decodeFrame({ resolveKAB: () => kAB, frameBytes: tampered });
    assert.equal(out, null);
  });

  it('flips a nonce byte → decrypt fails', async () => {
    const tampered = frame.slice();
    tampered[HEADER_LEN] ^= 0x01;
    const out = await decodeFrame({ resolveKAB: () => kAB, frameBytes: tampered });
    assert.equal(out, null);
  });

  it('wrong K_AB → decrypt fails', async () => {
    const wrong = randomBytes32();
    const out = await decodeFrame({ resolveKAB: () => wrong, frameBytes: frame });
    assert.equal(out, null);
  });

  it('unknown generation (resolver returns null) → decrypt fails', async () => {
    const out = await decodeFrame({ resolveKAB: () => null, frameBytes: frame });
    assert.equal(out, null);
  });

  it('truncated frame → decrypt fails without throwing', async () => {
    const short = frame.slice(0, HEADER_LEN + NONCE_LEN + 8);
    const out = await decodeFrame({ resolveKAB: () => kAB, frameBytes: short });
    assert.equal(out, null);
  });
});
