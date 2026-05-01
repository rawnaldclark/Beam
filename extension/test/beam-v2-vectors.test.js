/**
 * @file beam-v2-vectors.test.js
 * @description Cross-implementation interop check.
 *
 * Loads the canonical `server/test-vectors/beam-v2/vectors.json` and
 * verifies that this codec reproduces the expected K_AB derivations and
 * decodes the captured frame bytes to the expected plaintext.
 *
 * The Kotlin side runs the same assertions against the same file. Drift
 * between the two implementations is caught here before it can break a
 * paired transfer in the wild.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveKAB, decodeFrame } from '../crypto/beam-v2.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, '../../server/test-vectors/beam-v2/vectors.json'),
    'utf8',
  ),
);

const hex = (s) => {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) out[i / 2] = parseInt(s.substr(i, 2), 16);
  return out;
};
const toHex = (b) => {
  let s = '';
  for (let i = 0; i < b.length; i += 1) s += b[i].toString(16).padStart(2, '0');
  return s;
};

describe('beam-v2 vectors — K_AB derivation', () => {
  for (const v of VECTORS.kab_derivation) {
    it(v.name, async () => {
      const got = await deriveKAB({
        ourSk:    hex(v.a_x_sk),
        peerPk:   hex(v.b_x_pk),
        ourEdPk:  hex(v.a_ed_pk),
        peerEdPk: hex(v.b_ed_pk),
        generation:  v.generation,
        rotateNonce: v.rotate_nonce ? hex(v.rotate_nonce) : null,
      });
      assert.equal(toHex(got), v.expected_kab);
    });
  }
});

describe('beam-v2 vectors — frame decode', () => {
  for (const v of VECTORS.frames) {
    it(v.name, async () => {
      const kAB = hex(v.kab);
      const out = await decodeFrame({
        resolveKAB: () => kAB,
        frameBytes: hex(v.frame),
      });
      assert.ok(out, `decode failed for ${v.name}`);
      assert.equal(toHex(out.plaintext), v.expected_plaintext);
      assert.equal(toHex(out.header.transferId), v.expected_header.transferId);
      assert.equal(out.header.index,      v.expected_header.index);
      assert.equal(out.header.isFinal,    v.expected_header.isFinal);
      assert.equal(out.header.hasMeta,    v.expected_header.hasMeta);
      assert.equal(out.header.generation, v.expected_header.generation);
    });
  }
});
