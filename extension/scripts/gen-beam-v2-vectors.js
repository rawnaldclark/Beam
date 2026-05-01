/**
 * @file gen-beam-v2-vectors.js
 * @description One-shot generator for `server/test-vectors/beam-v2/vectors.json`.
 *
 * Run:  node scripts/gen-beam-v2-vectors.js
 *
 * Uses fixed inputs (hardcoded byte arrays) and a fixed nonce so the output
 * is byte-deterministic. Both Chrome (`beam-v2.test.js`) and Android
 * (`BeamV2Test.kt`) load the resulting JSON and verify they decode each
 * vector to the expected plaintext, AND that K_AB derivation matches.
 *
 * Re-run only when the protocol bytes legitimately change. Diff the
 * resulting file in code review — bytes flipping is a wire-format break.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  deriveKAB,
  encodeFrame,
  newTransferId,
} from '../crypto/beam-v2.js';
import { x25519PublicKey } from '../crypto/beam-crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Hard-coded inputs — never random. Each constant is a fixed 32-byte hex string.
const A_X_SK = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
const B_X_SK = hexToBytes('0202020202020202020202020202020202020202020202020202020202020202');
const A_ED_PK = hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
const B_ED_PK = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

const FIXED_NONCE = hexToBytes('303132333435363738393a3b3c3d3e3f4041424344454647'); // 24 bytes
const FIXED_TRANSFER_ID = hexToBytes('00112233445566778899aabbccddeeff'); // 16 bytes

async function main() {
  const A_X_PK = await x25519PublicKey(A_X_SK);
  const B_X_PK = await x25519PublicKey(B_X_SK);

  // ── K_AB derivation ────────────────────────────────────────────────
  const kab_gen0_aliceSide = await deriveKAB({
    ourSk: A_X_SK, peerPk: B_X_PK, ourEdPk: A_ED_PK, peerEdPk: B_ED_PK, generation: 0,
  });
  const kab_gen0_bobSide = await deriveKAB({
    ourSk: B_X_SK, peerPk: A_X_PK, ourEdPk: B_ED_PK, peerEdPk: A_ED_PK, generation: 0,
  });
  if (toHex(kab_gen0_aliceSide) !== toHex(kab_gen0_bobSide)) {
    throw new Error('alice/bob K_AB derivations differ — broken sort?');
  }

  const ROTATE_NONCE = hexToBytes('5050505050505050505050505050505050505050505050505050505050505050'.slice(0, 32));
  const kab_gen1 = await deriveKAB({
    ourSk: A_X_SK, peerPk: B_X_PK, ourEdPk: A_ED_PK, peerEdPk: B_ED_PK,
    generation: 1, rotateNonce: ROTATE_NONCE,
  });

  // ── Frames ─────────────────────────────────────────────────────────

  // Vector 1: minimal clipboard frame
  const clipboardPlain = (() => {
    const meta = new TextEncoder().encode(JSON.stringify({ kind: 'clipboard', v: 2 }));
    const text = new TextEncoder().encode('hello beam');
    const out = new Uint8Array(2 + meta.byteLength + text.byteLength);
    new DataView(out.buffer).setUint16(0, meta.byteLength, false);
    out.set(meta, 2);
    out.set(text, 2 + meta.byteLength);
    return out;
  })();
  const clipboardFrame = await encodeFrame({
    kAB: kab_gen0_aliceSide, generation: 0,
    transferId: FIXED_TRANSFER_ID, index: 0,
    isFinal: true, hasMeta: true,
    plaintext: clipboardPlain,
    _testNonce: FIXED_NONCE,
  });

  // Vector 2: file metadata frame (index=0, hasMeta=1, isFinal=0)
  const filePlain = (() => {
    const meta = new TextEncoder().encode(JSON.stringify({
      kind: 'file', v: 2, fileName: 'note.txt', fileSize: 5, mime: 'text/plain', totalChunks: 1,
    }));
    const out = new Uint8Array(2 + meta.byteLength);
    new DataView(out.buffer).setUint16(0, meta.byteLength, false);
    out.set(meta, 2);
    return out;
  })();
  const fileMetaFrame = await encodeFrame({
    kAB: kab_gen0_aliceSide, generation: 0,
    transferId: FIXED_TRANSFER_ID, index: 0,
    isFinal: false, hasMeta: true,
    plaintext: filePlain,
    _testNonce: FIXED_NONCE,
  });

  // Vector 3: file chunk frame (index=1, isFinal=1)
  const chunkPlain = new TextEncoder().encode('hello'); // 5 bytes
  const fileChunkFrame = await encodeFrame({
    kAB: kab_gen0_aliceSide, generation: 0,
    transferId: FIXED_TRANSFER_ID, index: 1,
    isFinal: true, hasMeta: false,
    plaintext: chunkPlain,
    _testNonce: FIXED_NONCE,
  });

  const out = {
    description: 'Beam v2 cross-implementation interop vectors. See spec at docs/superpowers/specs/2026-04-30-beam-v2-design.md.',
    generated_by: 'extension/scripts/gen-beam-v2-vectors.js',
    kab_derivation: [
      {
        name: 'alice_bob_gen0',
        a_x_sk: toHex(A_X_SK),  a_ed_pk: toHex(A_ED_PK),
        b_x_sk: toHex(B_X_SK),  b_ed_pk: toHex(B_ED_PK),
        a_x_pk: toHex(A_X_PK),  b_x_pk: toHex(B_X_PK),
        generation: 0,
        rotate_nonce: null,
        expected_kab: toHex(kab_gen0_aliceSide),
      },
      {
        name: 'alice_bob_gen1_rotated',
        a_x_sk: toHex(A_X_SK),  a_ed_pk: toHex(A_ED_PK),
        b_x_sk: toHex(B_X_SK),  b_ed_pk: toHex(B_ED_PK),
        a_x_pk: toHex(A_X_PK),  b_x_pk: toHex(B_X_PK),
        generation: 1,
        rotate_nonce: toHex(ROTATE_NONCE),
        expected_kab: toHex(kab_gen1),
      },
    ],
    frames: [
      {
        name: 'clipboard_hello_beam',
        kab: toHex(kab_gen0_aliceSide),
        frame: toHex(clipboardFrame),
        expected_header: {
          transferId: toHex(FIXED_TRANSFER_ID), index: 0,
          isFinal: true, hasMeta: true, generation: 0,
        },
        expected_plaintext: toHex(clipboardPlain),
      },
      {
        name: 'file_metadata_note_txt',
        kab: toHex(kab_gen0_aliceSide),
        frame: toHex(fileMetaFrame),
        expected_header: {
          transferId: toHex(FIXED_TRANSFER_ID), index: 0,
          isFinal: false, hasMeta: true, generation: 0,
        },
        expected_plaintext: toHex(filePlain),
      },
      {
        name: 'file_chunk_hello',
        kab: toHex(kab_gen0_aliceSide),
        frame: toHex(fileChunkFrame),
        expected_header: {
          transferId: toHex(FIXED_TRANSFER_ID), index: 1,
          isFinal: true, hasMeta: false, generation: 0,
        },
        expected_plaintext: toHex(chunkPlain),
      },
    ],
  };

  const outPath = path.resolve(__dirname, '../../server/test-vectors/beam-v2/vectors.json');
  await fs.writeFile(outPath, JSON.stringify(out, null, 2) + '\n', 'utf8');
  console.log('wrote', outPath);
}

function toHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i += 1) s += b[i].toString(16).padStart(2, '0');
  return s;
}
function hexToBytes(s) {
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) b[i / 2] = parseInt(s.substr(i, 2), 16);
  return b;
}

main().catch((err) => { console.error(err); process.exit(1); });
