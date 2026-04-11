// Beam crypto — test vector suite for the Chrome implementation.
//
// Loads test-vectors-v1.json (byte-exact mirror of
// server/test-vectors/crypto-v1.json) and asserts that every public function
// in beam-crypto.js reproduces the canonical output produced by the Python
// generator. If any assertion fails, the Chrome implementation has drifted
// from the spec and must be fixed before it can interoperate with Android.
//
// Usage: loaded by beam-crypto.test.html in a browser context.

import {
  PROTOCOL_VERSION,
  KIND_CLIPBOARD,
  KIND_FILE_METADATA,
  KIND_FILE_CHUNK,
  computeTripleDHInitiator,
  computeTripleDHResponder,
  computeTranscript,
  deriveSessionKey,
  deriveChunkKey,
  deriveMetaKey,
  deriveNonce,
  buildAAD,
  padPlaintext,
  unpadPlaintext,
  encryptClipboard,
  decryptClipboard,
  encryptFileMetadata,
  decryptFileMetadata,
  encryptFileChunk,
  decryptFileChunk,
  x25519PublicKey,
  fromHex,
  toHex,
} from './beam-crypto.js';

// ---------------------------------------------------------------------------
// Tiny test harness. Writes results into #results in the host page and also
// logs to the console. Returns overall pass/fail for the page to display.
// ---------------------------------------------------------------------------

const results = [];

function record(name, passed, detail) {
  results.push({ name, passed, detail });
  const line = `${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? `  — ${detail}` : ''}`;
  if (passed) console.log(line);
  else console.error(line);
}

function assertHexEqual(name, actual, expectedHex, detail) {
  const actualHex = toHex(actual);
  const passed = actualHex === expectedHex;
  record(name, passed, passed ? detail : `expected ${expectedHex}, got ${actualHex}`);
  return passed;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

function assertEqual(name, actual, expected, detail) {
  const passed = actual === expected;
  record(name, passed, passed ? detail : `expected ${expected}, got ${actual}`);
  return passed;
}

// ---------------------------------------------------------------------------
// Main runner.
// ---------------------------------------------------------------------------

export async function runTests() {
  const res = await fetch('./test-vectors-v1.json');
  if (!res.ok) throw new Error(`failed to load test vectors: ${res.status}`);
  const v = await res.json();

  // Sanity: version matches what our module expects.
  assertEqual('protocol version', v.version, PROTOCOL_VERSION);

  // Decode all inputs once.
  const staticSkA = fromHex(v.inputs.staticSkA);
  const staticPkA = fromHex(v.inputs.staticPkA);
  const staticSkB = fromHex(v.inputs.staticSkB);
  const staticPkB = fromHex(v.inputs.staticPkB);
  const ephSkA = fromHex(v.inputs.ephSkA);
  const ephPkA = fromHex(v.inputs.ephPkA);
  const ephSkB = fromHex(v.inputs.ephSkB);
  const ephPkB = fromHex(v.inputs.ephPkB);
  const salt = fromHex(v.inputs.salt);
  const transferId = fromHex(v.inputs.transferId);

  // ---- public keys derive correctly from the private keys ----
  {
    const pkA = await x25519PublicKey(staticSkA);
    assertHexEqual('staticPkA derived from staticSkA', pkA, v.inputs.staticPkA);
    const pkB = await x25519PublicKey(staticSkB);
    assertHexEqual('staticPkB derived from staticSkB', pkB, v.inputs.staticPkB);
    const epkA = await x25519PublicKey(ephSkA);
    assertHexEqual('ephPkA derived from ephSkA', epkA, v.inputs.ephPkA);
    const epkB = await x25519PublicKey(ephSkB);
    assertHexEqual('ephPkB derived from ephSkB', epkB, v.inputs.ephPkB);
  }

  // ---- Triple-DH from both perspectives ----
  const { dh1: dh1I, dh2: dh2I, dh3: dh3I, ikm: ikmI } =
    await computeTripleDHInitiator({ staticSkA, ephSkA, staticPkB, ephPkB });
  assertHexEqual('tripleDH.dh1 (initiator)', dh1I, v.tripleDH.dh1);
  assertHexEqual('tripleDH.dh2 (initiator)', dh2I, v.tripleDH.dh2);
  assertHexEqual('tripleDH.dh3 (initiator)', dh3I, v.tripleDH.dh3);
  assertHexEqual('tripleDH.ikm (initiator)', ikmI, v.tripleDH.ikm);

  const { dh1: dh1R, dh2: dh2R, dh3: dh3R, ikm: ikmR } =
    await computeTripleDHResponder({ staticSkB, ephSkB, staticPkA, ephPkA });
  assertHexEqual('tripleDH.dh1 (responder mirror)', dh1R, v.tripleDH.dh1);
  assertHexEqual('tripleDH.dh2 (responder mirror)', dh2R, v.tripleDH.dh2);
  assertHexEqual('tripleDH.dh3 (responder mirror)', dh3R, v.tripleDH.dh3);
  assertHexEqual('tripleDH.ikm (responder mirror)', ikmR, v.tripleDH.ikm);

  // ---- Transcript hash ----
  const transcript = await computeTranscript({
    version: v.version,
    staticPkA,
    staticPkB,
    ephPkA,
    ephPkB,
    transferId,
  });
  assertHexEqual('transcript', transcript, v.transcript);

  // ---- Session / chunk / meta keys ----
  const sessionKey = await deriveSessionKey({ ikm: ikmI, salt, transcript });
  assertHexEqual('sessionKey', sessionKey, v.keys.sessionKey);

  const chunkKey = await deriveChunkKey(sessionKey);
  assertHexEqual('chunkKey', chunkKey, v.keys.chunkKey);

  const metaKey = await deriveMetaKey(sessionKey);
  assertHexEqual('metaKey', metaKey, v.keys.metaKey);

  // ---- Clipboard AEAD ----
  {
    const plaintext = fromHex(v.clipboard.plaintext);
    const expectedNonceHex = v.clipboard.nonce;
    const expectedAadHex = v.clipboard.aad;
    const expectedCtHex = v.clipboard.ciphertext;

    const nonce = await deriveNonce(chunkKey, 0);
    assertHexEqual('clipboard.nonce', nonce, expectedNonceHex);

    const aad = buildAAD({
      kindByte: KIND_CLIPBOARD,
      index: 0,
      totalChunks: 1,
      transcript,
    });
    assertHexEqual('clipboard.aad', aad, expectedAadHex);

    const { ciphertext } = await encryptClipboard({
      plaintext,
      chunkKey,
      transcript,
    });
    assertHexEqual('clipboard.ciphertext', ciphertext, expectedCtHex);

    // round-trip
    const decoded = await decryptClipboard({
      ciphertext: fromHex(expectedCtHex),
      chunkKey,
      transcript,
    });
    assertHexEqual(
      'clipboard.roundtrip',
      decoded,
      v.clipboard.plaintext,
      `${decoded.byteLength} bytes`,
    );
  }

  // ---- File metadata AEAD ----
  {
    const plaintext = fromHex(v.fileMetadata.plaintext);
    const nonce = await deriveNonce(metaKey, 0);
    assertHexEqual('fileMetadata.nonce', nonce, v.fileMetadata.nonce);

    const aad = buildAAD({
      kindByte: KIND_FILE_METADATA,
      index: 0,
      totalChunks: 0,
      transcript,
    });
    assertHexEqual('fileMetadata.aad', aad, v.fileMetadata.aad);

    const { ciphertext } = await encryptFileMetadata({
      plaintext,
      metaKey,
      transcript,
    });
    assertHexEqual('fileMetadata.ciphertext', ciphertext, v.fileMetadata.ciphertext);

    const decoded = await decryptFileMetadata({
      ciphertext: fromHex(v.fileMetadata.ciphertext),
      metaKey,
      transcript,
    });
    assertHexEqual('fileMetadata.roundtrip', decoded, v.fileMetadata.plaintext);
  }

  // ---- File chunks ----
  {
    const totalChunks = v.fileChunks.totalChunks;
    // We regenerate the plaintext chunks using the same byte pattern as the
    // Python generator: chunk i uses (i * A + B) & 0xFF where (A, B) are
    // fixed per chunk. We only have the plaintextSha256 in the JSON, so we
    // reconstruct and check the hash matches before feeding into encrypt.
    const patterns = [
      { a: 37, b: 13, len: 200 * 1024 },
      { a: 91, b:  7, len: 200 * 1024 },
      { a: 53, b: 29, len: 12345 },
    ];
    for (let i = 0; i < patterns.length; i += 1) {
      const { a, b, len } = patterns[i];
      const chunkIndex = i + 1;
      const vc = v.fileChunks.chunks[i];
      assertEqual(`fileChunk[${chunkIndex}].index`, vc.index, chunkIndex);

      // Build plaintext.
      const plaintext = new Uint8Array(len);
      for (let k = 0; k < len; k += 1) {
        plaintext[k] = (k * a + b) & 0xff;
      }
      // Hash check — confirms our reconstruction matches the generator.
      // eslint-disable-next-line no-await-in-loop
      const ptHashHex = await sha256Hex(plaintext);
      assertEqual(
        `fileChunk[${chunkIndex}].plaintextSha256`,
        ptHashHex,
        vc.plaintextSha256,
      );

      // eslint-disable-next-line no-await-in-loop
      const nonce = await deriveNonce(chunkKey, chunkIndex);
      assertHexEqual(`fileChunk[${chunkIndex}].nonce`, nonce, vc.nonce);

      const aad = buildAAD({
        kindByte: KIND_FILE_CHUNK,
        index: chunkIndex,
        totalChunks,
        transcript,
      });
      assertHexEqual(`fileChunk[${chunkIndex}].aad`, aad, vc.aad);

      // eslint-disable-next-line no-await-in-loop
      const { ciphertext } = await encryptFileChunk({
        plaintext,
        chunkKey,
        index: chunkIndex,
        totalChunks,
        transcript,
      });
      assertEqual(
        `fileChunk[${chunkIndex}].ciphertextLen`,
        ciphertext.byteLength,
        vc.ciphertextLen,
      );
      // eslint-disable-next-line no-await-in-loop
      const ctHashHex = await sha256Hex(ciphertext);
      assertEqual(
        `fileChunk[${chunkIndex}].ciphertextSha256`,
        ctHashHex,
        vc.ciphertextSha256,
      );

      // Round-trip decrypt.
      // eslint-disable-next-line no-await-in-loop
      const decoded = await decryptFileChunk({
        ciphertext,
        chunkKey,
        index: chunkIndex,
        totalChunks,
        transcript,
      });
      // eslint-disable-next-line no-await-in-loop
      const rtHashHex = await sha256Hex(decoded);
      assertEqual(
        `fileChunk[${chunkIndex}].roundtripSha256`,
        rtHashHex,
        vc.plaintextSha256,
      );
    }
  }

  // ---- Padding sanity ----
  {
    const p = padPlaintext(new Uint8Array([1, 2, 3]));
    const u = unpadPlaintext(p);
    assertEqual('padding roundtrip length', u.byteLength, 3);
    assertEqual('padding roundtrip[0]', u[0], 1);
    assertEqual('padding roundtrip[1]', u[1], 2);
    assertEqual('padding roundtrip[2]', u[2], 3);
  }

  // ---- Summary ----
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;
  return { total, passed, failed, results };
}
