/**
 * @file wire-format.test.js
 * @description Tests for the Beam wire-format helpers (offscreen/wire-format.js).
 *
 * Runs with:  node --test test/wire-format.test.js
 *
 * Coverage:
 *   - uuidToBytes / bytesToUuid round-trip
 *   - encodeChunkHeader / decodeChunkHeader round-trip
 *   - Large value handling (uint64 byteOffset via BigInt)
 *   - isFinal flag encoding (bit 0 of flags byte)
 *   - Header fixed size (64 bytes)
 *   - Type byte always 0x01
 *   - Reserved bytes are all zero
 *   - Edge cases: chunkIndex 0, byteOffset 0n, isFinal false
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  uuidToBytes,
  bytesToUuid,
  encodeChunkHeader,
  decodeChunkHeader,
} from '../offscreen/wire-format.js';

// ─── helpers ────────────────────────────────────────────────────────────────

/** Canonical test UUID. */
const TEST_UUID = '550e8400-e29b-41d4-a716-446655440000';

// ═══════════════════════════════════════════════════════════════════════════
// 1. uuidToBytes
// ═══════════════════════════════════════════════════════════════════════════

describe('uuidToBytes', () => {
  it('returns a Uint8Array of exactly 16 bytes', () => {
    const bytes = uuidToBytes(TEST_UUID);
    assert.ok(bytes instanceof Uint8Array, 'should be Uint8Array');
    assert.strictEqual(bytes.length, 16);
  });

  it('encodes known UUID bytes correctly', () => {
    // 550e8400-e29b-41d4-a716-446655440000
    // hex: 550e8400 e29b 41d4 a716 446655440000
    const bytes = uuidToBytes(TEST_UUID);
    assert.strictEqual(bytes[0], 0x55);
    assert.strictEqual(bytes[1], 0x0e);
    assert.strictEqual(bytes[2], 0x84);
    assert.strictEqual(bytes[3], 0x00);
    assert.strictEqual(bytes[4], 0xe2);
    assert.strictEqual(bytes[5], 0x9b);
    assert.strictEqual(bytes[6], 0x41);
    assert.strictEqual(bytes[7], 0xd4);
    assert.strictEqual(bytes[8], 0xa7);
    assert.strictEqual(bytes[9], 0x16);
    assert.strictEqual(bytes[10], 0x44);
    assert.strictEqual(bytes[11], 0x66);
    assert.strictEqual(bytes[12], 0x55);
    assert.strictEqual(bytes[13], 0x44);
    assert.strictEqual(bytes[14], 0x00);
    assert.strictEqual(bytes[15], 0x00);
  });

  it('handles all-zero UUID', () => {
    const bytes = uuidToBytes('00000000-0000-0000-0000-000000000000');
    assert.ok(bytes.every(b => b === 0));
  });

  it('handles all-ff UUID', () => {
    const bytes = uuidToBytes('ffffffff-ffff-ffff-ffff-ffffffffffff');
    assert.ok(bytes.every(b => b === 0xff));
  });

  it('handles mixed-case hex digits', () => {
    const lower = uuidToBytes('aabbccdd-eeff-1122-3344-556677889900');
    const upper = uuidToBytes('AABBCCDD-EEFF-1122-3344-556677889900');
    assert.deepStrictEqual(lower, upper);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. bytesToUuid
// ═══════════════════════════════════════════════════════════════════════════

describe('bytesToUuid', () => {
  it('returns a string in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format', () => {
    const bytes = uuidToBytes(TEST_UUID);
    const result = bytesToUuid(bytes);
    assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(result),
      `UUID format mismatch: ${result}`);
  });

  it('produces lowercase hex', () => {
    const bytes = new Uint8Array(16).fill(0xab);
    const result = bytesToUuid(bytes);
    assert.strictEqual(result, result.toLowerCase());
  });

  it('all-zero bytes yield all-zero UUID', () => {
    const result = bytesToUuid(new Uint8Array(16));
    assert.strictEqual(result, '00000000-0000-0000-0000-000000000000');
  });

  it('all-0xff bytes yield all-f UUID', () => {
    const result = bytesToUuid(new Uint8Array(16).fill(0xff));
    assert.strictEqual(result, 'ffffffff-ffff-ffff-ffff-ffffffffffff');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. uuidToBytes / bytesToUuid round-trip
// ═══════════════════════════════════════════════════════════════════════════

describe('UUID round-trip', () => {
  it('bytesToUuid(uuidToBytes(uuid)) === uuid (lowercase)', () => {
    const result = bytesToUuid(uuidToBytes(TEST_UUID));
    assert.strictEqual(result, TEST_UUID.toLowerCase());
  });

  it('round-trips multiple UUIDs', () => {
    const uuids = [
      '00000000-0000-0000-0000-000000000000',
      'ffffffff-ffff-ffff-ffff-ffffffffffff',
      '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
      '6ba7b811-9dad-11d1-80b4-00c04fd430c8',
    ];
    for (const uuid of uuids) {
      assert.strictEqual(bytesToUuid(uuidToBytes(uuid)), uuid.toLowerCase(),
        `round-trip failed for ${uuid}`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. encodeChunkHeader
// ═══════════════════════════════════════════════════════════════════════════

describe('encodeChunkHeader', () => {
  const baseParams = {
    transferId: TEST_UUID,
    chunkIndex: 0,
    byteOffset: 0n,
    chunkSize: 65536,
    isFinal: false,
  };

  it('returns a Uint8Array of exactly 64 bytes', () => {
    const header = encodeChunkHeader(baseParams);
    assert.ok(header instanceof Uint8Array, 'should be Uint8Array');
    assert.strictEqual(header.length, 64);
  });

  it('byte 0 is always 0x01 (chunk type)', () => {
    const header = encodeChunkHeader(baseParams);
    assert.strictEqual(header[0], 0x01);
  });

  it('bytes 1-16 encode the transferId UUID', () => {
    const header = encodeChunkHeader(baseParams);
    const expectedBytes = uuidToBytes(TEST_UUID);
    const actual = header.slice(1, 17);
    assert.deepStrictEqual(actual, expectedBytes);
  });

  it('bytes 17-20 encode chunkIndex as uint32 big-endian', () => {
    const header = encodeChunkHeader({ ...baseParams, chunkIndex: 0x01020304 });
    const view = new DataView(header.buffer);
    assert.strictEqual(view.getUint32(17, false), 0x01020304);
  });

  it('bytes 21-28 encode byteOffset as uint64 big-endian (BigInt)', () => {
    const offset = 0x0102030405060708n;
    const header = encodeChunkHeader({ ...baseParams, byteOffset: offset });
    const view = new DataView(header.buffer);
    assert.strictEqual(view.getBigUint64(21, false), offset);
  });

  it('bytes 29-32 encode chunkSize as uint32 big-endian', () => {
    const header = encodeChunkHeader({ ...baseParams, chunkSize: 0xdeadbeef });
    const view = new DataView(header.buffer);
    assert.strictEqual(view.getUint32(29, false), 0xdeadbeef);
  });

  it('byte 33: bit 0 clear when isFinal is false', () => {
    const header = encodeChunkHeader({ ...baseParams, isFinal: false });
    assert.strictEqual(header[33] & 0x01, 0);
  });

  it('byte 33: bit 0 set when isFinal is true', () => {
    const header = encodeChunkHeader({ ...baseParams, isFinal: true });
    assert.strictEqual(header[33] & 0x01, 1);
  });

  it('bytes 34-63 (reserved) are all zero', () => {
    const header = encodeChunkHeader({ ...baseParams, isFinal: true });
    for (let i = 34; i < 64; i++) {
      assert.strictEqual(header[i], 0, `reserved byte ${i} should be 0`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. decodeChunkHeader
// ═══════════════════════════════════════════════════════════════════════════

describe('decodeChunkHeader', () => {
  it('returns an object with the correct shape', () => {
    const header = encodeChunkHeader({
      transferId: TEST_UUID,
      chunkIndex: 1,
      byteOffset: 65536n,
      chunkSize: 65536,
      isFinal: false,
    });
    const decoded = decodeChunkHeader(header);
    assert.ok(typeof decoded === 'object' && decoded !== null);
    assert.ok('type' in decoded, 'missing .type');
    assert.ok('transferId' in decoded, 'missing .transferId');
    assert.ok('chunkIndex' in decoded, 'missing .chunkIndex');
    assert.ok('byteOffset' in decoded, 'missing .byteOffset');
    assert.ok('chunkSize' in decoded, 'missing .chunkSize');
    assert.ok('isFinal' in decoded, 'missing .isFinal');
  });

  it('type is 0x01', () => {
    const header = encodeChunkHeader({
      transferId: TEST_UUID, chunkIndex: 0, byteOffset: 0n, chunkSize: 1, isFinal: false,
    });
    assert.strictEqual(decodeChunkHeader(header).type, 0x01);
  });

  it('byteOffset is a BigInt', () => {
    const header = encodeChunkHeader({
      transferId: TEST_UUID, chunkIndex: 0, byteOffset: 0n, chunkSize: 1, isFinal: false,
    });
    assert.strictEqual(typeof decodeChunkHeader(header).byteOffset, 'bigint');
  });

  it('isFinal is a boolean', () => {
    const header = encodeChunkHeader({
      transferId: TEST_UUID, chunkIndex: 0, byteOffset: 0n, chunkSize: 1, isFinal: true,
    });
    assert.strictEqual(typeof decodeChunkHeader(header).isFinal, 'boolean');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. encodeChunkHeader / decodeChunkHeader round-trips
// ═══════════════════════════════════════════════════════════════════════════

describe('chunk header round-trip', () => {
  /**
   * Encode then decode a set of params and verify all fields survive intact.
   * @param {object} params
   */
  function assertRoundTrip(params) {
    const header = encodeChunkHeader(params);
    const decoded = decodeChunkHeader(header);

    assert.strictEqual(decoded.type, 0x01, 'type should always be 0x01');
    assert.strictEqual(decoded.transferId.toLowerCase(), params.transferId.toLowerCase(),
      'transferId mismatch');
    assert.strictEqual(decoded.chunkIndex, params.chunkIndex, 'chunkIndex mismatch');
    assert.strictEqual(decoded.byteOffset, BigInt(params.byteOffset), 'byteOffset mismatch');
    assert.strictEqual(decoded.chunkSize, params.chunkSize, 'chunkSize mismatch');
    assert.strictEqual(decoded.isFinal, params.isFinal, 'isFinal mismatch');
  }

  it('round-trips a basic chunk (index 0, not final)', () => {
    assertRoundTrip({
      transferId: TEST_UUID,
      chunkIndex: 0,
      byteOffset: 0n,
      chunkSize: 65536,
      isFinal: false,
    });
  });

  it('round-trips the final chunk flag', () => {
    assertRoundTrip({
      transferId: TEST_UUID,
      chunkIndex: 99,
      byteOffset: 6488064n,
      chunkSize: 4096,
      isFinal: true,
    });
  });

  it('round-trips a large byteOffset (> 32-bit range)', () => {
    assertRoundTrip({
      transferId: TEST_UUID,
      chunkIndex: 100000,
      byteOffset: 6_871_947_674_112n,  // ~6.25 TiB
      chunkSize: 65536,
      isFinal: false,
    });
  });

  it('round-trips maximum safe uint32 chunkIndex', () => {
    assertRoundTrip({
      transferId: TEST_UUID,
      chunkIndex: 0xffffffff,
      byteOffset: 0n,
      chunkSize: 1,
      isFinal: false,
    });
  });

  it('round-trips maximum uint32 chunkSize', () => {
    assertRoundTrip({
      transferId: TEST_UUID,
      chunkIndex: 0,
      byteOffset: 0n,
      chunkSize: 0xffffffff,
      isFinal: false,
    });
  });

  it('round-trips a large uint64 byteOffset at near-maximum value', () => {
    // 2^53 - 1 is the max safe integer; BigInt can go higher
    const hugeOffset = 9_007_199_254_740_992n; // 2^53
    assertRoundTrip({
      transferId: TEST_UUID,
      chunkIndex: 0,
      byteOffset: hugeOffset,
      chunkSize: 65536,
      isFinal: false,
    });
  });

  it('round-trips all-zero UUID', () => {
    assertRoundTrip({
      transferId: '00000000-0000-0000-0000-000000000000',
      chunkIndex: 1,
      byteOffset: 1n,
      chunkSize: 1,
      isFinal: true,
    });
  });

  it('round-trips all-f UUID', () => {
    assertRoundTrip({
      transferId: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
      chunkIndex: 0,
      byteOffset: 0n,
      chunkSize: 512,
      isFinal: false,
    });
  });

  it('isFinal=false does not bleed into isFinal=true on consecutive encodes', () => {
    const paramsA = {
      transferId: TEST_UUID, chunkIndex: 0, byteOffset: 0n, chunkSize: 1, isFinal: false,
    };
    const paramsB = {
      transferId: TEST_UUID, chunkIndex: 1, byteOffset: 1n, chunkSize: 1, isFinal: true,
    };
    const headerA = encodeChunkHeader(paramsA);
    const headerB = encodeChunkHeader(paramsB);
    assert.strictEqual(decodeChunkHeader(headerA).isFinal, false);
    assert.strictEqual(decodeChunkHeader(headerB).isFinal, true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. decodeChunkHeader with ArrayBuffer input
// ═══════════════════════════════════════════════════════════════════════════

describe('decodeChunkHeader accepts ArrayBuffer', () => {
  it('decodes correctly when passed an ArrayBuffer (not Uint8Array)', () => {
    const params = {
      transferId: TEST_UUID,
      chunkIndex: 42,
      byteOffset: 2_097_152n,
      chunkSize: 32768,
      isFinal: true,
    };
    const uint8 = encodeChunkHeader(params);
    // Pass the underlying ArrayBuffer directly
    const decoded = decodeChunkHeader(uint8.buffer);
    assert.strictEqual(decoded.chunkIndex, 42);
    assert.strictEqual(decoded.byteOffset, 2_097_152n);
    assert.strictEqual(decoded.isFinal, true);
  });
});
