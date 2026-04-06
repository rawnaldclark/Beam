/**
 * @file wire-format.js
 * @description Binary wire-format helpers for Beam chunk headers.
 *
 * Chunk header layout — 64 bytes total:
 *
 *   Offset  Len  Field        Encoding
 *   ------  ---  -----------  -------------------------
 *    [0]      1  type         0x01 for chunk
 *    [1-16]  16  transferId   UUID as raw bytes (strip hyphens, parse hex)
 *   [17-20]   4  chunkIndex   uint32 big-endian
 *   [21-28]   8  byteOffset   uint64 big-endian (BigInt)
 *   [29-32]   4  chunkSize    uint32 big-endian
 *    [33]     1  flags        bit 0 = isFinal
 *   [34-63]  30  reserved     zeros
 *
 * Design notes:
 *   - byteOffset uses BigInt / DataView.getBigUint64 to avoid precision loss
 *     on offsets > 2^53 (files larger than ~8 PiB would overflow a JS number).
 *   - All multi-byte fields are big-endian (network byte order).
 *   - The reserved bytes are always written as zeros; decoders must ignore them
 *     to allow future backwards-compatible header extensions.
 *
 * @module offscreen/wire-format
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Byte length of every chunk header. */
const HEADER_SIZE = 64;

/** Type byte value identifying a data chunk. */
const CHUNK_TYPE = 0x01;

// ---------------------------------------------------------------------------
// UUID helpers
// ---------------------------------------------------------------------------

/**
 * Convert a hyphenated UUID string to a 16-byte Uint8Array.
 *
 * The hyphens are stripped and each pair of hex characters is parsed into
 * a single byte.  Input is case-insensitive.
 *
 * @param {string} uuidString - UUID in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format.
 * @returns {Uint8Array} 16-byte representation of the UUID.
 * @example
 *   uuidToBytes('550e8400-e29b-41d4-a716-446655440000')
 *   // → Uint8Array [ 0x55, 0x0e, 0x84, 0x00, ... ]
 */
export function uuidToBytes(uuidString) {
  // Strip all hyphens to get a contiguous 32-character hex string.
  const hex = uuidString.replace(/-/g, '');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert a 16-byte Uint8Array back to a hyphenated UUID string.
 *
 * The output is always lowercase with hyphens inserted at the standard
 * positions: 8-4-4-4-12.
 *
 * @param {Uint8Array} bytes - 16-byte UUID bytes.
 * @returns {string} UUID in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format.
 * @example
 *   bytesToUuid(new Uint8Array([0x55, 0x0e, 0x84, 0x00, ...]))
 *   // → '550e8400-e29b-41d4-a716-446655440000'
 */
export function bytesToUuid(bytes) {
  // Build a 32-character hex string then insert hyphens.
  let hex = '';
  for (let i = 0; i < 16; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  // Insert hyphens at positions 8, 12, 16, 20 (standard UUID group boundaries).
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ---------------------------------------------------------------------------
// Chunk header encode / decode
// ---------------------------------------------------------------------------

/**
 * Encode a chunk header into a 64-byte Uint8Array.
 *
 * @param {object}  params
 * @param {string}  params.transferId  - UUID string identifying the transfer.
 * @param {number}  params.chunkIndex  - Non-negative uint32 index of this chunk.
 * @param {bigint}  params.byteOffset  - Byte offset of this chunk within the file (BigInt).
 * @param {number}  params.chunkSize   - Byte length of this chunk's payload (uint32).
 * @param {boolean} params.isFinal     - True if this is the last chunk in the transfer.
 * @returns {Uint8Array} 64-byte serialised chunk header.
 *
 * @example
 *   const header = encodeChunkHeader({
 *     transferId: '550e8400-e29b-41d4-a716-446655440000',
 *     chunkIndex: 0,
 *     byteOffset: 0n,
 *     chunkSize: 65536,
 *     isFinal: false,
 *   });
 */
export function encodeChunkHeader({ transferId, chunkIndex, byteOffset, chunkSize, isFinal }) {
  const buffer = new ArrayBuffer(HEADER_SIZE);
  const view   = new DataView(buffer);
  const bytes  = new Uint8Array(buffer);

  // [0] type — always 0x01 for a data chunk
  view.setUint8(0, CHUNK_TYPE);

  // [1-16] transferId — 16 raw UUID bytes
  const idBytes = uuidToBytes(transferId);
  bytes.set(idBytes, 1);

  // [17-20] chunkIndex — uint32 big-endian
  view.setUint32(17, chunkIndex, /* littleEndian= */ false);

  // [21-28] byteOffset — uint64 big-endian (BigInt)
  view.setBigUint64(21, BigInt(byteOffset), /* littleEndian= */ false);

  // [29-32] chunkSize — uint32 big-endian
  view.setUint32(29, chunkSize, /* littleEndian= */ false);

  // [33] flags — bit 0 is the isFinal flag; all other bits are 0
  view.setUint8(33, isFinal ? 0x01 : 0x00);

  // [34-63] reserved — already zero (ArrayBuffer is zero-initialised)

  return bytes;
}

/**
 * Decode a 64-byte chunk header from a Uint8Array or ArrayBuffer.
 *
 * @param {Uint8Array | ArrayBuffer} buffer - 64-byte header to decode.
 * @returns {{
 *   type:        number,
 *   transferId:  string,
 *   chunkIndex:  number,
 *   byteOffset:  bigint,
 *   chunkSize:   number,
 *   isFinal:     boolean,
 * }} Parsed header fields.
 *
 * @example
 *   const { transferId, chunkIndex, byteOffset, isFinal } = decodeChunkHeader(rawBytes);
 */
export function decodeChunkHeader(buffer) {
  // Accept either a Uint8Array (with a possible byteOffset into its ArrayBuffer)
  // or a plain ArrayBuffer.
  let view;
  let bytes;
  if (buffer instanceof Uint8Array) {
    view  = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    bytes = buffer;
  } else {
    // Assume ArrayBuffer
    view  = new DataView(buffer);
    bytes = new Uint8Array(buffer);
  }

  // [0] type
  const type = view.getUint8(0);

  // [1-16] transferId — 16 UUID bytes → hyphenated string
  const idBytes    = bytes.slice(bytes.byteOffset === 0 ? 1 : 1, 17);
  // When wrapping an ArrayBuffer, bytes is already a flat view; for a Uint8Array
  // with non-zero byteOffset we need to account for that.  Use the DataView
  // byte-at-a-time path for correctness.
  const idRaw      = new Uint8Array(16);
  for (let i = 0; i < 16; i++) idRaw[i] = view.getUint8(1 + i);
  const transferId = bytesToUuid(idRaw);

  // [17-20] chunkIndex — uint32 big-endian
  const chunkIndex = view.getUint32(17, /* littleEndian= */ false);

  // [21-28] byteOffset — uint64 big-endian (BigInt)
  const byteOffset = view.getBigUint64(21, /* littleEndian= */ false);

  // [29-32] chunkSize — uint32 big-endian
  const chunkSize  = view.getUint32(29, /* littleEndian= */ false);

  // [33] flags — bit 0 is isFinal
  const flags      = view.getUint8(33);
  const isFinal    = Boolean(flags & 0x01);

  return { type, transferId, chunkIndex, byteOffset, chunkSize, isFinal };
}
