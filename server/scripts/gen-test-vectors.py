#!/usr/bin/env python3
"""
Beam crypto test vector generator.

Produces server/test-vectors/crypto-v1.json containing fixed-input, known-output
values for the Triple-DH handshake, HKDF derivations, and XChaCha20-Poly1305
AEAD operations specified in docs/superpowers/specs/2026-04-10-e2e-encryption-design.md.

Both the Chrome and Android crypto modules MUST load this file in their test
suites and assert byte-exact equality. If this script changes, both clients'
implementations must be updated in lockstep.

Run:
    python server/scripts/gen-test-vectors.py

Dependencies:
    pip install pynacl
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from pathlib import Path

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_scalarmult,
    crypto_scalarmult_base,
)


# ---------------------------------------------------------------------------
# Fixed inputs
# ---------------------------------------------------------------------------

# Long-term X25519 identity private keys (32 bytes each).
STATIC_SK_A = bytes.fromhex(
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)
STATIC_SK_B = bytes.fromhex(
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
)

# Per-transfer ephemeral X25519 private keys (32 bytes each).
EPH_SK_A = bytes.fromhex(
    "1011121314151617184192a3b4c5d6e7"
    "0001020304050607f8e9dacbbcad9e8f"
)
EPH_SK_B = bytes.fromhex(
    "2021222324252627281131425364758a"
    "9988776655443322112233445566778f"
)

# Handshake parameters.
VERSION = 1
SALT = bytes.fromhex(
    "5a1750d1a2b3c4d5e6f708192a3b4c5d"
    "6e7f8091a2b3c4d5e6f708192a3b4c5d"
)
TRANSFER_ID = bytes.fromhex("11223344556677889900aabbccddeeff")

# Sample plaintexts.
CLIPBOARD_PLAINTEXT = b"Hello from Beam - the quick brown fox jumps over the lazy dog."

FILE_METADATA_JSON = (
    '{"fileName":"vacation-photo.jpg",'
    '"fileSize":614400,'
    '"mime":"image/jpeg",'
    '"totalChunks":3}'
).encode("utf-8")

# Three file chunks of varying sizes to exercise padding.
CHUNK_SIZE = 200 * 1024
FILE_CHUNK_1 = bytes(((i * 37 + 13) & 0xFF) for i in range(CHUNK_SIZE))  # full 200KB
FILE_CHUNK_2 = bytes(((i * 91 + 7) & 0xFF) for i in range(CHUNK_SIZE))   # full 200KB
FILE_CHUNK_3 = bytes(((i * 53 + 29) & 0xFF) for i in range(12345))       # partial (final)

TOTAL_CHUNKS = 3

# Kind bytes per spec.
KIND_CLIPBOARD = 0x01
KIND_FILE_METADATA = 0x02
KIND_FILE_CHUNK = 0x03


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def x25519(sk: bytes, pk: bytes) -> bytes:
    return crypto_scalarmult(sk, pk)


def x25519_base(sk: bytes) -> bytes:
    return crypto_scalarmult_base(sk)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # RFC 5869 Extract
    if not salt:
        salt = b"\x00" * 32
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 Expand
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


# ---------------------------------------------------------------------------
# Beam-specific derivations (per spec)
# ---------------------------------------------------------------------------

def compute_transcript(
    version: int,
    static_pk_a: bytes,
    static_pk_b: bytes,
    eph_pk_a: bytes,
    eph_pk_b: bytes,
    transfer_id: bytes,
) -> bytes:
    """SHA-256('beam-transcript-v1' || u8(version) || staticPkA || staticPkB || ephPkA || ephPkB || transferId)"""
    buf = (
        b"beam-transcript-v1"
        + bytes([version])
        + static_pk_a
        + static_pk_b
        + eph_pk_a
        + eph_pk_b
        + transfer_id
    )
    return sha256(buf)


def compute_triple_dh_initiator(
    static_sk_a: bytes,
    eph_sk_a: bytes,
    static_pk_b: bytes,
    eph_pk_b: bytes,
) -> tuple[bytes, bytes, bytes]:
    dh1 = x25519(static_sk_a, eph_pk_b)   # initiator static × responder ephemeral
    dh2 = x25519(eph_sk_a, static_pk_b)   # initiator ephemeral × responder static
    dh3 = x25519(eph_sk_a, eph_pk_b)      # ephemeral × ephemeral
    return dh1, dh2, dh3


def compute_triple_dh_responder(
    static_sk_b: bytes,
    eph_sk_b: bytes,
    static_pk_a: bytes,
    eph_pk_a: bytes,
) -> tuple[bytes, bytes, bytes]:
    # Responder computes the mirror; must produce byte-identical dh1/dh2/dh3.
    dh1 = x25519(eph_sk_b, static_pk_a)
    dh2 = x25519(static_sk_b, eph_pk_a)
    dh3 = x25519(eph_sk_b, eph_pk_a)
    return dh1, dh2, dh3


def derive_session_key(ikm: bytes, salt: bytes, transcript: bytes) -> bytes:
    prk = hkdf_extract(salt, ikm)
    info = b"beam-session-v1" + transcript
    return hkdf_expand(prk, info, 32)


def derive_chunk_key(session_key: bytes) -> bytes:
    # Re-extract with session_key as PRK-equivalent via HKDF-Expand only.
    return hkdf_expand(session_key, b"beam-chunk-v1", 32)


def derive_meta_key(session_key: bytes) -> bytes:
    return hkdf_expand(session_key, b"beam-meta-v1", 32)


def derive_nonce(chunk_key: bytes, index: int) -> bytes:
    """HMAC-SHA256(chunkKey, 'beam-nonce-v1' || u64_be(index))[0..24]"""
    mac = hmac_sha256(chunk_key, b"beam-nonce-v1" + struct.pack(">Q", index))
    return mac[:24]


def build_aad(
    kind_byte: int,
    index: int,
    total_chunks: int,
    transcript: bytes,
) -> bytes:
    return (
        b"beam-aead-v1"
        + bytes([kind_byte])
        + struct.pack(">I", index)
        + struct.pack(">I", total_chunks)
        + transcript
    )


def next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


def pad_plaintext(data: bytes) -> bytes:
    """u32_be(actual_len) || data || zero_pad to next power-of-two bucket."""
    raw_len = len(data)
    prefixed_len = 4 + raw_len
    bucket = next_power_of_two(max(prefixed_len, 64))  # floor of 64 bytes
    pad = bucket - prefixed_len
    return struct.pack(">I", raw_len) + data + (b"\x00" * pad)


def unpad_plaintext(padded: bytes) -> bytes:
    raw_len = struct.unpack(">I", padded[:4])[0]
    return padded[4 : 4 + raw_len]


def aead_encrypt(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def aead_decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


# ---------------------------------------------------------------------------
# Vector generation
# ---------------------------------------------------------------------------

def hx(b: bytes) -> str:
    return b.hex()


def generate() -> dict:
    static_pk_a = x25519_base(STATIC_SK_A)
    static_pk_b = x25519_base(STATIC_SK_B)
    eph_pk_a = x25519_base(EPH_SK_A)
    eph_pk_b = x25519_base(EPH_SK_B)

    # Triple-DH from both sides (must match).
    dh_a = compute_triple_dh_initiator(STATIC_SK_A, EPH_SK_A, static_pk_b, eph_pk_b)
    dh_b = compute_triple_dh_responder(STATIC_SK_B, EPH_SK_B, static_pk_a, eph_pk_a)
    assert dh_a == dh_b, "Triple-DH mismatch between initiator and responder perspectives"
    dh1, dh2, dh3 = dh_a

    ikm = dh1 + dh2 + dh3

    transcript = compute_transcript(
        VERSION, static_pk_a, static_pk_b, eph_pk_a, eph_pk_b, TRANSFER_ID
    )

    session_key = derive_session_key(ikm, SALT, transcript)
    chunk_key = derive_chunk_key(session_key)
    meta_key = derive_meta_key(session_key)

    # Clipboard: single sealed chunk at index 0, totalChunks 1.
    clip_padded = pad_plaintext(CLIPBOARD_PLAINTEXT)
    clip_nonce = derive_nonce(chunk_key, 0)
    clip_aad = build_aad(KIND_CLIPBOARD, 0, 1, transcript)
    clip_ct = aead_encrypt(clip_padded, chunk_key, clip_nonce, clip_aad)
    # Verify round-trip.
    assert unpad_plaintext(aead_decrypt(clip_ct, chunk_key, clip_nonce, clip_aad)) == CLIPBOARD_PLAINTEXT

    # File metadata: index 0 under meta_key, kind 0x02, totalChunks=0 in AAD (header, not a data chunk).
    meta_padded = pad_plaintext(FILE_METADATA_JSON)
    meta_nonce = derive_nonce(meta_key, 0)
    meta_aad = build_aad(KIND_FILE_METADATA, 0, 0, transcript)
    meta_ct = aead_encrypt(meta_padded, meta_key, meta_nonce, meta_aad)
    assert unpad_plaintext(aead_decrypt(meta_ct, meta_key, meta_nonce, meta_aad)) == FILE_METADATA_JSON

    # File chunks: index 1..N under chunk_key, kind 0x03, totalChunks=N.
    chunks_out = []
    for i, chunk in enumerate([FILE_CHUNK_1, FILE_CHUNK_2, FILE_CHUNK_3], start=1):
        padded = pad_plaintext(chunk)
        nonce = derive_nonce(chunk_key, i)
        aad = build_aad(KIND_FILE_CHUNK, i, TOTAL_CHUNKS, transcript)
        ct = aead_encrypt(padded, chunk_key, nonce, aad)
        assert unpad_plaintext(aead_decrypt(ct, chunk_key, nonce, aad)) == chunk
        chunks_out.append(
            {
                "index": i,
                "plaintextSha256": hx(sha256(chunk)),
                "plaintextLen": len(chunk),
                "paddedLen": len(padded),
                "nonce": hx(nonce),
                "aad": hx(aad),
                "ciphertextSha256": hx(sha256(ct)),
                "ciphertextLen": len(ct),
            }
        )

    return {
        "version": VERSION,
        "spec": "docs/superpowers/specs/2026-04-10-e2e-encryption-design.md",
        "generator": "server/scripts/gen-test-vectors.py",
        "inputs": {
            "staticSkA": hx(STATIC_SK_A),
            "staticPkA": hx(static_pk_a),
            "staticSkB": hx(STATIC_SK_B),
            "staticPkB": hx(static_pk_b),
            "ephSkA": hx(EPH_SK_A),
            "ephPkA": hx(eph_pk_a),
            "ephSkB": hx(EPH_SK_B),
            "ephPkB": hx(eph_pk_b),
            "salt": hx(SALT),
            "transferId": hx(TRANSFER_ID),
        },
        "tripleDH": {
            "dh1": hx(dh1),
            "dh2": hx(dh2),
            "dh3": hx(dh3),
            "ikm": hx(ikm),
        },
        "transcript": hx(transcript),
        "keys": {
            "sessionKey": hx(session_key),
            "chunkKey": hx(chunk_key),
            "metaKey": hx(meta_key),
        },
        "clipboard": {
            "plaintext": hx(CLIPBOARD_PLAINTEXT),
            "plaintextLen": len(CLIPBOARD_PLAINTEXT),
            "paddedLen": len(clip_padded),
            "kindByte": KIND_CLIPBOARD,
            "index": 0,
            "totalChunks": 1,
            "nonce": hx(clip_nonce),
            "aad": hx(clip_aad),
            "ciphertext": hx(clip_ct),
        },
        "fileMetadata": {
            "plaintext": hx(FILE_METADATA_JSON),
            "plaintextLen": len(FILE_METADATA_JSON),
            "paddedLen": len(meta_padded),
            "kindByte": KIND_FILE_METADATA,
            "index": 0,
            "totalChunks": 0,
            "nonce": hx(meta_nonce),
            "aad": hx(meta_aad),
            "ciphertext": hx(meta_ct),
        },
        "fileChunks": {
            "chunkSize": CHUNK_SIZE,
            "totalChunks": TOTAL_CHUNKS,
            "kindByte": KIND_FILE_CHUNK,
            "chunks": chunks_out,
        },
    }


def main() -> None:
    out_path = Path(__file__).resolve().parent.parent / "test-vectors" / "crypto-v1.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    vectors = generate()
    out_path.write_text(json.dumps(vectors, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"  sessionKey: {vectors['keys']['sessionKey']}")
    print(f"  transcript: {vectors['transcript']}")


if __name__ == "__main__":
    main()
