package com.zaptransfer.android.crypto

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Beam E2E encryption — spec-compliant cipher for Android.
 *
 * Mirrors `extension/crypto/beam-crypto.js` byte-for-byte. Both sides MUST
 * reproduce the canonical test vectors at `server/test-vectors/crypto-v1.json`,
 * which are loaded from resources by `BeamCipherTest`.
 *
 * This class is stateless — it holds key material only transiently inside
 * method scopes. Session lifetime is managed by the (upcoming) SessionRegistry
 * and BeamHandshake classes.
 *
 * NOTE: the legacy [SessionCipher] in this package predates the Beam v1 spec
 * and is retained only so that the unused TransferEngine keeps compiling.
 * All new code must use [BeamCipher].
 */
class BeamCipher(
    private val sodium: LazySodium = LazySodiumAndroid(SodiumAndroid()),
) {

    // -------------------------------------------------------------------------
    // Constants (must match beam-crypto.js exactly)
    // -------------------------------------------------------------------------

    companion object {
        const val PROTOCOL_VERSION: Int = 1

        const val KIND_CLIPBOARD: Int = 0x01
        const val KIND_FILE_METADATA: Int = 0x02
        const val KIND_FILE_CHUNK: Int = 0x03

        const val XCHACHA20_NONCE_BYTES: Int = 24
        const val XCHACHA20_KEY_BYTES: Int = 32
        const val POLY1305_TAG_BYTES: Int = 16

        private const val PADDING_FLOOR_BYTES: Int = 64

        private val LABEL_TRANSCRIPT = "beam-transcript-v1".toByteArray(Charsets.UTF_8)
        private val LABEL_SESSION    = "beam-session-v1".toByteArray(Charsets.UTF_8)
        private val LABEL_CHUNK      = "beam-chunk-v1".toByteArray(Charsets.UTF_8)
        private val LABEL_META       = "beam-meta-v1".toByteArray(Charsets.UTF_8)
        private val LABEL_NONCE      = "beam-nonce-v1".toByteArray(Charsets.UTF_8)
        private val LABEL_AEAD       = "beam-aead-v1".toByteArray(Charsets.UTF_8)
    }

    // -------------------------------------------------------------------------
    // Byte helpers
    // -------------------------------------------------------------------------

    private fun concat(vararg parts: ByteArray): ByteArray {
        val total = parts.sumOf { it.size }
        val out = ByteArray(total)
        var off = 0
        for (p in parts) {
            p.copyInto(out, off)
            off += p.size
        }
        return out
    }

    private fun u8(n: Int): ByteArray = byteArrayOf((n and 0xff).toByte())

    private fun u32be(n: Int): ByteArray {
        val out = ByteArray(4)
        out[0] = ((n ushr 24) and 0xff).toByte()
        out[1] = ((n ushr 16) and 0xff).toByte()
        out[2] = ((n ushr 8) and 0xff).toByte()
        out[3] = (n and 0xff).toByte()
        return out
    }

    private fun u64be(n: Long): ByteArray {
        val out = ByteArray(8)
        var v = n
        for (i in 7 downTo 0) {
            out[i] = (v and 0xff).toByte()
            v = v ushr 8
        }
        return out
    }

    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun nextPowerOfTwo(n: Int): Int {
        if (n <= 1) return 1
        var p = 1
        while (p < n) p = p shl 1
        return p
    }

    // -------------------------------------------------------------------------
    // HKDF-SHA256 (RFC 5869)
    // -------------------------------------------------------------------------

    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val saltBytes = if (salt.isNotEmpty()) salt else ByteArray(32)
        return hmacSha256(saltBytes, ikm)
    }

    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(32 * 255)) { "HKDF output length out of range: $length" }
        val out = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val input = concat(t, info, u8(counter))
            t = hmacSha256(prk, input)
            val take = minOf(t.size, length - offset)
            t.copyInto(out, offset, 0, take)
            offset += take
            counter += 1
        }
        return out
    }

    // -------------------------------------------------------------------------
    // X25519 and Triple-DH
    // -------------------------------------------------------------------------

    fun x25519(sk: ByteArray, peerPk: ByteArray): ByteArray {
        require(sk.size == 32) { "sk must be 32 bytes, got ${sk.size}" }
        require(peerPk.size == 32) { "peerPk must be 32 bytes, got ${peerPk.size}" }
        val out = ByteArray(32)
        val success = sodium.cryptoScalarMult(out, sk, peerPk)
        check(success) { "X25519 scalar multiplication failed" }
        return out
    }

    fun x25519PublicKey(sk: ByteArray): ByteArray {
        require(sk.size == 32) { "sk must be 32 bytes, got ${sk.size}" }
        val out = ByteArray(32)
        val success = sodium.cryptoScalarMultBase(out, sk)
        check(success) { "X25519 base scalar multiplication failed" }
        return out
    }

    data class TripleDH(
        val dh1: ByteArray,
        val dh2: ByteArray,
        val dh3: ByteArray,
        val ikm: ByteArray,
    )

    /**
     * Triple-DH from the initiator's perspective.
     * Both sides MUST concatenate dh1 || dh2 || dh3 in this order.
     */
    fun computeTripleDHInitiator(
        staticSkA: ByteArray,
        ephSkA: ByteArray,
        staticPkB: ByteArray,
        ephPkB: ByteArray,
    ): TripleDH {
        val dh1 = x25519(staticSkA, ephPkB)   // initiator static × responder ephemeral
        val dh2 = x25519(ephSkA,    staticPkB) // initiator ephemeral × responder static
        val dh3 = x25519(ephSkA,    ephPkB)    // ephemeral × ephemeral
        return TripleDH(dh1, dh2, dh3, concat(dh1, dh2, dh3))
    }

    /**
     * Triple-DH from the responder's perspective. Produces byte-identical
     * dh1/dh2/dh3 to [computeTripleDHInitiator].
     */
    fun computeTripleDHResponder(
        staticSkB: ByteArray,
        ephSkB: ByteArray,
        staticPkA: ByteArray,
        ephPkA: ByteArray,
    ): TripleDH {
        val dh1 = x25519(ephSkB,    staticPkA)
        val dh2 = x25519(staticSkB, ephPkA)
        val dh3 = x25519(ephSkB,    ephPkA)
        return TripleDH(dh1, dh2, dh3, concat(dh1, dh2, dh3))
    }

    // -------------------------------------------------------------------------
    // Transcript hash and key derivation
    // -------------------------------------------------------------------------

    fun computeTranscript(
        version: Int,
        staticPkA: ByteArray,
        staticPkB: ByteArray,
        ephPkA: ByteArray,
        ephPkB: ByteArray,
        transferId: ByteArray,
    ): ByteArray {
        val buf = concat(
            LABEL_TRANSCRIPT,
            u8(version),
            staticPkA,
            staticPkB,
            ephPkA,
            ephPkB,
            transferId,
        )
        return sha256(buf)
    }

    fun deriveSessionKey(ikm: ByteArray, salt: ByteArray, transcript: ByteArray): ByteArray {
        val prk = hkdfExtract(salt, ikm)
        val info = concat(LABEL_SESSION, transcript)
        return hkdfExpand(prk, info, 32)
    }

    fun deriveChunkKey(sessionKey: ByteArray): ByteArray {
        require(sessionKey.size == 32) { "sessionKey must be 32 bytes" }
        return hkdfExpand(sessionKey, LABEL_CHUNK, 32)
    }

    fun deriveMetaKey(sessionKey: ByteArray): ByteArray {
        require(sessionKey.size == 32) { "sessionKey must be 32 bytes" }
        return hkdfExpand(sessionKey, LABEL_META, 32)
    }

    // -------------------------------------------------------------------------
    // Nonce and AAD
    // -------------------------------------------------------------------------

    /**
     * nonce(i) = HMAC-SHA256(chunkKey, "beam-nonce-v1" || u64_be(i))[0..24]
     */
    fun deriveNonce(chunkKey: ByteArray, index: Long): ByteArray {
        val mac = hmacSha256(chunkKey, concat(LABEL_NONCE, u64be(index)))
        return mac.copyOf(XCHACHA20_NONCE_BYTES)
    }

    fun buildAAD(
        kindByte: Int,
        index: Int,
        totalChunks: Int,
        transcript: ByteArray,
    ): ByteArray {
        return concat(
            LABEL_AEAD,
            u8(kindByte),
            u32be(index),
            u32be(totalChunks),
            transcript,
        )
    }

    // -------------------------------------------------------------------------
    // Padding
    // -------------------------------------------------------------------------

    fun padPlaintext(data: ByteArray): ByteArray {
        val rawLen = data.size
        val prefixedLen = 4 + rawLen
        val bucket = nextPowerOfTwo(maxOf(prefixedLen, PADDING_FLOOR_BYTES))
        val out = ByteArray(bucket)
        u32be(rawLen).copyInto(out, 0)
        data.copyInto(out, 4)
        // Remaining bytes already zero.
        return out
    }

    fun unpadPlaintext(padded: ByteArray): ByteArray {
        require(padded.size >= 4) { "padded plaintext shorter than length prefix" }
        val rawLen =
            ((padded[0].toInt() and 0xff) shl 24) or
                ((padded[1].toInt() and 0xff) shl 16) or
                ((padded[2].toInt() and 0xff) shl 8) or
                (padded[3].toInt() and 0xff)
        require(rawLen >= 0 && rawLen <= padded.size - 4) {
            "padded plaintext length prefix out of range: $rawLen"
        }
        return padded.copyOfRange(4, 4 + rawLen)
    }

    // -------------------------------------------------------------------------
    // AEAD (XChaCha20-Poly1305 IETF)
    // -------------------------------------------------------------------------

    private fun aeadEncrypt(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == XCHACHA20_KEY_BYTES) { "key must be 32 bytes" }
        require(nonce.size == XCHACHA20_NONCE_BYTES) { "nonce must be 24 bytes" }
        val ciphertext = ByteArray(plaintext.size + POLY1305_TAG_BYTES)
        val ciphertextLen = LongArray(1)
        val success = sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            ciphertext,
            ciphertextLen,
            plaintext,
            plaintext.size.toLong(),
            aad,
            aad.size.toLong(),
            null,
            nonce,
            key,
        )
        check(success) { "XChaCha20-Poly1305 encryption failed" }
        return ciphertext
    }

    private fun aeadDecrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == XCHACHA20_KEY_BYTES) { "key must be 32 bytes" }
        require(nonce.size == XCHACHA20_NONCE_BYTES) { "nonce must be 24 bytes" }
        require(ciphertext.size >= POLY1305_TAG_BYTES) { "ciphertext too short for tag" }
        val plaintext = ByteArray(ciphertext.size - POLY1305_TAG_BYTES)
        val plaintextLen = LongArray(1)
        val success = sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            plaintext,
            plaintextLen,
            null,
            ciphertext,
            ciphertext.size.toLong(),
            aad,
            aad.size.toLong(),
            nonce,
            key,
        )
        check(success) { "XChaCha20-Poly1305 authentication/decryption failed" }
        return plaintext
    }

    /**
     * Encrypt a clipboard payload. kind 0x01, index 0, totalChunks 1, chunkKey.
     */
    fun encryptClipboard(plaintext: ByteArray, chunkKey: ByteArray, transcript: ByteArray): ByteArray {
        val padded = padPlaintext(plaintext)
        val nonce = deriveNonce(chunkKey, 0L)
        val aad = buildAAD(KIND_CLIPBOARD, 0, 1, transcript)
        return aeadEncrypt(padded, chunkKey, nonce, aad)
    }

    fun decryptClipboard(ciphertext: ByteArray, chunkKey: ByteArray, transcript: ByteArray): ByteArray {
        val nonce = deriveNonce(chunkKey, 0L)
        val aad = buildAAD(KIND_CLIPBOARD, 0, 1, transcript)
        return unpadPlaintext(aeadDecrypt(ciphertext, chunkKey, nonce, aad))
    }

    /**
     * Encrypt the file-offer metadata envelope. kind 0x02, index 0, totalChunks 0, metaKey.
     */
    fun encryptFileMetadata(plaintext: ByteArray, metaKey: ByteArray, transcript: ByteArray): ByteArray {
        val padded = padPlaintext(plaintext)
        val nonce = deriveNonce(metaKey, 0L)
        val aad = buildAAD(KIND_FILE_METADATA, 0, 0, transcript)
        return aeadEncrypt(padded, metaKey, nonce, aad)
    }

    fun decryptFileMetadata(ciphertext: ByteArray, metaKey: ByteArray, transcript: ByteArray): ByteArray {
        val nonce = deriveNonce(metaKey, 0L)
        val aad = buildAAD(KIND_FILE_METADATA, 0, 0, transcript)
        return unpadPlaintext(aeadDecrypt(ciphertext, metaKey, nonce, aad))
    }

    /**
     * Encrypt a file chunk. kind 0x03, index 1..N, chunkKey.
     */
    fun encryptFileChunk(
        plaintext: ByteArray,
        chunkKey: ByteArray,
        index: Int,
        totalChunks: Int,
        transcript: ByteArray,
    ): ByteArray {
        require(index in 1..totalChunks) { "file chunk index $index not in 1..$totalChunks" }
        val padded = padPlaintext(plaintext)
        val nonce = deriveNonce(chunkKey, index.toLong())
        val aad = buildAAD(KIND_FILE_CHUNK, index, totalChunks, transcript)
        return aeadEncrypt(padded, chunkKey, nonce, aad)
    }

    fun decryptFileChunk(
        ciphertext: ByteArray,
        chunkKey: ByteArray,
        index: Int,
        totalChunks: Int,
        transcript: ByteArray,
    ): ByteArray {
        val nonce = deriveNonce(chunkKey, index.toLong())
        val aad = buildAAD(KIND_FILE_CHUNK, index, totalChunks, transcript)
        return unpadPlaintext(aeadDecrypt(ciphertext, chunkKey, nonce, aad))
    }

    // -------------------------------------------------------------------------
    // Best-effort wipe (JVM cannot guarantee zeroization — document this).
    // -------------------------------------------------------------------------

    fun wipe(vararg buffers: ByteArray?) {
        for (b in buffers) {
            if (b != null) b.fill(0)
        }
    }
}
