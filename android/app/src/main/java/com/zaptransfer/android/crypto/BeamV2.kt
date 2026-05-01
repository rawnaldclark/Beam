package com.zaptransfer.android.crypto

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Beam v2 stateless codec — Kotlin mirror of `extension/crypto/beam-v2.js`.
 *
 * Pure functions over inputs. No timers, no module state. Cross-platform
 * interop is verified by `server/test-vectors/beam-v2/`.
 *
 * Spec: docs/superpowers/specs/2026-04-30-beam-v2-design.md
 */
class BeamV2(
    private val sodium: LazySodium = LazySodiumAndroid(SodiumAndroid()),
    private val secureRandom: SecureRandom = SecureRandom(),
) {

    // -------------------------------------------------------------------------
    // Pairing-key derivation
    // -------------------------------------------------------------------------

    /**
     * Compute the per-pair long-lived symmetric key K_AB.
     *
     * Both sides arrive at the same K_AB because:
     *   ikm  = X25519(ourSk, peerPk)             — DH is symmetric
     *   salt = SHA-256(sort_lex(edPkA, edPkB))   — sort makes role-independent
     *   info = "beam-v2-pairing-key/" || u32_be(generation) || rotateNonce?
     *
     * @param ourSk         32-byte X25519 private key (raw scalar).
     * @param peerPk        32-byte X25519 public key.
     * @param ourEdPk       32-byte Ed25519 public key (ours).
     * @param peerEdPk      32-byte Ed25519 public key (peer).
     * @param generation    u32 generation counter; starts at 0.
     * @param rotateNonce   16-byte rotation nonce; required for generation > 0.
     */
    fun deriveKAB(
        ourSk: ByteArray,
        peerPk: ByteArray,
        ourEdPk: ByteArray,
        peerEdPk: ByteArray,
        generation: Int,
        rotateNonce: ByteArray? = null,
    ): ByteArray {
        require(ourSk.size == 32)    { "ourSk must be 32 bytes" }
        require(peerPk.size == 32)   { "peerPk must be 32 bytes" }
        require(ourEdPk.size == 32)  { "ourEdPk must be 32 bytes" }
        require(peerEdPk.size == 32) { "peerEdPk must be 32 bytes" }
        require(generation >= 0)     { "generation must be non-negative" }
        if (generation > 0) {
            require(rotateNonce != null && rotateNonce.size == 16) {
                "rotateNonce (16 bytes) required for generation > 0"
            }
        }

        // ikm = X25519(ourSk, peerPk)
        val ikm = ByteArray(32)
        check(sodium.cryptoScalarMult(ikm, ourSk, peerPk)) { "X25519 failed" }

        // salt = SHA-256(sort_lex(ourEdPk, peerEdPk))
        val salt = run {
            val cmp = compareLex(ourEdPk, peerEdPk)
            val (lo, hi) = if (cmp <= 0) ourEdPk to peerEdPk else peerEdPk to ourEdPk
            val concat = ByteArray(64)
            lo.copyInto(concat, 0)
            hi.copyInto(concat, 32)
            MessageDigest.getInstance("SHA-256").digest(concat)
        }

        // info = ASCII prefix || u32_be(generation) || rotateNonce?
        val prefix = BeamV2Constants.KAB_INFO_PREFIX.toByteArray(Charsets.UTF_8)
        val genBE = u32be(generation)
        val info = if (rotateNonce != null) {
            ByteArray(prefix.size + 4 + 16).also {
                prefix.copyInto(it, 0)
                genBE.copyInto(it, prefix.size)
                rotateNonce.copyInto(it, prefix.size + 4)
            }
        } else {
            ByteArray(prefix.size + 4).also {
                prefix.copyInto(it, 0)
                genBE.copyInto(it, prefix.size)
            }
        }

        val prk = hkdfExtract(salt, ikm)
        return hkdfExpand(prk, info, BeamV2Constants.KAB_LEN)
    }

    // -------------------------------------------------------------------------
    // Frame encode / decode
    // -------------------------------------------------------------------------

    data class Header(
        val transferId: ByteArray, // 16 bytes
        val index: Int,            // u32
        val isFinal: Boolean,
        val hasMeta: Boolean,
        val generation: Int,       // u32
    )

    /**
     * Build the 48-byte header. The header IS the AEAD additional-data — it
     * binds version, transferId, index, flags, and generation to the
     * ciphertext. Reorder/tamper of any of these fails decrypt.
     */
    fun buildHeader(transferId: ByteArray, index: Int, isFinal: Boolean, hasMeta: Boolean, generation: Int): ByteArray {
        require(transferId.size == 16) { "transferId must be 16 bytes" }
        require(index >= 0)             { "index must be non-negative" }
        require(generation >= 0)        { "generation must be non-negative" }
        val h = ByteArray(BeamV2Constants.HEADER_LEN)
        BeamV2Constants.MAGIC.copyInto(h, 0)
        h[4] = BeamV2Constants.VERSION
        var flags: Int = 0
        if (isFinal) flags = flags or BeamV2Constants.FLAG_IS_FINAL.toInt()
        if (hasMeta) flags = flags or BeamV2Constants.FLAG_HAS_META.toInt()
        h[5] = (flags and 0xff).toByte()
        // bytes 6..7 reserved zero
        transferId.copyInto(h, 8)
        u32be(index).copyInto(h, 24)
        u32be(generation).copyInto(h, 28)
        // bytes 32..47 reserved zero
        return h
    }

    /**
     * Parse the fixed 48-byte header, returning null on any structural mismatch
     * so callers can drop the frame without surfacing a noisy decrypt failure.
     */
    fun peekHeader(bytes: ByteArray): Header? {
        if (bytes.size < BeamV2Constants.HEADER_LEN) return null
        for (i in 0 until 4) {
            if (bytes[i] != BeamV2Constants.MAGIC[i]) return null
        }
        if (bytes[4] != BeamV2Constants.VERSION) return null
        val flagsByte = bytes[5].toInt() and 0xff
        val knownMask = BeamV2Constants.FLAG_IS_FINAL.toInt() or BeamV2Constants.FLAG_HAS_META.toInt()
        if ((flagsByte and knownMask.inv() and 0xff) != 0) return null
        if (bytes[6] != 0.toByte() || bytes[7] != 0.toByte()) return null
        for (i in 32 until 48) {
            if (bytes[i] != 0.toByte()) return null
        }
        val transferId = bytes.copyOfRange(8, 24)
        val index = readU32be(bytes, 24)
        val generation = readU32be(bytes, 28)
        return Header(
            transferId  = transferId,
            index       = index,
            isFinal     = (flagsByte and BeamV2Constants.FLAG_IS_FINAL.toInt()) != 0,
            hasMeta     = (flagsByte and BeamV2Constants.FLAG_HAS_META.toInt()) != 0,
            generation  = generation,
        )
    }

    /**
     * Encrypt a frame. Random 24-byte nonce per call (XChaCha20 collision-safe).
     * Returns header || nonce || ciphertext.
     */
    fun encodeFrame(
        kAB: ByteArray,
        generation: Int,
        transferId: ByteArray,
        index: Int,
        isFinal: Boolean,
        hasMeta: Boolean,
        plaintext: ByteArray,
    ): ByteArray {
        require(kAB.size == BeamV2Constants.KAB_LEN) { "kAB must be ${BeamV2Constants.KAB_LEN} bytes" }
        val header = buildHeader(transferId, index, isFinal, hasMeta, generation)
        val nonce = ByteArray(BeamV2Constants.NONCE_LEN).also { secureRandom.nextBytes(it) }

        val ciphertext = ByteArray(plaintext.size + 16) // +16 = Poly1305 tag
        val ctLen = LongArray(1)
        val ok = sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            ciphertext, ctLen, plaintext, plaintext.size.toLong(),
            header, header.size.toLong(), null, nonce, kAB,
        )
        check(ok) { "XChaCha20-Poly1305 encrypt failed" }

        val frame = ByteArray(BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN + ctLen[0].toInt())
        header.copyInto(frame, 0)
        nonce.copyInto(frame, BeamV2Constants.HEADER_LEN)
        ciphertext.copyInto(frame, BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN, 0, ctLen[0].toInt())
        return frame
    }

    data class DecodedFrame(val header: Header, val plaintext: ByteArray)

    /**
     * Decrypt a frame. The caller supplies a `resolveKAB(generation)` function
     * because the receiver may know multiple K_AB generations; the codec stays
     * stateless by deferring lookup.
     *
     * Returns null on any structural or cryptographic failure.
     */
    fun decodeFrame(
        frameBytes: ByteArray,
        resolveKAB: (Int) -> ByteArray?,
    ): DecodedFrame? {
        val header = peekHeader(frameBytes) ?: return null
        if (frameBytes.size < BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN + 16) return null

        val kAB = resolveKAB(header.generation) ?: return null
        if (kAB.size != BeamV2Constants.KAB_LEN) return null

        val headerBytes = frameBytes.copyOfRange(0, BeamV2Constants.HEADER_LEN)
        val nonce       = frameBytes.copyOfRange(BeamV2Constants.HEADER_LEN, BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN)
        val ciphertext  = frameBytes.copyOfRange(BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN, frameBytes.size)

        val plaintext = ByteArray(ciphertext.size - 16)
        val ptLen = LongArray(1)
        val ok = try {
            sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                plaintext, ptLen, null, ciphertext, ciphertext.size.toLong(),
                headerBytes, headerBytes.size.toLong(), nonce, kAB,
            )
        } catch (_: Exception) {
            false
        }
        if (!ok) return null
        val outPlain = if (ptLen[0].toInt() == plaintext.size) plaintext
                       else plaintext.copyOfRange(0, ptLen[0].toInt())
        return DecodedFrame(header, outPlain)
    }

    /** Generate a fresh 16-byte transferId. */
    fun newTransferId(): ByteArray {
        val id = ByteArray(16)
        secureRandom.nextBytes(id)
        return id
    }

    // -------------------------------------------------------------------------
    // HKDF / helpers
    // -------------------------------------------------------------------------

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val saltBytes = if (salt.isNotEmpty()) salt else ByteArray(32)
        return hmacSha256(saltBytes, ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(32 * 255)) { "HKDF output length out of range" }
        val out = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val input = ByteArray(t.size + info.size + 1)
            t.copyInto(input, 0)
            info.copyInto(input, t.size)
            input[input.size - 1] = (counter and 0xff).toByte()
            t = hmacSha256(prk, input)
            val take = minOf(t.size, length - offset)
            t.copyInto(out, offset, 0, take)
            offset += take
            counter += 1
        }
        return out
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun compareLex(a: ByteArray, b: ByteArray): Int {
        val len = minOf(a.size, b.size)
        for (i in 0 until len) {
            val ai = a[i].toInt() and 0xff
            val bi = b[i].toInt() and 0xff
            if (ai != bi) return ai - bi
        }
        return a.size - b.size
    }

    private fun u32be(n: Int): ByteArray = ByteArray(4).also { out ->
        ByteBuffer.wrap(out).order(ByteOrder.BIG_ENDIAN).putInt(n)
    }

    private fun readU32be(b: ByteArray, off: Int): Int =
        ByteBuffer.wrap(b, off, 4).order(ByteOrder.BIG_ENDIAN).int
}
