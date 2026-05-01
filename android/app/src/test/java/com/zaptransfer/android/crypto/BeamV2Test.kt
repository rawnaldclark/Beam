package com.zaptransfer.android.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * Unit coverage for the Beam v2 codec — Kotlin counterpart of
 * `extension/test/beam-v2.test.js`. Every assertion encodes a property the
 * spec promises and the JS implementation verifies. If any test breaks,
 * cross-platform interop has regressed.
 *
 * Runs as a plain JVM unit test using lazysodium-java (no emulator).
 */
class BeamV2Test {

    private val codec = BeamV2(LazySodiumJava(SodiumJava()), SecureRandom())

    // ── Pair fixture ─────────────────────────────────────────────────────

    private data class Pair(
        val aSk: ByteArray, val aPk: ByteArray, val aEd: ByteArray,
        val bSk: ByteArray, val bPk: ByteArray, val bEd: ByteArray,
    )

    private fun makePair(): Pair {
        val rng = SecureRandom()
        val aSk = ByteArray(32).also(rng::nextBytes)
        val bSk = ByteArray(32).also(rng::nextBytes)
        val aPk = ByteArray(32)
        val bPk = ByteArray(32)
        val sodium = LazySodiumJava(SodiumJava())
        sodium.cryptoScalarMultBase(aPk, aSk)
        sodium.cryptoScalarMultBase(bPk, bSk)
        return Pair(
            aSk, aPk, ByteArray(32).also(rng::nextBytes),
            bSk, bPk, ByteArray(32).also(rng::nextBytes),
        )
    }

    private fun random32(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    // ── deriveKAB ────────────────────────────────────────────────────────

    @Test fun deriveKAB_producesIdenticalKeyOnBothSides() {
        val p = makePair()
        val kA = codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, generation = 0)
        val kB = codec.deriveKAB(p.bSk, p.aPk, p.bEd, p.aEd, generation = 0)
        assertEquals(BeamV2Constants.KAB_LEN, kA.size)
        assertArrayEquals(kA, kB)
    }

    @Test fun deriveKAB_differentGenerationsProduceDifferentKeys() {
        val p = makePair()
        val k0 = codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, generation = 0)
        val nonce = ByteArray(16).also(SecureRandom()::nextBytes)
        val k1 = codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, generation = 1, rotateNonce = nonce)
        assertFalse(k0.contentEquals(k1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun deriveKAB_rotationRequiresNonce() {
        val p = makePair()
        codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, generation = 1)
    }

    @Test fun deriveKAB_differentNoncesYieldDifferentKeys() {
        val p = makePair()
        val n1 = ByteArray(16).also(SecureRandom()::nextBytes)
        val n2 = ByteArray(16).also(SecureRandom()::nextBytes)
        val k1 = codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, 1, n1)
        val k2 = codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, 1, n2)
        assertFalse(k1.contentEquals(k2))
    }

    // ── header ───────────────────────────────────────────────────────────

    @Test fun header_isExactly48BytesWithMagicAndZeros() {
        val tid = codec.newTransferId()
        val h = codec.buildHeader(tid, index = 7, isFinal = true, hasMeta = false, generation = 3)
        assertEquals(BeamV2Constants.HEADER_LEN, h.size)
        for (i in 0 until 4) assertEquals(BeamV2Constants.MAGIC[i], h[i])
        assertEquals(BeamV2Constants.VERSION, h[4])
        assertEquals(BeamV2Constants.FLAG_IS_FINAL, h[5])
        assertEquals(0.toByte(), h[6])
        assertEquals(0.toByte(), h[7])
        for (i in 32 until 48) assertEquals(0.toByte(), h[i])
    }

    @Test fun header_roundTripsThroughPeekHeader() {
        val tid = codec.newTransferId()
        val h = codec.buildHeader(tid, index = 0xDEADBE, isFinal = false, hasMeta = true, generation = 42)
        val p = codec.peekHeader(h)
        assertNotNull(p)
        assertArrayEquals(tid, p!!.transferId)
        assertEquals(0xDEADBE, p.index)
        assertFalse(p.isFinal)
        assertTrue(p.hasMeta)
        assertEquals(42, p.generation)
    }

    @Test fun peekHeader_rejectsBadMagic() {
        val h = codec.buildHeader(codec.newTransferId(), 0, true, true, 0)
        h[0] = 0
        assertNull(codec.peekHeader(h))
    }

    @Test fun peekHeader_rejectsUnknownVersion() {
        val h = codec.buildHeader(codec.newTransferId(), 0, true, true, 0)
        h[4] = 0x99.toByte()
        assertNull(codec.peekHeader(h))
    }

    @Test fun peekHeader_rejectsReservedBitViolations() {
        val h = codec.buildHeader(codec.newTransferId(), 0, true, true, 0)
        h[5] = 0xFF.toByte()
        assertNull(codec.peekHeader(h))
    }

    @Test fun peekHeader_rejectsNonZeroReserved() {
        val h = codec.buildHeader(codec.newTransferId(), 0, true, true, 0)
        h[40] = 1
        assertNull(codec.peekHeader(h))
    }

    // ── round-trip ───────────────────────────────────────────────────────

    private fun makeKAB(): ByteArray {
        val p = makePair()
        return codec.deriveKAB(p.aSk, p.bPk, p.aEd, p.bEd, generation = 0)
    }

    @Test fun roundTrip_oneByte() = roundTripOf(1)
    @Test fun roundTrip_32Bytes() = roundTripOf(32)
    @Test fun roundTrip_1KB() = roundTripOf(1024)
    @Test fun roundTrip_200KB() = roundTripOf(200 * 1024)

    private fun roundTripOf(size: Int) {
        val kAB = makeKAB()
        val tid = codec.newTransferId()
        val plaintext = ByteArray(size).also { SecureRandom().nextBytes(it) }
        val frame = codec.encodeFrame(
            kAB = kAB, generation = 0, transferId = tid,
            index = 0, isFinal = true, hasMeta = true, plaintext = plaintext,
        )
        val out = codec.decodeFrame(frame) { g -> if (g == 0) kAB else null }
        assertNotNull(out)
        assertArrayEquals(plaintext, out!!.plaintext)
        assertArrayEquals(tid, out.header.transferId)
        assertEquals(0, out.header.index)
        assertTrue(out.header.isFinal)
        assertTrue(out.header.hasMeta)
        assertEquals(0, out.header.generation)
    }

    // ── tamper resistance ────────────────────────────────────────────────

    private fun makeFrame(): kotlin.Pair<ByteArray, ByteArray> {
        val kAB = makeKAB()
        val frame = codec.encodeFrame(
            kAB = kAB, generation = 0, transferId = codec.newTransferId(),
            index = 0, isFinal = true, hasMeta = true,
            plaintext = "the quick brown fox".toByteArray(),
        )
        return kAB to frame
    }

    @Test fun tamper_ciphertextByteFails() {
        val (kAB, frame) = makeFrame()
        val tampered = frame.copyOf()
        tampered[BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN + 5] =
            (tampered[BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN + 5].toInt() xor 1).toByte()
        assertNull(codec.decodeFrame(tampered) { kAB })
    }

    @Test fun tamper_headerBoundByAADFails() {
        val (kAB, frame) = makeFrame()
        val tampered = frame.copyOf()
        tampered[24] = (tampered[24].toInt() xor 1).toByte()
        assertNull(codec.decodeFrame(tampered) { kAB })
    }

    @Test fun tamper_nonceByteFails() {
        val (kAB, frame) = makeFrame()
        val tampered = frame.copyOf()
        tampered[BeamV2Constants.HEADER_LEN] = (tampered[BeamV2Constants.HEADER_LEN].toInt() xor 1).toByte()
        assertNull(codec.decodeFrame(tampered) { kAB })
    }

    @Test fun tamper_wrongKABFails() {
        val (_, frame) = makeFrame()
        val wrong = random32()
        assertNull(codec.decodeFrame(frame) { wrong })
    }

    @Test fun tamper_unknownGenerationFails() {
        val (_, frame) = makeFrame()
        assertNull(codec.decodeFrame(frame) { null })
    }

    @Test fun tamper_truncatedFrameFails() {
        val (kAB, frame) = makeFrame()
        val short = frame.copyOfRange(0, BeamV2Constants.HEADER_LEN + BeamV2Constants.NONCE_LEN + 8)
        assertNull(codec.decodeFrame(short) { kAB })
    }
}
