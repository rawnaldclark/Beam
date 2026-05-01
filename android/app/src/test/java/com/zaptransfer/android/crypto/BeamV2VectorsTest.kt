package com.zaptransfer.android.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Cross-implementation interop check.
 *
 * Loads the canonical `beam-v2-vectors.json` (a copy of
 * `server/test-vectors/beam-v2/vectors.json`) and verifies that this codec
 * reproduces the expected K_AB derivations and decodes the captured frame
 * bytes to the expected plaintext.
 *
 * The JS side runs the same assertions against the same file. Drift between
 * the two implementations is caught here before it can break a paired
 * transfer in the wild.
 */
class BeamV2VectorsTest {

    private val codec = BeamV2(LazySodiumJava(SodiumJava()))

    private fun loadVectors(): JsonObject {
        val stream = javaClass.classLoader!!.getResourceAsStream("beam-v2-vectors.json")
            ?: error("beam-v2-vectors.json not found on test classpath")
        val text = stream.bufferedReader().use { it.readText() }
        return JsonParser.parseString(text).asJsonObject
    }

    private fun hex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
        }
        return out
    }
    private fun toHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    @Test fun kabDerivationVectors() {
        val arr: JsonArray = loadVectors().getAsJsonArray("kab_derivation")
        for (i in 0 until arr.size()) {
            val v = arr.get(i).asJsonObject
            val rotateNonce = v.get("rotate_nonce")
            val nonce = if (rotateNonce.isJsonNull) null else hex(rotateNonce.asString)
            val got = codec.deriveKAB(
                ourSk    = hex(v.get("a_x_sk").asString),
                peerPk   = hex(v.get("b_x_pk").asString),
                ourEdPk  = hex(v.get("a_ed_pk").asString),
                peerEdPk = hex(v.get("b_ed_pk").asString),
                generation = v.get("generation").asInt,
                rotateNonce = nonce,
            )
            assertEquals(
                "vector ${v.get("name").asString}",
                v.get("expected_kab").asString,
                toHex(got),
            )
        }
    }

    @Test fun frameDecodeVectors() {
        val arr: JsonArray = loadVectors().getAsJsonArray("frames")
        for (i in 0 until arr.size()) {
            val v = arr.get(i).asJsonObject
            val name = v.get("name").asString
            val kAB = hex(v.get("kab").asString)
            val frame = hex(v.get("frame").asString)
            val out = codec.decodeFrame(frame) { _ -> kAB }
            assertNotNull("decode null for $name", out)
            assertEquals("plaintext mismatch for $name", v.get("expected_plaintext").asString, toHex(out!!.plaintext))
            val expHeader = v.get("expected_header").asJsonObject
            assertArrayEquals(
                "transferId mismatch for $name",
                hex(expHeader.get("transferId").asString),
                out.header.transferId,
            )
            assertEquals("index mismatch for $name",      expHeader.get("index").asInt,      out.header.index)
            assertEquals("isFinal mismatch for $name",    expHeader.get("isFinal").asBoolean, out.header.isFinal)
            assertEquals("hasMeta mismatch for $name",    expHeader.get("hasMeta").asBoolean, out.header.hasMeta)
            assertEquals("generation mismatch for $name", expHeader.get("generation").asInt, out.header.generation)
        }
    }
}
