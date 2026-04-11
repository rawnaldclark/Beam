package com.zaptransfer.android.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.SecureRandom

/**
 * Unit tests for [BeamSessionRegistry] — state machine, rate limits, timeouts,
 * and cross-party session-key agreement.
 */
class BeamSessionRegistryTest {

    private val cipher = BeamCipher(LazySodiumJava(SodiumJava()))
    private val rng = SecureRandom()

    private data class Identity(val sk: ByteArray, val pk: ByteArray)

    private fun makeIdentity(): Identity {
        val sk = ByteArray(32).also { rng.nextBytes(it) }
        return Identity(sk, cipher.x25519PublicKey(sk))
    }

    private fun makeRegistry(
        id: Identity,
        config: BeamSessionRegistry.Config = BeamSessionRegistry.Config(),
        clock: () -> Long = { System.currentTimeMillis() },
    ) = BeamSessionRegistry(
        cipher = cipher,
        ourStaticSk = id.sk,
        ourStaticPk = id.pk,
        config = config,
        clock = clock,
        random = rng,
    )

    @Test
    fun happyPathDerivesMatchingSessionKeys() {
        val alice = makeIdentity()
        val bob = makeIdentity()
        val regA = makeRegistry(alice)
        val regB = makeRegistry(bob)

        val init = regA.startInit("bob", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
        assertEquals(BeamSessionRegistry.State.AWAITING_ACCEPT, init.session.state)
        assertEquals(BeamCipher.PROTOCOL_VERSION, init.wireMessage.v)
        assertEquals(16, init.wireMessage.transferId.size)
        assertEquals(32, init.wireMessage.ephPkA.size)
        assertEquals(32, init.wireMessage.salt.size)

        val accept = regB.onInit("alice", alice.pk, init.wireMessage)
        assertEquals(BeamSessionRegistry.State.ACTIVE, accept.session.state)
        assertNotEquals(0, accept.session.transcript!!.size)

        val sessionA = regA.onAccept("bob", accept.wireMessage)
        assertEquals(BeamSessionRegistry.State.ACTIVE, sessionA.state)

        // Critical: both sides agree on the derived keys.
        assertArrayEquals("sessionKey", sessionA.sessionKey, accept.session.sessionKey)
        assertArrayEquals("chunkKey", sessionA.chunkKey, accept.session.chunkKey)
        assertArrayEquals("metaKey", sessionA.metaKey, accept.session.metaKey)
        assertArrayEquals("transcript", sessionA.transcript, accept.session.transcript)

        // Ephemerals wiped after derivation.
        assertNull(sessionA.ephSk)

        // Destroy both sides cleanly.
        regA.destroy(sessionA.transferId)
        regB.destroy(accept.session.transferId)
        assertEquals(0, regA.size())
        assertEquals(0, regB.size())
    }

    @Test
    fun versionMismatchRejected() {
        val alice = makeIdentity()
        val bob = makeIdentity()
        val regB = makeRegistry(bob)

        val badInit = BeamSessionRegistry.TransferInitMessage(
            v = 99,
            transferId = ByteArray(16),
            kind = BeamSessionRegistry.Kind.CLIPBOARD,
            ephPkA = ByteArray(32),
            salt = ByteArray(32),
        )
        try {
            regB.onInit("alice", alice.pk, badInit)
            fail("expected HandshakeException")
        } catch (e: BeamSessionRegistry.HandshakeException) {
            assertEquals(BeamSessionRegistry.ErrorCodes.VERSION, e.code)
        }
    }

    @Test
    fun duplicateTransferIdRejected() {
        val alice = makeIdentity()
        val bob = makeIdentity()
        val regA = makeRegistry(alice)
        val regB = makeRegistry(bob)

        val init = regA.startInit("bob", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
        regB.onInit("alice", alice.pk, init.wireMessage)
        try {
            regB.onInit("alice", alice.pk, init.wireMessage)
            fail("expected HandshakeException")
        } catch (e: BeamSessionRegistry.HandshakeException) {
            assertEquals(BeamSessionRegistry.ErrorCodes.DUPLICATE, e.code)
        }
    }

    @Test
    fun sweepReapsTimedOutHandshakes() {
        val alice = makeIdentity()
        val bob = makeIdentity()
        var now = 1_000_000L
        val reg = makeRegistry(
            alice,
            config = BeamSessionRegistry.Config(handshakeTimeoutMs = 1_000),
            clock = { now },
        )
        reg.startInit("bob", bob.pk, BeamSessionRegistry.Kind.FILE)
        assertEquals(1, reg.size())
        now += 1_500
        reg.sweep()
        assertEquals(0, reg.size())
    }

    @Test
    fun perPeerRateLimitEnforced() {
        val alice = makeIdentity()
        val bob = makeIdentity()
        val reg = makeRegistry(
            alice,
            config = BeamSessionRegistry.Config(maxPendingPerPeer = 2, maxGlobalPerSecond = 999),
        )
        reg.startInit("bob", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
        reg.startInit("bob", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
        try {
            reg.startInit("bob", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
            fail("expected rate-limit HandshakeException")
        } catch (e: BeamSessionRegistry.HandshakeException) {
            assertEquals(BeamSessionRegistry.ErrorCodes.RATE_LIMIT, e.code)
        }
    }

    @Test
    fun globalRateLimitEnforcedAndRecovers() {
        val alice = makeIdentity()
        val bob = makeIdentity()
        var now = 1_000_000L
        val reg = makeRegistry(
            alice,
            config = BeamSessionRegistry.Config(maxPendingPerPeer = 999, maxGlobalPerSecond = 3),
            clock = { now },
        )
        repeat(3) { i ->
            reg.startInit("peer$i", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
        }
        try {
            reg.startInit("overflow", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
            fail("expected global rate-limit HandshakeException")
        } catch (e: BeamSessionRegistry.HandshakeException) {
            assertEquals(BeamSessionRegistry.ErrorCodes.RATE_LIMIT, e.code)
        }
        // Window slides — allowed again 1.5s later.
        now += 1_500
        val ok = reg.startInit("peer-late", bob.pk, BeamSessionRegistry.Kind.CLIPBOARD)
        assertTrue(ok.session.state == BeamSessionRegistry.State.AWAITING_ACCEPT)
    }
}
