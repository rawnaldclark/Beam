package com.zaptransfer.android.connection

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Unit coverage for [PeerPingTracker]. Mirrors `extension/test/peer-ping.test.js`
 * test-for-test so any divergence between the Chrome and Android
 * implementations surfaces as a delta in this matrix.
 *
 * Style: JUnit 4 (`@Test` with assertion API), `runTest` for the cases
 * that await deferreds. No emulator dependency — pure JVM unit tests.
 *
 * Note on JSON shape: the production code emits typed [PeerPingMessage]
 * values, NOT `org.json.JSONObject`. This keeps the test matrix free of
 * Android's stub `org.json` (which returns null from typed accessors when
 * `testOptions.unitTests.isReturnDefaultValues = true` — see
 * `BeamV2VectorsTest` for the gson workaround used elsewhere). The future
 * `ConnectionAuthority` (Task 15) is responsible for the
 * `PeerPingMessage -> JSONObject` adaptation at the transport boundary.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PeerPingTrackerTest {

    // ── helpers ─────────────────────────────────────────────────────────────

    /** Records every [PeerPingMessage] the tracker hands to the injected sender. */
    private class CapturingSender : (PeerPingMessage) -> Unit {
        val sent: MutableList<PeerPingMessage> = mutableListOf()
        override fun invoke(msg: PeerPingMessage) {
            sent += msg
        }
    }

    private fun newTracker(
        sender: CapturingSender = CapturingSender(),
        timeoutMs: Long = 5_000L,
        ownDeviceId: String = "device-self",
    ): Pair<PeerPingTracker, CapturingSender> =
        PeerPingTracker(sender, timeoutMs, ownDeviceId) to sender

    // ── constructor guards ──────────────────────────────────────────────────

    @Test
    fun constructor_throwsOnEmptyOwnDeviceId() {
        try {
            PeerPingTracker(
                sendMessage = {},
                timeoutMs = 5_000L,
                ownDeviceId = "",
            )
            fail("Expected IllegalArgumentException for empty ownDeviceId")
        } catch (e: IllegalArgumentException) {
            assertTrue(
                "Message must mention ownDeviceId; was: ${e.message}",
                e.message?.contains("ownDeviceId") == true,
            )
        }
    }

    @Test
    fun constructor_throwsOnZeroTimeout() {
        try {
            PeerPingTracker(
                sendMessage = {},
                timeoutMs = 0L,
                ownDeviceId = "device-self",
            )
            fail("Expected IllegalArgumentException for zero timeoutMs")
        } catch (e: IllegalArgumentException) {
            assertTrue(
                "Message must mention timeoutMs; was: ${e.message}",
                e.message?.contains("timeoutMs") == true,
            )
        }
    }

    @Test
    fun constructor_throwsOnNegativeTimeout() {
        try {
            PeerPingTracker(
                sendMessage = {},
                timeoutMs = -1L,
                ownDeviceId = "device-self",
            )
            fail("Expected IllegalArgumentException for negative timeoutMs")
        } catch (e: IllegalArgumentException) {
            assertTrue(
                "Message must mention timeoutMs; was: ${e.message}",
                e.message?.contains("timeoutMs") == true,
            )
        }
    }

    // ── sendPing ────────────────────────────────────────────────────────────

    @Test
    fun sendPing_returnsNonceAndDeferred_andEmitsCorrectWireShape() {
        val sender = CapturingSender()
        val tracker = PeerPingTracker(
            sendMessage = sender,
            timeoutMs = 5_000L,
            ownDeviceId = "device-self",
        )

        val peerId = "peer-device-abc"
        val (nonce, deferred) = tracker.sendPing(peerId, now = 1_000L)

        assertNotNull("nonce must be non-null", nonce)
        assertEquals(1, sender.sent.size)
        val msg = sender.sent[0]
        assertEquals("peer-ping", msg.type)
        assertEquals(nonce, msg.nonce)
        assertEquals(peerId, msg.targetDeviceId)
        assertEquals(
            "rendezvousId must be ownDeviceId, NOT peerId",
            "device-self",
            msg.rendezvousId,
        )

        assertFalse(
            "deferred must still be pending after sendPing",
            deferred.isCompleted,
        )
    }

    @Test
    fun sendPing_rendezvousIsOwnDeviceIdNotPeerId() {
        val sender = CapturingSender()
        val tracker = PeerPingTracker(
            sendMessage = sender,
            timeoutMs = 5_000L,
            ownDeviceId = "android-own-id-xyz",
        )

        val peerId = "chrome-peer-id-123"
        tracker.sendPing(peerId, now = 0L)

        assertEquals(1, sender.sent.size)
        val msg = sender.sent[0]
        assertEquals(peerId, msg.targetDeviceId)
        assertEquals("android-own-id-xyz", msg.rendezvousId)
        assertNotEquals(peerId, msg.rendezvousId)
    }

    @Test
    fun sendPing_nonceIsB64UrlNoPaddingAndUniquePerCall() {
        val (tracker, _) = newTracker()
        val nonces = mutableSetOf<String>()
        repeat(20) { i ->
            val (nonce, _) = tracker.sendPing("peer-$i", now = i.toLong())
            // 16 random bytes, b64url, no padding -> 22 chars exactly.
            assertEquals(
                "nonce must be 22 chars (16 bytes b64url no-pad)",
                22,
                nonce.length,
            )
            assertTrue(
                "nonce must contain only b64url chars; was: $nonce",
                nonce.matches(Regex("^[A-Za-z0-9\\-_]+$")),
            )
            assertFalse(
                "nonce must have no '=' padding; was: $nonce",
                nonce.contains('='),
            )
            nonces += nonce
        }
        assertEquals("all 20 nonces must be unique", 20, nonces.size)
    }

    // ── recordPong ──────────────────────────────────────────────────────────

    @Test
    fun recordPong_completesMatchingDeferredWithPongAndReturnsTrue() = runTest {
        val (tracker, _) = newTracker()
        val peerId = "peer-x"
        val (nonce, deferred) = tracker.sendPing(peerId, now = 1_000L)

        val matched = tracker.recordPong(nonce, now = 1_042L)
        assertTrue("recordPong on a known nonce must return true", matched)

        val result = deferred.await()
        assertEquals(PingResult.Pong(peerId), result)
    }

    @Test
    fun recordPong_unknownNonceIsNoOpAndReturnsFalse() {
        val (tracker, sender) = newTracker()
        // Issue a real ping so the tracker has SOME state, just not the nonce
        // we're about to record. Confirms the unknown lookup is independent.
        val (knownNonce, knownDeferred) = tracker.sendPing("peer-real", now = 0L)

        val matched = tracker.recordPong("completely-unknown-nonce", now = 100L)
        assertFalse("recordPong on an unknown nonce must return false", matched)

        // The real pending entry must NOT have been touched.
        assertFalse(
            "unknown-nonce recordPong must not complete unrelated pings",
            knownDeferred.isCompleted,
        )
        assertEquals(1, sender.sent.size) // sanity: only the known ping was sent
    }

    @Test
    fun sweepExpired_emptyTrackerReturnsZero() = runTest {
        // Covers the early-return branch that bypasses the iteration when
        // there are no in-flight pings. Cheap regression guard for the
        // case a future refactor accidentally drops the fast path.
        val (tracker, _) = newTracker()
        val swept = tracker.sweepExpired(now = 1_000L)
        assertEquals("sweep on an empty tracker must return 0", 0, swept)
    }

    // ── sweepExpired ────────────────────────────────────────────────────────

    @Test
    fun sweepExpired_beforeDeadlineIsNoOp() = runTest {
        val (tracker, _) = newTracker(timeoutMs = 3_000L)
        val (_, deferred) = tracker.sendPing("peer-timeout-test", now = 5_000L)

        val swept = tracker.sweepExpired(now = 5_000L + 2_999L)
        assertEquals("no entries should expire before the deadline", 0, swept)
        assertFalse("deferred must remain pending before deadline", deferred.isCompleted)
    }

    @Test
    fun sweepExpired_atDeadlineCompletesWithTimedOutAndReturnsCount() = runTest {
        val (tracker, _) = newTracker(timeoutMs = 3_000L)
        val peerId = "peer-timeout-test"
        val (_, deferred) = tracker.sendPing(peerId, now = 5_000L)

        val swept = tracker.sweepExpired(now = 5_000L + 3_000L)
        assertEquals("exactly one entry should expire at the deadline", 1, swept)

        val result = deferred.await()
        assertEquals(PingResult.TimedOut(peerId), result)
    }

    @Test
    fun sweepExpired_isIdempotentAfterFirstSweep() = runTest {
        val (tracker, _) = newTracker(timeoutMs = 1_000L)
        val (_, deferred) = tracker.sendPing("peer-sweep-once", now = 0L)

        val first = tracker.sweepExpired(now = 1_000L)
        assertEquals(1, first)
        // First sweep already completed the deferred — drain it.
        assertEquals(PingResult.TimedOut("peer-sweep-once"), deferred.await())

        val second = tracker.sweepExpired(now = 2_000L)
        assertEquals("entry must not appear in second sweep", 0, second)
    }

    @Test
    fun sweepExpired_nonExpiredPingsStayPending() = runTest {
        val (tracker, _) = newTracker(timeoutMs = 5_000L)

        val (_, p1) = tracker.sendPing("peer-1", now = 0L)
        // p2 sent later -> deadline later. At t=5000, p1's deadline (5000)
        // has passed; p2's deadline (8000) has not.
        val (_, p2) = tracker.sendPing("peer-2", now = 3_000L)

        val swept = tracker.sweepExpired(now = 5_000L)
        assertEquals("only the first ping should expire", 1, swept)

        assertEquals(PingResult.TimedOut("peer-1"), p1.await())
        assertFalse("second ping must still be pending", p2.isCompleted)
    }
}
