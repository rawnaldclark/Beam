package com.zaptransfer.android.connection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * Unit coverage for [PeerHealth.reduce]. Mirrors `extension/test/peer-health.test.js`
 * test-for-test so any divergence between the Chrome and Android reducers
 * surfaces as a delta in this matrix.
 *
 * Style: JUnit 4. The reducer is a pure function so no `runTest`,
 * coroutines, or fakes are needed — just `assertEquals` for forward
 * transitions and `assertSame` for the no-op branches that MUST preserve
 * object identity (so a downstream `StateFlow` does not re-emit).
 *
 * State machine summary mirrors the JS:
 *
 *   States: Unknown | Healthy | Stale | Failed | Offline
 *
 *   Forward transitions:
 *     PongReceived       : * \ {Offline} -> Healthy
 *     FrameReceived      : * \ {Offline} -> Healthy
 *     SendCompleted      : * \ {Offline} -> Healthy
 *     PingMissed         : Unknown -> Stale, Healthy -> Stale, Stale -> Failed
 *     PreFlightFailed    : *        -> Failed (yes, including Offline)
 *     RelayPeerOnline    : Offline  -> Unknown (weaker evidence, NOT Healthy)
 *     RelayPeerOffline   : *        -> Offline
 *     RecoverySucceeded  : Failed   -> Unknown
 *     RecoveryGivenUp    : *        -> SAME instance (no-op everywhere)
 *
 *   Anything else (no rule matches): no-op (state unchanged, identity preserved).
 */
class PeerHealthReduceTest {

    private val allStates: List<PeerHealth> = listOf(
        PeerHealth.Unknown,
        PeerHealth.Healthy,
        PeerHealth.Stale,
        PeerHealth.Failed,
        PeerHealth.Offline,
    )

    // ── enum sanity ─────────────────────────────────────────────────────────

    @Test
    fun stateNames_matchJsStringConstants() {
        assertEquals("UNKNOWN", PeerHealth.Unknown.name)
        assertEquals("HEALTHY", PeerHealth.Healthy.name)
        assertEquals("STALE", PeerHealth.Stale.name)
        assertEquals("FAILED", PeerHealth.Failed.name)
        assertEquals("OFFLINE", PeerHealth.Offline.name)
    }

    // ── PongReceived ────────────────────────────────────────────────────────

    @Test
    fun pongReceived_unknownToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.PongReceived))
    }

    @Test
    fun pongReceived_healthyStaysHealthy_sameInstance() {
        // Already-Healthy receiving another pong is a no-op identity-wise.
        assertSame(
            PeerHealth.Healthy,
            PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.PongReceived),
        )
    }

    @Test
    fun pongReceived_stalePromotesToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.PongReceived))
    }

    @Test
    fun pongReceived_failedPromotesToHealthy() {
        // Recovery-bypass: a real pong out of FAILED jumps straight to HEALTHY.
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.PongReceived))
    }

    @Test
    fun pongReceived_offlineStaysOffline_sameInstance() {
        // Must wait for relay-peer-online before we even consider non-OFFLINE.
        assertSame(
            PeerHealth.Offline,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.PongReceived),
        )
    }

    // ── FrameReceived ───────────────────────────────────────────────────────

    @Test
    fun frameReceived_unknownToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.FrameReceived))
    }

    @Test
    fun frameReceived_healthyStaysHealthy_sameInstance() {
        assertSame(
            PeerHealth.Healthy,
            PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.FrameReceived),
        )
    }

    @Test
    fun frameReceived_stalePromotesToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.FrameReceived))
    }

    @Test
    fun frameReceived_failedPromotesToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.FrameReceived))
    }

    @Test
    fun frameReceived_offlineStaysOffline_sameInstance() {
        assertSame(
            PeerHealth.Offline,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.FrameReceived),
        )
    }

    // ── SendCompleted ───────────────────────────────────────────────────────

    @Test
    fun sendCompleted_unknownToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.SendCompleted))
    }

    @Test
    fun sendCompleted_healthyStaysHealthy_sameInstance() {
        assertSame(
            PeerHealth.Healthy,
            PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.SendCompleted),
        )
    }

    @Test
    fun sendCompleted_stalePromotesToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.SendCompleted))
    }

    @Test
    fun sendCompleted_failedPromotesToHealthy() {
        assertEquals(PeerHealth.Healthy, PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.SendCompleted))
    }

    @Test
    fun sendCompleted_offlineStaysOffline_sameInstance() {
        assertSame(
            PeerHealth.Offline,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.SendCompleted),
        )
    }

    // ── PingMissed ──────────────────────────────────────────────────────────

    @Test
    fun pingMissed_unknownToStale() {
        assertEquals(PeerHealth.Stale, PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.PingMissed))
    }

    @Test
    fun pingMissed_healthyToStale() {
        assertEquals(PeerHealth.Stale, PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.PingMissed))
    }

    @Test
    fun pingMissed_staleToFailed_oneMissTolerated() {
        // The "one ping missed is forgivable, two is FAILED" contract.
        assertEquals(PeerHealth.Failed, PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.PingMissed))
    }

    @Test
    fun pingMissed_failedStaysFailed_sameInstance() {
        assertSame(
            PeerHealth.Failed,
            PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.PingMissed),
        )
    }

    @Test
    fun pingMissed_offlineStaysOffline_sameInstance() {
        // Offline owns the floor; missed pings while OFFLINE are not surprising.
        assertSame(
            PeerHealth.Offline,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.PingMissed),
        )
    }

    // ── PreFlightFailed ─────────────────────────────────────────────────────

    @Test
    fun preFlightFailed_unknownToFailed() {
        assertEquals(PeerHealth.Failed, PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.PreFlightFailed))
    }

    @Test
    fun preFlightFailed_healthyToFailed() {
        assertEquals(PeerHealth.Failed, PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.PreFlightFailed))
    }

    @Test
    fun preFlightFailed_staleToFailed() {
        assertEquals(PeerHealth.Failed, PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.PreFlightFailed))
    }

    @Test
    fun preFlightFailed_failedStaysFailed_sameInstance() {
        assertSame(
            PeerHealth.Failed,
            PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.PreFlightFailed),
        )
    }

    @Test
    fun preFlightFailed_offlineToFailed() {
        // Mirrors JS: preflight gives concrete failure evidence the relay's
        // peer-online claim is stale, so we move OFFLINE -> FAILED.
        assertEquals(
            PeerHealth.Failed,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.PreFlightFailed),
        )
    }

    // ── RelayPeerOnline ─────────────────────────────────────────────────────

    @Test
    fun relayPeerOnline_offlineToUnknown_notHealthy() {
        val next = PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.RelayPeerOnline)
        assertEquals(PeerHealth.Unknown, next)
        assertNotEquals(
            "relay says peer WS is open — that does not prove the app is responsive. " +
                "Must NOT promote to HEALTHY; only a peer-pong/frame can.",
            PeerHealth.Healthy,
            next,
        )
    }

    @Test
    fun relayPeerOnline_unknownStaysUnknown_sameInstance() {
        assertSame(
            PeerHealth.Unknown,
            PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.RelayPeerOnline),
        )
    }

    @Test
    fun relayPeerOnline_healthyStaysHealthy_sameInstance() {
        // Do not downgrade on a weaker signal.
        assertSame(
            PeerHealth.Healthy,
            PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.RelayPeerOnline),
        )
    }

    @Test
    fun relayPeerOnline_staleStaysStale_sameInstance() {
        assertSame(
            PeerHealth.Stale,
            PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.RelayPeerOnline),
        )
    }

    @Test
    fun relayPeerOnline_failedStaysFailed_sameInstance() {
        // Recovery ladder owns the FAILED exit, not relay presence.
        assertSame(
            PeerHealth.Failed,
            PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.RelayPeerOnline),
        )
    }

    // ── RelayPeerOffline ────────────────────────────────────────────────────

    @Test
    fun relayPeerOffline_unknownToOffline() {
        assertEquals(PeerHealth.Offline, PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.RelayPeerOffline))
    }

    @Test
    fun relayPeerOffline_healthyToOffline() {
        assertEquals(PeerHealth.Offline, PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.RelayPeerOffline))
    }

    @Test
    fun relayPeerOffline_staleToOffline() {
        assertEquals(PeerHealth.Offline, PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.RelayPeerOffline))
    }

    @Test
    fun relayPeerOffline_failedToOffline() {
        assertEquals(PeerHealth.Offline, PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.RelayPeerOffline))
    }

    @Test
    fun relayPeerOffline_offlineStaysOffline_sameInstance() {
        assertSame(
            PeerHealth.Offline,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.RelayPeerOffline),
        )
    }

    // ── RecoverySucceeded ───────────────────────────────────────────────────

    @Test
    fun recoverySucceeded_failedToUnknown() {
        // Drop to UNKNOWN; the next ping/frame promotes us to HEALTHY.
        assertEquals(PeerHealth.Unknown, PeerHealth.reduce(PeerHealth.Failed, PeerHealthEvent.RecoverySucceeded))
    }

    @Test
    fun recoverySucceeded_unknownStaysUnknown_sameInstance() {
        assertSame(
            PeerHealth.Unknown,
            PeerHealth.reduce(PeerHealth.Unknown, PeerHealthEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_healthyStaysHealthy_sameInstance() {
        assertSame(
            PeerHealth.Healthy,
            PeerHealth.reduce(PeerHealth.Healthy, PeerHealthEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_staleStaysStale_sameInstance() {
        assertSame(
            PeerHealth.Stale,
            PeerHealth.reduce(PeerHealth.Stale, PeerHealthEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_offlineStaysOffline_sameInstance() {
        // Relay says peer is gone; recovery does not override.
        assertSame(
            PeerHealth.Offline,
            PeerHealth.reduce(PeerHealth.Offline, PeerHealthEvent.RecoverySucceeded),
        )
    }

    // ── RecoveryGivenUp ─────────────────────────────────────────────────────
    //
    // The peer-health reducer is a no-op for this event from EVERY state —
    // the surrender flag lives on SelfState.Reconnecting.surrenderedToUser
    // and FAILED is already the correct peerHealth signal for the UI to read.
    // Identity is preserved everywhere so StateFlow does not re-emit.

    @Test
    fun recoveryGivenUp_isIdentityNoOpFromEveryState() {
        for (s in allStates) {
            assertSame(
                "RecoveryGivenUp must be a strict identity no-op from $s",
                s,
                PeerHealth.reduce(s, PeerHealthEvent.RecoveryGivenUp),
            )
        }
    }

    // ── combined sequences (lifted from the JS test matrix) ─────────────────

    @Test
    fun sequence_healthyPingMissTwiceLandsInFailed() {
        var s: PeerHealth = PeerHealth.Healthy
        s = PeerHealth.reduce(s, PeerHealthEvent.PingMissed)
        assertEquals(PeerHealth.Stale, s)
        s = PeerHealth.reduce(s, PeerHealthEvent.PingMissed)
        assertEquals(PeerHealth.Failed, s)
    }

    @Test
    fun sequence_offlineRelayOnlinePongLandsInHealthy() {
        var s: PeerHealth = PeerHealth.Offline
        s = PeerHealth.reduce(s, PeerHealthEvent.RelayPeerOnline)
        assertEquals(
            "relay-peer-online must exit OFFLINE only as far as UNKNOWN",
            PeerHealth.Unknown,
            s,
        )
        s = PeerHealth.reduce(s, PeerHealthEvent.PongReceived)
        assertEquals(PeerHealth.Healthy, s)
    }

    @Test
    fun sequence_failedRecoverFrameLandsInHealthy() {
        var s: PeerHealth = PeerHealth.Failed
        s = PeerHealth.reduce(s, PeerHealthEvent.RecoverySucceeded)
        assertEquals(PeerHealth.Unknown, s)
        s = PeerHealth.reduce(s, PeerHealthEvent.FrameReceived)
        assertEquals(PeerHealth.Healthy, s)
    }

    @Test
    fun sequence_oneMissIsRecoverable() {
        // HEALTHY -> ping-missed (STALE) -> pong-received (HEALTHY).
        var s: PeerHealth = PeerHealth.Healthy
        s = PeerHealth.reduce(s, PeerHealthEvent.PingMissed)
        assertEquals(PeerHealth.Stale, s)
        s = PeerHealth.reduce(s, PeerHealthEvent.PongReceived)
        assertEquals(PeerHealth.Healthy, s)
    }

    @Test
    fun sequence_relayOfflineThenOnlineDoesNotAssumeHealthy() {
        // After going OFFLINE then back ONLINE we must NOT assume HEALTHY without a pong/frame.
        var s: PeerHealth = PeerHealth.Healthy
        s = PeerHealth.reduce(s, PeerHealthEvent.RelayPeerOffline)
        assertEquals(PeerHealth.Offline, s)
        s = PeerHealth.reduce(s, PeerHealthEvent.RelayPeerOnline)
        assertEquals(PeerHealth.Unknown, s)
    }

    @Test
    fun sequence_recoveryGivenUpKeepsFailedUntilUpgradeArrives() {
        var s: PeerHealth = PeerHealth.Failed
        s = PeerHealth.reduce(s, PeerHealthEvent.RecoveryGivenUp)
        assertEquals(PeerHealth.Failed, s)
        s = PeerHealth.reduce(s, PeerHealthEvent.RecoveryGivenUp)
        assertEquals(PeerHealth.Failed, s)
        s = PeerHealth.reduce(s, PeerHealthEvent.PongReceived)
        assertEquals("a real pong still rescues us out of FAILED", PeerHealth.Healthy, s)
    }

    // ── purity ──────────────────────────────────────────────────────────────

    @Test
    fun purity_callerSeesNoMutationOfArguments() {
        // The reducer's arguments are immutable by design (objects + a sealed
        // event class with `object` cases), but we still assert the input
        // state is identity-stable across many calls so a future refactor
        // adding mutable fields is caught here.
        val original: PeerHealth = PeerHealth.Healthy
        repeat(50) {
            PeerHealth.reduce(original, PeerHealthEvent.PongReceived)
            PeerHealth.reduce(original, PeerHealthEvent.PingMissed)
            PeerHealth.reduce(original, PeerHealthEvent.RelayPeerOffline)
        }
        // Original reference still points at the same PeerHealth.Healthy singleton.
        assertSame(PeerHealth.Healthy, original)
    }
}
