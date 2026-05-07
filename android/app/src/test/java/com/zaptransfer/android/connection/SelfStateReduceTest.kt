package com.zaptransfer.android.connection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for [SelfState.reduce]. Mirrors `extension/test/self-state.test.js`
 * test-for-test, with the Android-specific addition of the inline
 * [SelfState.Reconnecting.surrenderedToUser] flag handling.
 *
 * Style: JUnit 4. The reducer is a pure function so no `runTest`,
 * coroutines, or fakes are needed — just `assertEquals` for forward
 * transitions and `assertSame` for the no-op branches that MUST preserve
 * object identity.
 *
 * State machine summary mirrors the JS, with Android folding the surrender
 * flag onto the [SelfState.Reconnecting] case:
 *
 *   States: Offline | Connecting | Online | Reconnecting(surrendered)
 *
 *   Forward transitions:
 *     StartConnect       : Offline                            -> Connecting
 *     AuthComplete       : Connecting | Reconnecting          -> Online
 *                          (the RECONNECTING branch is the load-bearing
 *                          deadlock fix from Chrome commit bd56305)
 *     WsClosed           : Online | Connecting                -> Reconnecting(false)
 *     RecoveryBegan      : Connecting | Online                -> Reconnecting(false)
 *                          Reconnecting(true)                  -> Reconnecting(false)
 *                          Offline -> no-op (Android-specific)
 *     RecoverySucceeded  : Reconnecting (any flag)             -> Online
 *     RecoveryGivenUp    : Reconnecting(false)                 -> Reconnecting(true)
 *                          Reconnecting(true)                  -> SAME instance
 *                                                                (idempotent)
 *     Stop               : *                                   -> Offline
 *
 *   Anything else (no rule matches): no-op (state unchanged, identity preserved).
 */
class SelfStateReduceTest {

    // ── enum sanity ─────────────────────────────────────────────────────────

    @Test
    fun stateNames_matchJsStringConstants() {
        assertEquals("OFFLINE", SelfState.Offline.name)
        assertEquals("CONNECTING", SelfState.Connecting.name)
        assertEquals("ONLINE", SelfState.Online.name)
        assertEquals("RECONNECTING", SelfState.Reconnecting().name)
        assertEquals("RECONNECTING", SelfState.Reconnecting(surrenderedToUser = true).name)
    }

    @Test
    fun reconnecting_defaultsSurrenderToFalse() {
        assertFalse(SelfState.Reconnecting().surrenderedToUser)
    }

    // ── StartConnect ────────────────────────────────────────────────────────

    @Test
    fun startConnect_offlineToConnecting() {
        assertEquals(
            SelfState.Connecting,
            SelfState.reduce(SelfState.Offline, SelfStateEvent.StartConnect),
        )
    }

    @Test
    fun startConnect_connectingStaysConnecting_sameInstance() {
        assertSame(
            SelfState.Connecting,
            SelfState.reduce(SelfState.Connecting, SelfStateEvent.StartConnect),
        )
    }

    @Test
    fun startConnect_onlineStaysOnline_sameInstance() {
        assertSame(
            SelfState.Online,
            SelfState.reduce(SelfState.Online, SelfStateEvent.StartConnect),
        )
    }

    @Test
    fun startConnect_reconnectingStaysReconnecting_sameInstance() {
        // Recovery ladder owns reconnect; StartConnect is informational here.
        val r = SelfState.Reconnecting(surrenderedToUser = false)
        assertSame(r, SelfState.reduce(r, SelfStateEvent.StartConnect))

        val rSurrendered = SelfState.Reconnecting(surrenderedToUser = true)
        assertSame(rSurrendered, SelfState.reduce(rSurrendered, SelfStateEvent.StartConnect))
    }

    // ── AuthComplete (deadlock-fix territory) ───────────────────────────────

    @Test
    fun authComplete_connectingToOnline() {
        assertEquals(
            SelfState.Online,
            SelfState.reduce(SelfState.Connecting, SelfStateEvent.AuthComplete),
        )
    }

    @Test
    fun authComplete_offlineStaysOffline_sameInstance() {
        // Cannot complete auth without connecting first.
        assertSame(
            SelfState.Offline,
            SelfState.reduce(SelfState.Offline, SelfStateEvent.AuthComplete),
        )
    }

    @Test
    fun authComplete_onlineStaysOnline_sameInstance() {
        // No-op; already authed.
        assertSame(
            SelfState.Online,
            SelfState.reduce(SelfState.Online, SelfStateEvent.AuthComplete),
        )
    }

    @Test
    fun authComplete_reconnectingToOnline_deadlockFix() {
        // The load-bearing deadlock fix from Chrome commit bd56305: without
        // this transition, Rungs 2/3 of the recovery ladder deadlock — they
        // call forceWsReconnect / forceFullReset which reopens AND
        // reauthenticates the WS, but the rung's "selfState === Online"
        // success observer never fires because nothing else lifts
        // RECONNECTING. RecoverySucceeded is dispatched AFTER a rung resolves,
        // so it cannot be the trigger.
        assertEquals(
            "AuthComplete from Reconnecting(false) MUST lift to Online — the deadlock fix",
            SelfState.Online,
            SelfState.reduce(SelfState.Reconnecting(surrenderedToUser = false), SelfStateEvent.AuthComplete),
        )
    }

    @Test
    fun authComplete_reconnectingSurrenderedToOnline_deadlockFix() {
        // Even when the user has surrendered (banner red), a successful
        // background auth still lifts us to Online — the surrender flag is
        // about the UI affordance, not about gating a real success.
        assertEquals(
            SelfState.Online,
            SelfState.reduce(SelfState.Reconnecting(surrenderedToUser = true), SelfStateEvent.AuthComplete),
        )
    }

    // ── WsClosed ────────────────────────────────────────────────────────────

    @Test
    fun wsClosed_onlineToReconnectingClean() {
        val next = SelfState.reduce(SelfState.Online, SelfStateEvent.WsClosed)
        assertTrue("WsClosed from Online must enter Reconnecting", next is SelfState.Reconnecting)
        assertFalse(
            "fresh socket loss must clear any prior surrender flag",
            (next as SelfState.Reconnecting).surrenderedToUser,
        )
    }

    @Test
    fun wsClosed_connectingToReconnectingClean() {
        // Auth never completed — still need recovery.
        val next = SelfState.reduce(SelfState.Connecting, SelfStateEvent.WsClosed)
        assertTrue(next is SelfState.Reconnecting)
        assertFalse((next as SelfState.Reconnecting).surrenderedToUser)
    }

    @Test
    fun wsClosed_offlineStaysOffline_sameInstance() {
        // No socket exists to close.
        assertSame(
            SelfState.Offline,
            SelfState.reduce(SelfState.Offline, SelfStateEvent.WsClosed),
        )
    }

    @Test
    fun wsClosed_reconnectingStaysReconnecting_sameInstance() {
        // Already engaged — preserves the surrender flag and identity.
        val r = SelfState.Reconnecting(surrenderedToUser = false)
        assertSame(r, SelfState.reduce(r, SelfStateEvent.WsClosed))

        val rSurrendered = SelfState.Reconnecting(surrenderedToUser = true)
        assertSame(rSurrendered, SelfState.reduce(rSurrendered, SelfStateEvent.WsClosed))
    }

    // ── RecoveryBegan ───────────────────────────────────────────────────────

    @Test
    fun recoveryBegan_offlineToReconnectingClean() {
        // Cold-boot ladder scenario: a service waking with no prior connect
        // attempt (e.g. Android foreground service started after device
        // reboot) legitimately drives Offline -> Reconnecting, skipping
        // Connecting entirely. Matches the JS reducer at
        // `extension/connection/self-state.js` (`case 'recovery-began'`)
        // and the Chrome test at
        // `extension/test/self-state.test.js` ("recovery-began from OFFLINE").
        val next = SelfState.reduce(SelfState.Offline, SelfStateEvent.RecoveryBegan)
        assertTrue(next is SelfState.Reconnecting)
        assertFalse((next as SelfState.Reconnecting).surrenderedToUser)
    }

    @Test
    fun recoveryBegan_connectingToReconnectingClean() {
        val next = SelfState.reduce(SelfState.Connecting, SelfStateEvent.RecoveryBegan)
        assertTrue(next is SelfState.Reconnecting)
        assertFalse((next as SelfState.Reconnecting).surrenderedToUser)
    }

    @Test
    fun recoveryBegan_onlineToReconnectingClean() {
        val next = SelfState.reduce(SelfState.Online, SelfStateEvent.RecoveryBegan)
        assertTrue(next is SelfState.Reconnecting)
        assertFalse((next as SelfState.Reconnecting).surrenderedToUser)
    }

    @Test
    fun recoveryBegan_reconnectingCleanStaysReconnectingClean_sameInstance() {
        // Mid-recovery restart from Reconnecting(false) is identity-preserved
        // so a StateFlow does not re-emit on a non-change.
        val r = SelfState.Reconnecting(surrenderedToUser = false)
        assertSame(r, SelfState.reduce(r, SelfStateEvent.RecoveryBegan))
    }

    @Test
    fun recoveryBegan_reconnectingSurrenderedClearsSurrender() {
        // A new ladder kick clears the user-surrender flag so the UI banner
        // returns to amber. Identity must change because the value changed.
        val rSurrendered = SelfState.Reconnecting(surrenderedToUser = true)
        val next = SelfState.reduce(rSurrendered, SelfStateEvent.RecoveryBegan)
        assertEquals(SelfState.Reconnecting(surrenderedToUser = false), next)
        assertNotSame(
            "transitioning from surrendered=true to surrendered=false MUST be a fresh instance",
            rSurrendered,
            next,
        )
    }

    // ── RecoverySucceeded ───────────────────────────────────────────────────

    @Test
    fun recoverySucceeded_reconnectingToOnline() {
        assertEquals(
            SelfState.Online,
            SelfState.reduce(SelfState.Reconnecting(surrenderedToUser = false), SelfStateEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_reconnectingSurrenderedToOnline_dropsFlag() {
        // Even from surrendered=true, RecoverySucceeded promotes to Online
        // (Online has no surrender concept; the flag is implicitly cleared).
        assertEquals(
            SelfState.Online,
            SelfState.reduce(SelfState.Reconnecting(surrenderedToUser = true), SelfStateEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_offlineStaysOffline_sameInstance() {
        assertSame(
            SelfState.Offline,
            SelfState.reduce(SelfState.Offline, SelfStateEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_connectingStaysConnecting_sameInstance() {
        assertSame(
            SelfState.Connecting,
            SelfState.reduce(SelfState.Connecting, SelfStateEvent.RecoverySucceeded),
        )
    }

    @Test
    fun recoverySucceeded_onlineStaysOnline_sameInstance() {
        assertSame(
            SelfState.Online,
            SelfState.reduce(SelfState.Online, SelfStateEvent.RecoverySucceeded),
        )
    }

    // ── RecoveryGivenUp (the Reconnecting(true) idempotency contract) ───────

    @Test
    fun recoveryGivenUp_reconnectingCleanToReconnectingSurrendered() {
        // Reconnecting(false) -> Reconnecting(true) is a NEW instance — the
        // value changed, observers should see it (banner goes red).
        val before = SelfState.Reconnecting(surrenderedToUser = false)
        val next = SelfState.reduce(before, SelfStateEvent.RecoveryGivenUp)
        assertEquals(SelfState.Reconnecting(surrenderedToUser = true), next)
        assertNotSame(
            "transitioning from surrendered=false to surrendered=true MUST be a fresh instance",
            before,
            next,
        )
    }

    @Test
    fun recoveryGivenUp_reconnectingSurrenderedReturnsSameInstance() {
        // Reconnecting(true) -> Reconnecting(true) MUST return the SAME
        // instance, not a copy — the whole point of the idempotency clause is
        // StateFlow does not re-emit. Use assertSame, not assertEquals.
        val rSurrendered = SelfState.Reconnecting(surrenderedToUser = true)
        assertSame(
            "idempotent re-surrender MUST return the same Reconnecting(true) instance",
            rSurrendered,
            SelfState.reduce(rSurrendered, SelfStateEvent.RecoveryGivenUp),
        )
    }

    @Test
    fun recoveryGivenUp_offlineStaysOffline_sameInstance() {
        assertSame(
            SelfState.Offline,
            SelfState.reduce(SelfState.Offline, SelfStateEvent.RecoveryGivenUp),
        )
    }

    @Test
    fun recoveryGivenUp_connectingStaysConnecting_sameInstance() {
        assertSame(
            SelfState.Connecting,
            SelfState.reduce(SelfState.Connecting, SelfStateEvent.RecoveryGivenUp),
        )
    }

    @Test
    fun recoveryGivenUp_onlineStaysOnline_sameInstance() {
        assertSame(
            SelfState.Online,
            SelfState.reduce(SelfState.Online, SelfStateEvent.RecoveryGivenUp),
        )
    }

    // ── Stop ────────────────────────────────────────────────────────────────

    @Test
    fun stop_offlineStaysOffline_sameInstance() {
        // Already torn down; no spurious StateFlow re-emit.
        assertSame(
            SelfState.Offline,
            SelfState.reduce(SelfState.Offline, SelfStateEvent.Stop),
        )
    }

    @Test
    fun stop_connectingToOffline() {
        assertEquals(SelfState.Offline, SelfState.reduce(SelfState.Connecting, SelfStateEvent.Stop))
    }

    @Test
    fun stop_onlineToOffline() {
        assertEquals(SelfState.Offline, SelfState.reduce(SelfState.Online, SelfStateEvent.Stop))
    }

    @Test
    fun stop_reconnectingCleanToOffline() {
        assertEquals(
            SelfState.Offline,
            SelfState.reduce(SelfState.Reconnecting(surrenderedToUser = false), SelfStateEvent.Stop),
        )
    }

    @Test
    fun stop_reconnectingSurrenderedToOffline() {
        // Stop should also evict a surrendered-Reconnecting; the surrender
        // flag is ladder-scoped, not authority-shutdown-scoped.
        assertEquals(
            SelfState.Offline,
            SelfState.reduce(SelfState.Reconnecting(surrenderedToUser = true), SelfStateEvent.Stop),
        )
    }

    // ── combined sequences (lifted from the JS test matrix) ─────────────────

    @Test
    fun sequence_coldBootHappyPath() {
        // Offline -> Connecting -> Online -> Reconnecting -> Online
        var s: SelfState = SelfState.Offline
        s = SelfState.reduce(s, SelfStateEvent.StartConnect)
        assertEquals(SelfState.Connecting, s)
        s = SelfState.reduce(s, SelfStateEvent.AuthComplete)
        assertEquals(SelfState.Online, s)
        s = SelfState.reduce(s, SelfStateEvent.WsClosed)
        assertTrue(s is SelfState.Reconnecting)
        s = SelfState.reduce(s, SelfStateEvent.RecoverySucceeded)
        assertEquals(SelfState.Online, s)
    }

    @Test
    fun sequence_connectingDroppedBeforeAuth() {
        var s: SelfState = SelfState.Connecting
        s = SelfState.reduce(s, SelfStateEvent.WsClosed)
        assertTrue(
            "a socket close while CONNECTING (auth never completed) must enter RECONNECTING, not OFFLINE",
            s is SelfState.Reconnecting,
        )
        s = SelfState.reduce(s, SelfStateEvent.RecoverySucceeded)
        assertEquals(SelfState.Online, s)
    }

    @Test
    fun sequence_ladderSurrendersButStaysReconnecting() {
        // Online -> RecoveryBegan -> Reconnecting(false) -> RecoveryGivenUp
        // -> Reconnecting(true). A subsequent RecoveryGivenUp is idempotent
        // (same instance).
        var s: SelfState = SelfState.Online
        s = SelfState.reduce(s, SelfStateEvent.RecoveryBegan)
        assertEquals(SelfState.Reconnecting(surrenderedToUser = false), s)
        s = SelfState.reduce(s, SelfStateEvent.RecoveryGivenUp)
        assertEquals(SelfState.Reconnecting(surrenderedToUser = true), s)
        val surrenderedSnapshot = s
        s = SelfState.reduce(s, SelfStateEvent.RecoveryGivenUp)
        assertSame(
            "a second RecoveryGivenUp must be an identity no-op",
            surrenderedSnapshot,
            s,
        )
    }

    @Test
    fun sequence_userRetriesAfterSurrender() {
        // Reconnecting(true) -> Stop -> Offline -> StartConnect -> Connecting
        var s: SelfState = SelfState.Reconnecting(surrenderedToUser = true)
        s = SelfState.reduce(s, SelfStateEvent.Stop)
        assertEquals(SelfState.Offline, s)
        s = SelfState.reduce(s, SelfStateEvent.StartConnect)
        assertEquals(SelfState.Connecting, s)
    }

    @Test
    fun sequence_appShutdownFromOnline() {
        var s: SelfState = SelfState.Online
        s = SelfState.reduce(s, SelfStateEvent.Stop)
        assertEquals(SelfState.Offline, s)
    }

    @Test
    fun sequence_repeatStartConnectWhileConnectingIsIdempotent() {
        var s: SelfState = SelfState.Offline
        s = SelfState.reduce(s, SelfStateEvent.StartConnect)
        assertEquals(SelfState.Connecting, s)
        val first = s
        s = SelfState.reduce(s, SelfStateEvent.StartConnect)
        assertSame("a second StartConnect must be an identity no-op", first, s)
    }

    @Test
    fun sequence_recoveryAfterSurrenderClearsTheFlag() {
        // Reconnecting(true) -> RecoveryBegan -> Reconnecting(false). The
        // ladder restart clears the user-surrender flag so the UI banner can
        // return to amber.
        var s: SelfState = SelfState.Reconnecting(surrenderedToUser = true)
        s = SelfState.reduce(s, SelfStateEvent.RecoveryBegan)
        assertEquals(SelfState.Reconnecting(surrenderedToUser = false), s)
    }

    @Test
    fun sequence_authCompleteFromReconnectingIsTheLadderSuccessSignal() {
        // The full deadlock-fix scenario: ladder rung reopens the WS, auth
        // completes, AuthComplete lifts us straight from Reconnecting to
        // Online. Without this transition the rung deadlocks waiting for a
        // signal that would never come.
        var s: SelfState = SelfState.Reconnecting(surrenderedToUser = false)
        s = SelfState.reduce(s, SelfStateEvent.AuthComplete)
        assertEquals(
            "the deadlock fix MUST lift Reconnecting -> Online on AuthComplete",
            SelfState.Online,
            s,
        )
    }

    // ── purity ──────────────────────────────────────────────────────────────

    @Test
    fun purity_callerSeesNoMutationOfArguments() {
        val original: SelfState = SelfState.Reconnecting(surrenderedToUser = false)
        repeat(50) {
            SelfState.reduce(original, SelfStateEvent.WsClosed)
            SelfState.reduce(original, SelfStateEvent.RecoveryBegan)
            SelfState.reduce(original, SelfStateEvent.AuthComplete)
        }
        // Original reference still points at a Reconnecting(false) value.
        assertTrue(original is SelfState.Reconnecting)
        assertFalse((original as SelfState.Reconnecting).surrenderedToUser)
    }
}
