package com.zaptransfer.android.webrtc

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit coverage for [shouldStartConnectAttempt] — the guard that prevents
 * `connect()` from spawning a SECOND `attemptConnect` loop while one is
 * already actively establishing.
 *
 * Bug it fixes: at launch, `DeviceHubViewModel.init` AND `refreshPresence`
 * (LifecycleResume) both call `connect()` while the first attempt is still
 * mid-handshake (state not yet Connected). The old guard only short-circuited
 * on an already-Connected socket, so both calls launched a loop → two sockets
 * under one deviceId → the relay zombie-evicts one → presence flapping.
 *
 * The fix must still allow a `connect()` to INTERRUPT a loop that is asleep in
 * backoff (the fast-reconnect-on-foreground behaviour), so the decision needs
 * the `inBackoffSleep` input, not just "is a job active".
 */
class ConnectGuardTest {

    @Test
    fun alreadyConnectedWithSocket_doesNotStart() {
        assertEquals(false, shouldStartConnectAttempt(
            connected = true, hasSocket = true, attemptActive = true, inBackoffSleep = false))
    }

    @Test
    fun connectedButSocketGone_starts() {
        // Inconsistent state (Connected but null socket) → re-establish.
        assertEquals(true, shouldStartConnectAttempt(
            connected = true, hasSocket = false, attemptActive = false, inBackoffSleep = false))
    }

    @Test
    fun noAttemptInFlight_starts() {
        assertEquals(true, shouldStartConnectAttempt(
            connected = false, hasSocket = false, attemptActive = false, inBackoffSleep = false))
    }

    @Test
    fun attemptActivelyEstablishing_doesNotStartSecond() {
        // The double-connect race: a loop is active and mid-handshake (not
        // sleeping). A concurrent connect() must NOT launch a second loop.
        assertEquals(false, shouldStartConnectAttempt(
            connected = false, hasSocket = true, attemptActive = true, inBackoffSleep = false))
    }

    @Test
    fun attemptAsleepInBackoff_startsToInterrupt() {
        // Foreground-after-background: the loop is sleeping in delay(backoff).
        // connect() must cancel+relaunch for an immediate retry.
        assertEquals(true, shouldStartConnectAttempt(
            connected = false, hasSocket = false, attemptActive = true, inBackoffSleep = true))
    }
}
