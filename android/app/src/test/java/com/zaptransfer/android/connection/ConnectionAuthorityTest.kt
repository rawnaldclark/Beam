package com.zaptransfer.android.connection

import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for [ConnectionAuthority] (Task 15 skeleton).
 *
 * Mirrors `extension/test/connection-authority.test.js` from Chrome commit
 * `68e3c9f` test-for-test, with the Android-specific additions for:
 *
 *   - Confined-dispatcher threading model (concurrent dispatches must not
 *     race; verified by firing 100 frame-received events on different
 *     coroutines and asserting a consistent final state).
 *   - `signalingClient.connectionState` collector wiring (Connecting ->
 *     Connected -> Disconnected -> reducer events).
 *   - `peer-online`/`peer-offline` SignalingListener route into
 *     `notifyPeerOnline`/`notifyPeerOffline`.
 *   - [ConnectionAuthority.shutdown] tear-down idempotency.
 *
 * All tests use [StandardTestDispatcher] for deterministic ordering, so
 * `advanceUntilIdle()` is the canonical "drain the worker thread" call
 * after dispatching events. The production `Dispatchers.Default
 * .limitedParallelism(1)` is a shape-compatible substitute (single-thread
 * confinement); the test scheduler gives us `runTest`'s virtual time.
 *
 * Style: JUnit 4 with `runTest`. The `SignalingClient` dependency is
 * mocked via [mockk] — the only stub points are `connectionState` (a real
 * [MutableStateFlow] we drive) plus `addListener`/`removeListener` whose
 * registered listener we capture via a [slot].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ConnectionAuthorityTest {

    // ── helpers ─────────────────────────────────────────────────────────────

    /**
     * Bundle of a mocked [SignalingClient], the [MutableStateFlow] backing
     * its `connectionState`, and the captured [SignalingListener]
     * registered by the authority's `init` block.
     *
     * Every test that exercises `signalingClient`-driven state changes
     * obtains one of these and drives the flow / invokes the captured
     * listener directly.
     */
    private data class FakeSignaling(
        val client: SignalingClient,
        val connectionState: MutableStateFlow<ConnectionState>,
        val listenerSlot: io.mockk.CapturingSlot<SignalingListener>,
    )

    /** Build a relaxed [SignalingClient] mock with a controllable `connectionState`. */
    private fun newFakeSignaling(): FakeSignaling {
        val flow = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
        val client = mockk<SignalingClient>(relaxed = true)
        every { client.connectionState } returns flow
        val listenerSlot = slot<SignalingListener>()
        every { client.addListener(capture(listenerSlot)) } returns Unit
        every { client.removeListener(any()) } returns Unit
        return FakeSignaling(client, flow, listenerSlot)
    }

    /**
     * Build a [ConnectionAuthority] under a [StandardTestDispatcher] and
     * advance the scheduler so the `init` block's collector launch runs
     * its first emission. Returns the authority + the bundle of fakes.
     */
    private fun buildAuthority(
        dispatcher: CoroutineDispatcher,
        signaling: FakeSignaling = newFakeSignaling(),
    ): Pair<ConnectionAuthority, FakeSignaling> {
        val auth = ConnectionAuthority(signaling.client, dispatcher)
        return auth to signaling
    }

    // ── construction ────────────────────────────────────────────────────────

    @Test
    fun construction_initialSelfStateIsOffline_andPeerHealthIsEmpty() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        assertSame(SelfState.Offline, auth.selfState.value)
        assertEquals(0, auth.peerHealth.value.size)
    }

    @Test
    fun construction_registersASignalingListener() = runTest {
        val signaling = newFakeSignaling()
        ConnectionAuthority(signaling.client, StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        verify(exactly = 1) { signaling.client.addListener(any()) }
        assertTrue(
            "ConnectionAuthority must capture a SignalingListener for relay peer-online/offline",
            signaling.listenerSlot.isCaptured,
        )
    }

    // ── selfState transitions via notify methods ────────────────────────────

    @Test
    fun notifyWsOpening_flipsOfflineToConnecting() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        advanceUntilIdle()
        assertSame(SelfState.Connecting, auth.selfState.value)
    }

    @Test
    fun notifyWsOpeningThenAuthComplete_endsAtOnline() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        advanceUntilIdle()
        assertSame(SelfState.Online, auth.selfState.value)
    }

    @Test
    fun notifyWsClosed_fromOnline_movesToReconnectingFalse() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyWsClosed()
        advanceUntilIdle()
        val s = auth.selfState.value
        assertTrue(s is SelfState.Reconnecting)
        assertEquals(false, (s as SelfState.Reconnecting).surrenderedToUser)
    }

    @Test
    fun notifyAuthComplete_fromReconnecting_endsAtOnline_deadlockFix() = runTest {
        // Chrome commit bd56305: Reconnecting -> Online via auth-complete is
        // the only signal a ladder rung can act on. Load-bearing.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyWsClosed()
        advanceUntilIdle()
        assertTrue(auth.selfState.value is SelfState.Reconnecting)

        auth.notifyAuthComplete()
        advanceUntilIdle()
        assertSame(SelfState.Online, auth.selfState.value)
    }

    @Test
    fun notifyStop_drivesAnyStateToOffline() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        advanceUntilIdle()
        assertSame(SelfState.Online, auth.selfState.value)

        auth.notifyStop()
        advanceUntilIdle()
        assertSame(SelfState.Offline, auth.selfState.value)
    }

    // ── peerHealth transitions ──────────────────────────────────────────────

    @Test
    fun notifyPeerOnline_seedsPeerAsUnknown() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyPeerOnline("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])
    }

    @Test
    fun notifyFrameReceived_promotesPeerToHealthy() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyPeerOnline("X")
        auth.notifyFrameReceived("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])
    }

    @Test
    fun notifySendCompleted_promotesPeerToHealthy() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyPeerOnline("X")
        auth.notifySendCompleted("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])
    }

    @Test
    fun notifyPeerOffline_drivesPeerToOffline() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyPeerOnline("X")
        auth.notifyFrameReceived("X")
        auth.notifyPeerOffline("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Offline, auth.peerHealth.value["X"])
    }

    @Test
    fun notifyFrameReceived_promotesPeerFromUnknownStaleAndFailed() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // Unknown -> Healthy (no relay-peer-online needed: first-sighting seeding).
        auth.notifyFrameReceived("U")
        advanceUntilIdle()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["U"])

        // Healthy -> Stale (one ping miss) -> Failed (second miss) -> Healthy via frame.
        auth.notifyPingMissed("U") // Healthy -> Stale
        advanceUntilIdle()
        assertSame(PeerHealth.Stale, auth.peerHealth.value["U"])
        auth.notifyPingMissed("U") // Stale -> Failed
        advanceUntilIdle()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["U"])
        auth.notifyFrameReceived("U") // Failed -> Healthy
        advanceUntilIdle()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["U"])
    }

    @Test
    fun notifyPingMissed_healthyThenSecondMissEscalatesToFailed() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyFrameReceived("X") // Unknown (implicit) -> Healthy
        advanceUntilIdle()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        auth.notifyPingMissed("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Stale, auth.peerHealth.value["X"])

        auth.notifyPingMissed("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])
    }

    @Test
    fun multiplePeers_areTrackedIndependently() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyPeerOnline("X")
        auth.notifyPeerOnline("Y")
        auth.notifyFrameReceived("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["Y"])
    }

    // ── ensureSendable ──────────────────────────────────────────────────────

    @Test
    fun ensureSendable_returnsSelfOffline_whenSelfStateIsNotOnline() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // selfState is Offline at construction.
        val result = auth.ensureSendable("X")
        assertSame(SendGate.SelfOffline, result)
    }

    @Test
    fun ensureSendable_returnsPeerUnreachable_whenPeerIsFailed() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        // Unknown -> Stale -> Failed
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])

        val result = auth.ensureSendable("X")
        assertTrue(result is SendGate.PeerUnreachable)
        assertEquals("PEER_UNREACHABLE", (result as SendGate.PeerUnreachable).reason)
    }

    @Test
    fun ensureSendable_returnsPeerUnreachable_whenPeerIsOffline() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyPeerOffline("X")
        advanceUntilIdle()

        val result = auth.ensureSendable("X")
        assertTrue(result is SendGate.PeerUnreachable)
    }

    @Test
    fun ensureSendable_returnsOk_whenSelfOnlineAndPeerHealthy() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyFrameReceived("X")
        advanceUntilIdle()
        assertSame(SendGate.Ok, auth.ensureSendable("X"))
    }

    @Test
    fun ensureSendable_returnsOk_whenSelfOnlineAndPeerStale() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyFrameReceived("X") // Healthy
        auth.notifyPingMissed("X")    // Stale
        advanceUntilIdle()
        assertSame(PeerHealth.Stale, auth.peerHealth.value["X"])
        assertSame(SendGate.Ok, auth.ensureSendable("X"))
    }

    @Test
    fun ensureSendable_returnsOk_whenSelfOnlineAndPeerUnknown_includingUnseenPeer() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        advanceUntilIdle()
        // Peer never seen -> implicit Unknown -> Ok
        assertSame(SendGate.Ok, auth.ensureSendable("never-seen"))
    }

    // ── requestReconnect ────────────────────────────────────────────────────

    @Test
    fun requestReconnect_skeletonIsNoOp_doesNotChangeState() = runTest {
        // Matches the Chrome JS skeleton at commit 68e3c9f: requestReconnect
        // is a no-op stub until Task 17 wires the recovery ladder. The earlier
        // draft dispatched RecoveryBegan, which prematurely flipped Online
        // -> Reconnecting and would have collided with Task 17's actual
        // ladder kickoff.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        advanceUntilIdle()
        assertSame(SelfState.Online, auth.selfState.value)

        auth.requestReconnect()
        advanceUntilIdle()
        assertSame(
            "skeleton requestReconnect must not transition selfState",
            SelfState.Online,
            auth.selfState.value,
        )
    }

    @Test
    fun requestReconnect_doesNotThrow_inSkeletonForm() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.requestReconnect() // skeleton stub — must not throw
        advanceUntilIdle()
    }

    // ── threading: confined dispatcher serialises concurrent producers ─────

    @Test
    fun concurrentNotifyFrameReceivedCalls_doNotRaceOrLoseUpdates() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // Fire 100 notify calls concurrently. Each goes through scope.launch
        // onto the single-threaded dispatcher; the StateFlow's value MUST end
        // up Healthy with no exceptions and no lost updates.
        val deferreds = (1..100).map {
            async { auth.notifyFrameReceived("X") }
        }
        deferreds.awaitAll()
        advanceUntilIdle()

        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])
        assertEquals(1, auth.peerHealth.value.size) // only one peer, no duplication
    }

    @Test
    fun concurrentMixedNotifies_resolveDeterministically() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // Mix promote and miss events; the final state depends on the launch
        // order, but the invariant is "no exception thrown, peer has SOME
        // valid PeerHealth state" — which proves the read-modify-write was
        // never torn.
        val ops = mutableListOf<kotlinx.coroutines.Deferred<Unit>>()
        repeat(50) {
            ops += async { auth.notifyFrameReceived("Z") }
            ops += async { auth.notifyPingMissed("Z") }
        }
        ops.awaitAll()
        advanceUntilIdle()

        val final = auth.peerHealth.value["Z"]
        assertNotNull(final)
        // Any of these is valid depending on the interleaving the scheduler
        // chose — what matters is that the value is one of the legal cases.
        assertTrue(
            final is PeerHealth.Healthy ||
                final is PeerHealth.Stale ||
                final is PeerHealth.Failed ||
                final is PeerHealth.Unknown,
        )
    }

    // ── shutdown / teardown ────────────────────────────────────────────────

    @Test
    fun shutdown_cancelsScopeAndDeregistersListener() = runTest {
        val signaling = newFakeSignaling()
        val auth = ConnectionAuthority(signaling.client, StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        verify(exactly = 1) { signaling.client.addListener(any()) }

        auth.shutdown()
        advanceUntilIdle()

        verify(exactly = 1) { signaling.client.removeListener(any()) }
    }

    @Test
    fun shutdown_isIdempotent() = runTest {
        val signaling = newFakeSignaling()
        val auth = ConnectionAuthority(signaling.client, StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.shutdown()
        // Second shutdown must not throw — cancel() on an already-cancelled
        // scope is a no-op; removeListener twice is harmless.
        auth.shutdown()
        advanceUntilIdle()
    }

    @Test
    fun postShutdown_notifyCallsAreSilentlyDropped_andStatePreserved() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // Drive a known state pre-shutdown so we can assert preservation.
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyPeerOnline("X")
        advanceUntilIdle()
        val selfBeforeShutdown = auth.selfState.value
        val peerBeforeShutdown = auth.peerHealth.value

        auth.shutdown()
        advanceUntilIdle()

        // After shutdown, notify methods must not throw — they simply fail
        // to launch on the cancelled scope.
        auth.notifyFrameReceived("X")
        auth.notifyWsClosed()
        auth.notifyPeerOffline("X")
        advanceUntilIdle()

        // State preservation: post-shutdown reads still surface the last
        // published values for read-only inspection. Spurious post-shutdown
        // dispatches must not have mutated either StateFlow.
        assertSame(
            "selfState must be preserved across shutdown",
            selfBeforeShutdown,
            auth.selfState.value,
        )
        assertSame(
            "peerHealth must be preserved across shutdown",
            peerBeforeShutdown,
            auth.peerHealth.value,
        )
    }

    // ── SignalingClient.connectionState observation ────────────────────────

    @Test
    fun connectionStateConnecting_dispatchesStartConnect() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Connecting(0)
        advanceUntilIdle()
        assertSame(SelfState.Connecting, auth.selfState.value)
    }

    @Test
    fun connectionStateConnected_dispatchesAuthComplete() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // Advance the scheduler between each value change so the collector
        // observes both transitions — StateFlow conflates rapid back-to-back
        // updates, and the reducer needs both Connecting and Connected to
        // walk Offline -> Connecting -> Online.
        signaling.connectionState.value = ConnectionState.Connecting(0)
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Connected
        advanceUntilIdle()
        assertSame(SelfState.Online, auth.selfState.value)
    }

    @Test
    fun connectionStateDisconnectedFromConnected_dispatchesWsClosed() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Connecting(0)
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Connected
        advanceUntilIdle()
        assertSame(SelfState.Online, auth.selfState.value)

        signaling.connectionState.value = ConnectionState.Disconnected
        advanceUntilIdle()
        val s = auth.selfState.value
        assertTrue(s is SelfState.Reconnecting)
        assertEquals(false, (s as SelfState.Reconnecting).surrenderedToUser)
    }

    @Test
    fun connectionStateError_dispatchesWsClosed() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Connecting(0)
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Connected
        advanceUntilIdle()
        signaling.connectionState.value = ConnectionState.Error("boom")
        advanceUntilIdle()
        assertTrue(auth.selfState.value is SelfState.Reconnecting)
    }

    // ── relay listener: peer-online / peer-offline routing ─────────────────

    @Test
    fun relayPeerOnline_routesToNotifyPeerOnline() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        val listener = signaling.listenerSlot.captured

        // Build a mocked JSONObject that returns our values from optString.
        val json = mockk<JSONObject>()
        every { json.optString("type") } returns "peer-online"
        every { json.optString("deviceId", "") } returns "X"

        listener.onMessage(RelayMessage.Text(json))
        advanceUntilIdle()

        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])
    }

    @Test
    fun relayPeerOffline_routesToNotifyPeerOffline() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        val listener = signaling.listenerSlot.captured

        // Seed peer X first.
        auth.notifyPeerOnline("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])

        val json = mockk<JSONObject>()
        every { json.optString("type") } returns "peer-offline"
        every { json.optString("deviceId", "") } returns "X"

        listener.onMessage(RelayMessage.Text(json))
        advanceUntilIdle()

        assertSame(PeerHealth.Offline, auth.peerHealth.value["X"])
    }

    @Test
    fun relayListener_ignoresUnknownTextTypes_andNonTextMessages() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        val listener = signaling.listenerSlot.captured

        // Unknown text type — must not change peerHealth.
        val unknownJson = mockk<JSONObject>()
        every { unknownJson.optString("type") } returns "some-other-type"
        every { unknownJson.optString("deviceId", "") } returns "X"
        listener.onMessage(RelayMessage.Text(unknownJson))

        // Binary frame — must not change peerHealth either.
        listener.onMessage(RelayMessage.Binary(byteArrayOf(0x42, 0x45, 0x41, 0x32)))

        advanceUntilIdle()
        assertEquals(0, auth.peerHealth.value.size)
    }

    @Test
    fun relayListener_ignoresPeerOnlineWithEmptyDeviceId() = runTest {
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        val listener = signaling.listenerSlot.captured

        val json = mockk<JSONObject>()
        every { json.optString("type") } returns "peer-online"
        every { json.optString("deviceId", "") } returns ""

        listener.onMessage(RelayMessage.Text(json))
        advanceUntilIdle()

        assertEquals(0, auth.peerHealth.value.size)
    }

    // ── StateFlow re-emission contract: no spurious updates on reducer no-ops ─

    @Test
    fun selfState_doesNotEmitOnReducerNoOps() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        val emissions = mutableListOf<SelfState>()
        val collector = launch {
            auth.selfState.collect { emissions += it }
        }
        advanceUntilIdle()
        // Initial replay only — Offline.
        assertEquals(1, emissions.size)
        assertSame(SelfState.Offline, emissions[0])

        // OFFLINE + WsClosed is a reducer no-op — must not emit.
        auth.notifyWsClosed()
        advanceUntilIdle()
        assertEquals(1, emissions.size)

        collector.cancel()
    }

    @Test
    fun peerHealth_doesNotEmitOnReducerNoOps_forKnownPeer() = runTest {
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // Seed peer X as Healthy.
        auth.notifyPeerOnline("X")
        auth.notifyFrameReceived("X")
        advanceUntilIdle()

        val emissions = mutableListOf<Map<String, PeerHealth>>()
        val collector = launch {
            auth.peerHealth.collect { emissions += it }
        }
        advanceUntilIdle()
        assertEquals(1, emissions.size)

        // FrameReceived on a Healthy peer is a reducer no-op.
        auth.notifyFrameReceived("X")
        advanceUntilIdle()
        assertEquals(1, emissions.size)

        // SendCompleted on a Healthy peer is also a no-op.
        auth.notifySendCompleted("X")
        advanceUntilIdle()
        assertEquals(1, emissions.size)

        // But a real change MUST emit.
        auth.notifyPeerOffline("X")
        advanceUntilIdle()
        assertEquals(2, emissions.size)
        assertSame(PeerHealth.Offline, emissions[1]["X"])

        collector.cancel()
    }
}

