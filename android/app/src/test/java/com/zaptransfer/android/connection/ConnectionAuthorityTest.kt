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
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
    fun ensureSendable_returnsSelfOffline_whenPeerIsFailedAndLadderHasMovedSelfToReconnecting() = runTest {
        // TODO(Task 18): rewrite this test once the async ensureSendable
        // upgrade lands. The current assertion is a TRANSIENT artefact of
        // the Task 17 ↔ Task 15 interaction described below.
        //
        // Pre-Task 17 this test asserted PEER_UNREACHABLE when a peer is
        // FAILED and self is ONLINE. Task 17 wires the recovery ladder to
        // kick on the peer→FAILED transition and dispatch RecoveryBegan,
        // which drives selfState ONLINE → RECONNECTING. With self no
        // longer ONLINE, the skeleton classifier returns SELF_OFFLINE
        // (matching Chrome's same-precedence rule: self-not-online wins
        // over peer-unreachable).
        //
        // Task 18 (the async ensureSendable upgrade) will return
        // PEER_UNREACHABLE only after the ladder actually exhausts its
        // rungs — at which point the per-call await of the ladder's
        // settle decides the gate. For the synchronous skeleton, the
        // SELF_OFFLINE gate is the right read mid-ladder.
        //
        // Spec reviewer flagged this as a "transient skeleton-period
        // assertion"; the rename + this comment exist to make sure Task 18
        // doesn't ship without revisiting the contract.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        // Unknown -> Stale -> Failed (Failed transition kicks the ladder,
        // which dispatches RecoveryBegan, moving selfState to Reconnecting).
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        advanceUntilIdle()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])
        assertTrue(
            "ladder-kickoff dispatched RecoveryBegan on peer-FAILED",
            auth.selfState.value is SelfState.Reconnecting,
        )

        val result = auth.ensureSendable("X")
        assertSame(
            "self-not-online wins over peer-unreachable in the skeleton classifier",
            SendGate.SelfOffline,
            result,
        )
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

    // ── Task 16: background ping cadence ───────────────────────────────────
    //
    // Mirrors `extension/test/connection-authority.test.js`'s "Task 7"
    // describe block. Each test seeds a peer, advances virtual time across
    // BG_PING_INTERVAL_MS (and PING_TIMEOUT_MS), captures outbound peer-ping
    // wire frames via the injected sendMessage closure, and asserts on:
    //   - which pings fired and to whom (the `sent` list),
    //   - the resulting peerHealth state,
    //   - whether timer jobs leaked (probed via `runCurrent` + a final
    //     `assertEquals(PeerHealth.X, ...)`).
    //
    // The cadence engine's `delay(BG_PING_INTERVAL_MS)` participates in the
    // StandardTestDispatcher's virtual time, so `advanceTimeBy(N)` is the
    // canonical "drive the clock forward" call. `runCurrent()` pumps any
    // microtasks (e.g. the launch body that follows a delay) before we
    // assert.

    /**
     * Bundle of a cadence-enabled authority plus the captured `sent` list
     * of outbound peer-ping wire frames. The injected [PeerPingTracker]
     * uses a fixed `ownDeviceId` so tests can assert on `rendezvousId`.
     */
    private data class CadenceFixture(
        val auth: ConnectionAuthority,
        val signaling: FakeSignaling,
        val sent: MutableList<PeerPingMessage>,
    )

    /**
     * Build an authority with a real [PeerPingTracker] wired to a captured
     * `sent` list. [ownDeviceId] defaults to the JS test's literal so the
     * Kotlin / JS expectations align.
     */
    private fun buildCadenceAuthority(
        dispatcher: CoroutineDispatcher,
        ownDeviceId: String = "self-device-id",
        pingTimeoutMs: Long = PING_TIMEOUT_MS,
    ): CadenceFixture {
        val signaling = newFakeSignaling()
        val sent = mutableListOf<PeerPingMessage>()
        val tracker = PeerPingTracker(
            sendMessage = { sent += it },
            timeoutMs = pingTimeoutMs,
            ownDeviceId = ownDeviceId,
        )
        val auth = ConnectionAuthority(signaling.client, dispatcher, tracker)
        return CadenceFixture(auth, signaling, sent)
    }

    @Test
    fun cadence_schedulesAPingAtBgPingIntervalMs_whenPeerComesOnline() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        // IMPORTANT: use `runCurrent()`, NOT `advanceUntilIdle()`, between
        // notify calls and explicit time advancements. `advanceUntilIdle`
        // would advance virtual time to whatever delayed task is pending
        // — including the cadence's own `delay(BG_PING_INTERVAL_MS)` — and
        // then keep firing the next-ping reschedule chain forever, which
        // OOMs the JVM.
        runCurrent()

        // Just before 120s: no ping yet.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS - 1)
        runCurrent()
        assertEquals("no ping before 120s", 0, sent.size)

        // At exactly 120s: peer-ping is sent for X.
        testScheduler.advanceTimeBy(1)
        runCurrent()
        assertEquals("ping fires at 120s", 1, sent.size)
        assertEquals("peer-ping", sent[0].type)
        assertEquals("X", sent[0].targetDeviceId)
        assertEquals("self-device-id", sent[0].rendezvousId)
        assertTrue("nonce is non-empty", sent[0].nonce.isNotEmpty())

        // Cadence is still armed (timeoutJob counting down at virtual_time=130s);
        // shutdown drops it before runTest's cleanup so we don't leak.
        auth.shutdown()
    }

    @Test
    fun cadence_pongWithinDeadline_promotesToHealthyAndReschedules() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()

        // Drive to first ping fire.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals(1, sent.size)
        val nonce = sent[0].nonce

        // Pong arrives 5s later (well inside the 10s timeout).
        testScheduler.advanceTimeBy(5_000)
        auth.notifyPongReceived(nonce)
        runCurrent()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        // Next ping is scheduled for now + 120s. Tick to just before, then to it.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS - 1)
        runCurrent()
        assertEquals("no second ping until 120s after pong", 1, sent.size)
        testScheduler.advanceTimeBy(1)
        runCurrent()
        assertEquals("second ping fires 120s after pong", 2, sent.size)
        assertEquals("X", sent[1].targetDeviceId)

        auth.shutdown()
    }

    @Test
    fun cadence_twoConsecutiveMissedPings_escalateUnknownToStaleToFailed() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])

        // First ping at t=120s, no pong, timeout at t=130s -> Stale.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals("first ping fires", 1, sent.size)
        testScheduler.advanceTimeBy(PING_TIMEOUT_MS)
        runCurrent()
        assertSame(PeerHealth.Stale, auth.peerHealth.value["X"])

        // Second cycle: next ping at t=250s, timeout at t=260s -> Failed.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals("second ping fires", 2, sent.size)
        testScheduler.advanceTimeBy(PING_TIMEOUT_MS)
        runCurrent()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])

        auth.shutdown()
    }

    @Test
    fun cadence_offlinePeer_isSkipped_noPingsFired() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        auth.notifyPeerOffline("X")
        runCurrent()
        assertSame(PeerHealth.Offline, auth.peerHealth.value["X"])

        // Advance well past the cadence interval. The cadence entry has been
        // torn down on offline; even if a tick fired, the OFFLINE check
        // would skip the send.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS * 3)
        runCurrent()
        assertEquals("no ping issued to OFFLINE peer", 0, sent.size)

        auth.shutdown()
    }

    @Test
    fun cadence_frameReceivedMidWindow_resetsTheNextPingTimer() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()

        // At t=100s a real frame arrives — reschedule for 100 + 120 = 220s.
        testScheduler.advanceTimeBy(100_000)
        auth.notifyFrameReceived("X")
        runCurrent()

        // At t=120s (the original schedule) no ping should fire.
        testScheduler.advanceTimeBy(20_000)
        runCurrent()
        assertEquals("frame at t=100 must push ping past t=120", 0, sent.size)

        // At t=220s the rescheduled ping fires.
        testScheduler.advanceTimeBy(99_999)
        runCurrent()
        assertEquals("no ping just before t=220", 0, sent.size)
        testScheduler.advanceTimeBy(1)
        runCurrent()
        assertEquals("ping fires at t=220 (reset by frame)", 1, sent.size)

        auth.shutdown()
    }

    @Test
    fun cadence_sendCompletedMidWindow_resetsTheNextPingTimer_sameAsFrameReceived() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()

        testScheduler.advanceTimeBy(60_000)
        auth.notifySendCompleted("X")
        runCurrent()

        // Original schedule was t=120s; new schedule is t=60+120 = 180s.
        testScheduler.advanceTimeBy(60_000) // now t=120s
        runCurrent()
        assertEquals("send-completed at t=60 must reschedule past t=120", 0, sent.size)

        testScheduler.advanceTimeBy(60_000) // now t=180s
        runCurrent()
        assertEquals("ping fires at t=180 (60s + 120s)", 1, sent.size)

        auth.shutdown()
    }

    @Test
    fun cadence_inFlightPing_isNotInterruptedByActivity() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()

        // First ping fires at t=120s; timeout armed.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals(1, sent.size)
        val nonce = sent[0].nonce

        // 5s into the timeout, a frame arrives. The cadence MUST NOT cancel
        // the timeout (would leak the tracker entry); the in-flight ping
        // settles via pong or timeout. The frame still promotes the peer
        // through the reducer.
        testScheduler.advanceTimeBy(5_000)
        auth.notifyFrameReceived("X")
        runCurrent()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        // Pong within the 10s deadline still works (4s more = 9s in total).
        testScheduler.advanceTimeBy(4_000)
        auth.notifyPongReceived(nonce)
        runCurrent()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        auth.shutdown()
    }

    @Test
    fun cadence_offlineToUnknownViaRelayPeerOnline_restartsCadence() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        auth.notifyPeerOffline("X")
        runCurrent()
        assertSame(PeerHealth.Offline, auth.peerHealth.value["X"])

        auth.notifyPeerOnline("X")
        runCurrent()
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])

        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals("cadence resumes after relay-peer-online resurrects peer", 1, sent.size)
        assertEquals("X", sent[0].targetDeviceId)

        auth.shutdown()
    }

    @Test
    fun cadence_unknownNonceInNotifyPongReceived_isASilentNoOp() = runTest {
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        // No ping in flight yet — pong with a fabricated nonce is ignored.
        auth.notifyPongReceived("fabricated-nonce")
        runCurrent()
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])

        auth.shutdown()
    }

    @Test
    fun cadence_multiplePeers_runIndependentCadenceLoops() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        testScheduler.advanceTimeBy(30_000)        // t=30
        auth.notifyPeerOnline("Y")                 // Y due at 30 + 120 = 150
        runCurrent()

        testScheduler.advanceTimeBy(90_000)        // t=120 — X due now
        runCurrent()
        assertEquals("X fires at t=120", 1, sent.size)
        assertEquals("X", sent[0].targetDeviceId)

        testScheduler.advanceTimeBy(30_000)        // t=150 — Y due now
        runCurrent()
        assertEquals("Y fires at t=150 (30 + 120)", 2, sent.size)
        assertEquals("Y", sent[1].targetDeviceId)

        auth.shutdown()
    }

    @Test
    fun cadence_doesNotFire_whenAuthorityHasNoPingTracker() = runTest {
        // Skeleton-mode (no tracker injected) — the existing two-arg
        // constructor path used by every Task 15 test. notifyPeerOnline
        // should still seed peer-health (Unknown) but no ping should fire,
        // because ensureCadenceFor short-circuits when the tracker is null.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS * 3)
        runCurrent()
        // No assertion on sent: we have no tracker to capture from. The
        // assertion here is that the test doesn't hang (no ping coroutine
        // waiting to fire) and the peer-health state is the expected
        // skeleton-mode value.
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])

        auth.shutdown()
    }

    @Test
    fun cadence_shutdownCancelsAllJobs_noLeakedCoroutines() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        auth.notifyPeerOnline("Y")
        runCurrent()

        // Pre-shutdown: each peer has an armed pingJob counting down to 120s.
        // Drive halfway through the first cycle to prove the jobs are alive.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS / 2)
        runCurrent()
        assertEquals("no pings fired yet at t=60s", 0, sent.size)

        auth.shutdown()
        runCurrent()

        // Post-shutdown: advance well past the cadence interval. No new
        // pings should fire — every cadence job was cancelled by shutdown.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS * 5)
        runCurrent()
        assertEquals("no pings fire after shutdown", 0, sent.size)
    }

    @Test
    fun cadence_shutdownClearsInFlightTimeout() = runTest {
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        // Drive to first ping fire (timeout job armed).
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals(1, sent.size)
        val healthBeforeShutdown = auth.peerHealth.value["X"]

        auth.shutdown()
        runCurrent()
        // Past the original timeout deadline: if the timeout job had not
        // been cancelled, peerHealth would have escalated UNKNOWN -> STALE
        // here. Since shutdown cancelled it, peerHealth stays as it was.
        testScheduler.advanceTimeBy(PING_TIMEOUT_MS * 2)
        runCurrent()
        assertSame(
            "shutdown must cancel the in-flight timeout job",
            healthBeforeShutdown,
            auth.peerHealth.value["X"],
        )
    }

    @Test
    fun cadence_notifyPongReceived_afterShutdown_isSilentlyDropped() = runTest {
        // Symmetric to postShutdown_notifyCallsAreSilentlyDropped_andStatePreserved
        // but exercises the pong path that was added in Task 16. After
        // shutdown, the cancelled scope rejects new launches, so the late
        // pong leaves both StateFlows untouched.
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        // Send a ping so a nonce is in-flight, then capture state, shut down,
        // then deliver the pong AFTER shutdown.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals(1, sent.size)
        val nonce = sent[0].nonce
        val healthBeforeShutdown = auth.peerHealth.value["X"]

        auth.shutdown()
        runCurrent()

        auth.notifyPongReceived(nonce)
        runCurrent()

        // The post-shutdown pong must NOT promote the peer (no PongReceived
        // dispatch), and must not throw.
        assertSame(
            "post-shutdown pong must leave peerHealth unchanged",
            healthBeforeShutdown,
            auth.peerHealth.value["X"],
        )
    }

    @Test
    fun cadence_relayListenerHandlesPeerPongWireMessage() = runTest {
        val (auth, signaling, sent) =
            buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        val listener = signaling.listenerSlot.captured

        auth.notifyPeerOnline("X")
        runCurrent()
        // Drive to first ping fire so we know the nonce.
        testScheduler.advanceTimeBy(BG_PING_INTERVAL_MS)
        runCurrent()
        assertEquals(1, sent.size)
        val nonce = sent[0].nonce

        // Simulate the relay routing back a peer-pong wire frame. The
        // listener pulls "nonce" out and forwards to notifyPongReceived;
        // peerHealth should promote to Healthy.
        val pongJson = mockk<JSONObject>()
        every { pongJson.optString("type") } returns "peer-pong"
        every { pongJson.optString("nonce", "") } returns nonce
        listener.onMessage(RelayMessage.Text(pongJson))
        runCurrent()

        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        auth.shutdown()
    }

    // ── Task 17: recovery ladder wiring ────────────────────────────────────
    //
    // Mirrors `extension/test/connection-authority.test.js`'s
    // `describe('ConnectionAuthority: recovery ladder wiring')`. Each test
    // builds a cadence-enabled authority (so the rung 1 register-rendezvous
    // frame gets a real ownDeviceId in scope) and asserts on:
    //   - which transitions kick the ladder (peer→FAILED, self→RECONNECTING),
    //   - single-flight discipline (concurrent FAILED peers share the ladder),
    //   - rung 1 success path (peer becomes HEALTHY → ladder lifts state),
    //   - rung 2 invocation when rung 1 budget elapses (mock disconnect/connect),
    //   - shutdown cancels the ladder cleanly.
    //
    // The cadence helper [buildCadenceAuthority] supplies a captured `sent`
    // list so we can introspect the register-rendezvous frame the ladder
    // emits via the mocked SignalingClient.send adapter.

    @Test
    fun ladder_kicksWhenAPeerCrossesIntoFailed() = runTest {
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        // Simulate two consecutive cadence-pings missed → STALE → FAILED.
        auth.notifyPeerOnline("X")
        runCurrent()
        auth.notifyPingMissed("X") // Unknown -> Stale
        auth.notifyPingMissed("X") // Stale -> Failed (kicks ladder)
        runCurrent()

        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])
        assertNotNull("ladder is active after peer->FAILED", auth.currentLadder)

        // Rung 1 dispatched a register-rendezvous via SignalingClient.send.
        // Drive virtual time past Rung 1+2 budgets to drain the ladder
        // cleanly before shutdown.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        assertNull("ladder cleared after exhaustion", auth.currentLadder)

        auth.shutdown()
        // Verify the disconnect/connect calls happened during Rung 2.
        verify(atLeast = 1) { signaling.client.disconnect() }
        verify(atLeast = 1) { signaling.client.connect(any()) }
    }

    @Test
    fun ladder_singleFlight_secondFailedPeerDoesNotStartASecondLadder() = runTest {
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()

        auth.notifyPeerOnline("X")
        auth.notifyPeerOnline("Y")
        runCurrent()

        // Drive X → FAILED → kick ladder #1.
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        val firstLadder = auth.currentLadder
        assertNotNull("first FAILED peer kicks the ladder", firstLadder)

        // Now drive Y → FAILED. Single-flight discipline says the existing
        // ladder is reused; currentLadder must remain the same instance.
        auth.notifyPingMissed("Y")
        auth.notifyPingMissed("Y")
        runCurrent()
        assertSame(
            "second FAILED peer must not replace the in-flight ladder",
            firstLadder,
            auth.currentLadder,
        )

        // Drain to exhaustion before shutdown so we don't leak.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()
    }

    @Test
    fun ladder_kicksWhenSelfCrossesToReconnecting_viaWsClosed() = runTest {
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        // Drive selfState to ONLINE first, so notifyWsClosed is a real
        // ONLINE -> RECONNECTING transition (the trigger we care about).
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        assertSame(SelfState.Online, auth.selfState.value)
        assertNull("no ladder while ONLINE", auth.currentLadder)

        auth.notifyWsClosed()
        runCurrent()
        assertTrue(
            "selfState transitioned into Reconnecting",
            auth.selfState.value is SelfState.Reconnecting,
        )
        assertNotNull(
            "self->RECONNECTING transition kicks the ladder",
            auth.currentLadder,
        )

        // Drain.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()
    }

    @Test
    fun ladder_rung1Success_liftsSelfStateAndPeerHealth() = runTest {
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()

        auth.notifyPeerOnline("X")
        runCurrent()
        // Drive X -> FAILED to kick the ladder.
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])
        assertNotNull(auth.currentLadder)

        // Now mid-Rung 1, a frame arrives from X. The reducer promotes X
        // to HEALTHY directly; the ladder's success-criterion observer
        // (peer X is HEALTHY) fires and Rung 1 returns true → ladder
        // dispatches RecoverySucceeded.
        testScheduler.advanceTimeBy(2_000L)
        auth.notifyFrameReceived("X")
        runCurrent()
        // Allow the ladder's settle handler to run on the worker thread.
        runCurrent()

        // Once the ladder settles via Success, currentLadder is cleared
        // and selfState is dispatched RecoverySucceeded which lifts any
        // RECONNECTING back to ONLINE. PeerHealth was already HEALTHY via
        // the FrameReceived dispatch.
        assertNull("ladder released after Rung 1 success", auth.currentLadder)
        assertSame(SelfState.Online, auth.selfState.value)
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        // Shut down BEFORE runTest's teardown advances virtual time; X's
        // cadence delay(120000) is still armed and would otherwise drive
        // an unbounded reschedule loop. Same gotcha as the Task 16
        // cadence tests.
        auth.shutdown()
    }

    @Test
    fun ladder_rung1Timeout_fallsThroughToRung2WhichInvokesSignalingClientDisconnectConnect() = runTest {
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        assertNotNull(auth.currentLadder)

        // Advance past Rung 1's 5s budget. The withTimeoutOrNull inside
        // rung1Action resolves null, the action returns false, and the
        // ladder advances to Rung 2 which calls signalingClient.disconnect()
        // + signalingClient.connect().
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + 1L)
        runCurrent()

        verify(atLeast = 1) { signaling.client.disconnect() }
        verify(atLeast = 1) { signaling.client.connect(any()) }

        // Drain Rung 2's 15s budget so it surrenders cleanly.
        testScheduler.advanceTimeBy(RUNG_2_BUDGET_MS + 1L)
        runCurrent()
        assertNull("ladder cleared after Rung 2 exhaustion", auth.currentLadder)

        auth.shutdown()
    }

    @Test
    fun ladder_exhaustion_keepsSelfStateInReconnecting_noSurrender() = runTest {
        // Task 17 does NOT yet dispatch RecoveryGivenUp on exhaustion —
        // Rung 4 surrender lands in the follow-up task. Verify selfState
        // stays Reconnecting(false) after the ladder gives up.
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        auth.notifyWsClosed() // Online -> Reconnecting kicks ladder.
        runCurrent()

        // Drive past both budgets so the ladder exhausts.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()

        assertNull("ladder cleared after exhaustion", auth.currentLadder)
        val s = auth.selfState.value
        assertTrue("selfState stays Reconnecting on exhaustion", s is SelfState.Reconnecting)
        assertEquals(
            "surrender flag must NOT be set on Task 17 exhaustion",
            false,
            (s as SelfState.Reconnecting).surrenderedToUser,
        )

        auth.shutdown()
    }

    @Test
    fun ladder_shutdownCancelsTheInFlightLadder() = runTest {
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        assertNotNull(auth.currentLadder)

        auth.shutdown()
        runCurrent()

        // After shutdown the field is cleared and no further coroutine
        // work happens. Advancing virtual time past both budgets must NOT
        // cause any selfState transitions or unexpected dispatches.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        assertNull(auth.currentLadder)
    }

    @Test
    fun ladder_rung1SelfTrigger_succeedsWhenSelfBackOnlineAndAnyPeerHealthy() = runTest {
        // Self-RECONNECTING kick (no triggerPeerId): Rung 1's success
        // criterion is (selfState=Online AND any peer Healthy). Drive
        // the ladder by closing the WS, then mid-Rung 1, drive both
        // sides true and verify the ladder lifts.
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        // Seed a peer so it can later go HEALTHY.
        auth.notifyPeerOnline("X")
        runCurrent()

        auth.notifyWsClosed() // Online -> Reconnecting kicks ladder.
        runCurrent()
        assertNotNull(auth.currentLadder)

        // 1s into the rung, a frame arrives from X (promotes X to HEALTHY)
        // AND the WS auth-completes (lifts selfState back to Online).
        testScheduler.advanceTimeBy(1_000L)
        auth.notifyFrameReceived("X")
        runCurrent()
        auth.notifyAuthComplete() // Reconnecting -> Online (deadlock-fix path)
        runCurrent()
        // Ladder's combine-predicate fires; settle handler runs.
        runCurrent()

        assertNull("ladder released after Rung 1 self-trigger success", auth.currentLadder)
        assertSame(SelfState.Online, auth.selfState.value)

        // Shut down BEFORE runTest's teardown advances virtual time; the
        // cadence engine's delay(120000) for X is still armed and would
        // otherwise drive an unbounded reschedule loop. Same gotcha as
        // the Task 16 cadence tests.
        auth.shutdown()
    }

    @Test
    fun ladder_doesNotKickOnReconnectingToReconnectingTransition() = runTest {
        // When selfState is already Reconnecting, a second trigger that
        // would re-enter Reconnecting MUST NOT re-kick the ladder — the
        // existing ladder owns the floor. Verify by driving WsClosed
        // twice in a row.
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()

        auth.notifyWsClosed() // Online -> Reconnecting (kick #1)
        runCurrent()
        val firstLadder = auth.currentLadder
        assertNotNull(firstLadder)

        auth.notifyWsClosed() // Reconnecting -> Reconnecting (no transition, no kick)
        runCurrent()
        assertSame(
            "no new ladder on Reconnecting -> Reconnecting (reducer no-op)",
            firstLadder,
            auth.currentLadder,
        )

        // Drain so we don't leak coroutines.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()
    }
}

