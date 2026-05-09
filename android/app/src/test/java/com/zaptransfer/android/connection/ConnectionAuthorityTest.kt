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
import kotlinx.coroutines.test.TestScope
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
        // Pre-Step-E this used `advanceUntilIdle()` and asserted
        // surrenderedToUser=false. Task 20 / Step E adds Rung 4 surrender
        // promotion, which means a fully-drained ladder ends in
        // Reconnecting(true) — not the immediate state this test was
        // pinning. Switch to `runCurrent()` to capture the post-WsClosed
        // tick BEFORE the ladder runs to surrender; shutdown afterward
        // cancels the in-flight ladder cleanly so runTest's teardown
        // doesn't drive virtual time through the backoff loop.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyWsClosed()
        runCurrent()
        val s = auth.selfState.value
        assertTrue(s is SelfState.Reconnecting)
        assertEquals(false, (s as SelfState.Reconnecting).surrenderedToUser)
        auth.shutdown()
    }

    @Test
    fun notifyAuthComplete_fromReconnecting_endsAtOnline_deadlockFix() = runTest {
        // Chrome commit bd56305: Reconnecting -> Online via auth-complete is
        // the only signal a ladder rung can act on. Load-bearing.
        // Step-E note: the WsClosed kicks the ladder. The ladder's Rung 1
        // self-trigger requires (selfState=Online AND any peer Healthy);
        // with no peers seeded the predicate never fires and the ladder
        // would advance through Rungs 2+3 and surrender (Reconnecting(true))
        // even though we drove selfState to Online via notifyAuthComplete.
        // To pin the IMMEDIATE Reconnecting->Online deadlock-fix transition
        // without coupling to the ladder's success criterion, use
        // runCurrent + explicit shutdown.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        auth.notifyWsClosed()
        runCurrent()
        assertTrue(auth.selfState.value is SelfState.Reconnecting)

        auth.notifyAuthComplete()
        runCurrent()
        assertSame(SelfState.Online, auth.selfState.value)
        auth.shutdown()
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

    // ── ensureSendable: pre-task-18 skeleton-only invariants ───────────────

    @Test
    fun ensureSendable_returnsSelfOffline_whenSelfStateIsNotOnline() = runTest {
        // Step 1 of the algorithm short-circuits BEFORE the per-peer
        // coalescing map is consulted, so this test stays valid under the
        // async upgrade — no probe, no ladder, no virtual-time advancement
        // needed.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        advanceUntilIdle()
        // selfState is Offline at construction.
        val result = auth.ensureSendable("X")
        assertSame(SendGate.SelfOffline, result)
    }

    // ── requestReconnect ────────────────────────────────────────────────────

    @Test
    fun requestReconnect_fromOnline_kicksRung3Ladder_movesToReconnecting() = runTest {
        // Task 20 / Step F: requestReconnect is no longer a no-op. It
        // cancels any in-flight ladder, drops the surrender flag, resets
        // the thrash log + backoff attempt, and kicks a fresh Rung-3-only
        // ladder. The IMMEDIATE observable effect is the RecoveryBegan
        // dispatch — selfState moves Online -> Reconnecting(false). Use
        // runCurrent to capture the immediate state then shutdown to halt
        // the ladder before runTest's teardown drives it through Rung 3
        // surrender (which has its own runCurrent-friendly synchronous
        // false-return in skeleton mode).
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        assertSame(SelfState.Online, auth.selfState.value)

        auth.requestReconnect()
        runCurrent()
        assertTrue(
            "requestReconnect dispatches RecoveryBegan -> Reconnecting",
            auth.selfState.value is SelfState.Reconnecting,
        )
        auth.shutdown()
    }

    @Test
    fun requestReconnect_kicksRung3OnlyLadder_skipsRungs1and2() = runTest {
        // Task 20 / Step F: requestReconnect kicks a Rung-3-only ladder
        // (mirrors Chrome's `_buildRung3OnlyLadder`). Rung 1 dispatches
        // register-rendezvous via `signalingClient.send`; Rung 2 calls
        // disconnect/connect. A Rung-3-only ladder skips both — observable
        // as zero `send`/`disconnect`/`connect` calls during the
        // post-requestReconnect tick. Rung 3 in skeleton mode (no
        // forceFullReset) returns false synchronously, so the ladder
        // exhausts inside the same runCurrent.
        //
        // After the synchronous Rung 3 surrender, `handleLadderSettled`
        // runs Exhausted -> non-surrender ladder -> recordRung3Failure +
        // promoteToRung4 -> surrenderedToUser=true again. So we can't
        // assert on the surrender flag's intermediate cleared state from
        // the test without a more invasive instrumentation. Instead, we
        // pin the structural invariant: the Rung-3-only ladder did not
        // call send/disconnect/connect.
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        // Snapshot signaling counts BEFORE requestReconnect — should be 0
        // for all three because we haven't kicked any auto-recovery ladder.

        auth.requestReconnect()
        runCurrent()

        auth.shutdown()

        // No Rung-1 register-rendezvous send, no Rung-2 disconnect/connect.
        verify(exactly = 0) { signaling.client.send(any()) }
        verify(exactly = 0) { signaling.client.disconnect() }
        verify(exactly = 0) { signaling.client.connect(any()) }
    }

    @Test
    fun requestReconnect_doesNotThrow() = runTest {
        // Smoke test — even from cold-boot Offline state, requestReconnect
        // must not throw. The ladder kicks anyway (Rung 3 from any state),
        // but with no forceFullReset it surrenders synchronously.
        val (auth, _) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.requestReconnect()
        runCurrent()
        auth.shutdown()
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
        // Pre-Step-E this used `advanceUntilIdle()` after the Disconnected
        // transition. Task 20 / Step E adds Rung 4 surrender promotion,
        // so a fully-drained ladder would surrender the state machine to
        // Reconnecting(true) and the assertion `surrenderedToUser=false`
        // would fail. The intent here is the IMMEDIATE post-Disconnected
        // transition — switch to runCurrent + explicit shutdown to keep
        // the assertion focused.
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        signaling.connectionState.value = ConnectionState.Connecting(0)
        runCurrent()
        signaling.connectionState.value = ConnectionState.Connected
        runCurrent()
        assertSame(SelfState.Online, auth.selfState.value)

        signaling.connectionState.value = ConnectionState.Disconnected
        runCurrent()
        val s = auth.selfState.value
        assertTrue(s is SelfState.Reconnecting)
        assertEquals(false, (s as SelfState.Reconnecting).surrenderedToUser)
        auth.shutdown()
    }

    @Test
    fun connectionStateError_dispatchesWsClosed() = runTest {
        // See [connectionStateDisconnectedFromConnected_dispatchesWsClosed] —
        // same Step-E adjustment: assert IMMEDIATE post-Error state via
        // runCurrent, shutdown explicitly to halt the ladder before
        // runTest's teardown drives it to surrender.
        val (auth, signaling) = buildAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        signaling.connectionState.value = ConnectionState.Connecting(0)
        runCurrent()
        signaling.connectionState.value = ConnectionState.Connected
        runCurrent()
        signaling.connectionState.value = ConnectionState.Error("boom")
        runCurrent()
        assertTrue(auth.selfState.value is SelfState.Reconnecting)
        auth.shutdown()
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
    //
    // Two test-suite-wide gotchas apply across this and the Task 16 cadence
    // section above (consolidated here for the deferred Task 17 fold-ins):
    //
    //   1. Use `runCurrent()`, NOT `advanceUntilIdle()`, between notify
    //      calls and explicit time advancements. `advanceUntilIdle` can
    //      hop onto the cadence's `delay(BG_PING_INTERVAL_MS)` and
    //      reschedule forever in virtual time, OOMing the JVM. (Same
    //      gotcha called out in the Task 16 KDoc above.)
    //   2. Mockk introspection (`verify`, especially `capture(list)`)
    //      against the relaxed [SignalingClient] mock while the ladder /
    //      cadence supervisor scope is still alive triggers a test-JVM
    //      OOM under [StandardTestDispatcher] (~140s heap exhaustion in
    //      isolation). Drain the ladder to exhaustion AND call
    //      `auth.shutdown()` BEFORE introspecting. Plain-matcher `verify`
    //      with no `capture` is also fine post-shutdown; capture against
    //      a relaxed mock is the specific OOM trap.
    //   3. `isReturnDefaultValues = true` (see app/build.gradle.kts) makes
    //      `org.json.JSONObject` an opaque default mock — its
    //      `put`/`optString`/etc. are no-ops returning defaults, so wire-
    //      frame *content* assertions (matching Chrome JS's
    //      `registerFrame.rendezvousId === 'self-device-id'`) cannot be
    //      expressed without Robolectric or a gson workaround. The
    //      Android tests assert call-count invariants instead.

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
    fun ladder_rung1_invokesSignalingClientSendExactlyOnce() = runTest {
        // Android counterpart of Chrome JS lines 619-625 (which assert
        // `registerFrame.rendezvousId === 'self-device-id'`). Wire-frame
        // *content* is unverifiable here (gotcha #3 above), so assert the
        // structural invariant: Rung 1 dispatches exactly one outbound
        // JSON frame on first kick.
        //
        // The `send(any()) exactly = 1` assertion is load-bearing on Rung
        // 2 NOT calling `send` (it calls `disconnect()`/`connect()`
        // separately — see ConnectionAuthority.kt:706-707). The
        // disconnect/connect verifies pin that Rung 2 actually ran, so a
        // future Rung-2 refactor that adds a `send` call breaks this test
        // unambiguously (count goes 1→2 AND Rung 2 still happened).
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()

        auth.notifyPeerOnline("X")
        runCurrent()
        auth.notifyPingMissed("X") // Unknown -> Stale
        auth.notifyPingMissed("X") // Stale -> Failed (kicks ladder)
        runCurrent()
        assertNotNull("ladder kicked on peer->FAILED", auth.currentLadder)

        // Drain to exhaustion and shut down before introspecting the mock
        // (gotcha #2 above).
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()

        verify(exactly = 1) { signaling.client.send(any()) }
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
    fun ladder_singleFlight_secondKickEmitsNoExtraSignalingClientSend() = runTest {
        // Belt-and-suspenders for [ladder_singleFlight_secondFailedPeer...].
        // That test asserts `currentLadder` reference identity stays stable
        // across a second peer-FAILED kick; this one proves no extra
        // outbound wire frame leaks either. Android counterpart of Chrome
        // JS lines 645-653 — the count-based assertion captures the
        // single-flight invariant without needing JSONObject content
        // (gotcha #3 above).
        //
        // Like the rung1 test above, this assertion is load-bearing on
        // Rung 2 NOT calling `send`. The disconnect/connect verifies pin
        // that Rung 2 ran exactly once (not twice), so a future bug where
        // the absorbed kick somehow advanced through Rungs 1+2 again
        // would fail loudly.
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()

        auth.notifyPeerOnline("X")
        auth.notifyPeerOnline("Y")
        runCurrent()

        // Drive X -> FAILED -> kick #1 (Rung 1 dispatches one send).
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()

        // Drive Y -> FAILED -> would-be-kick #2. Single-flight discipline
        // must absorb it without dispatching a second register-rendezvous.
        auth.notifyPingMissed("Y")
        auth.notifyPingMissed("Y")
        runCurrent()

        // Drain + shutdown before introspecting (gotcha #2 above).
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()

        verify(exactly = 1) { signaling.client.send(any()) }
        verify(exactly = 1) { signaling.client.disconnect() }
        verify(exactly = 1) { signaling.client.connect(any()) }
    }

    @Test
    fun ladder_singleFlight_peerFailedThenSelfReconnectingShareTheLadder() = runTest {
        // Reverse-ordering mirror of
        // [ladder_singleFlight_selfReconnectingAndPeerFailedShareTheLadder]
        // — that one tests self-trigger first; this one tests peer-trigger
        // first then self. The single-flight guard at
        // ConnectionAuthority.kt:564-566 is symmetric by construction, but
        // symmetric-by-inspection isn't symmetric-by-test.
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        assertSame(SelfState.Online, auth.selfState.value)

        // Peer-trigger fires first: drive X -> FAILED -> kick #1.
        auth.notifyPeerOnline("X")
        runCurrent()
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        val firstLadder = auth.currentLadder
        assertNotNull("peer->FAILED transition kicks the ladder", firstLadder)
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])

        // Self-trigger second: WsClosed would normally kick a ladder via
        // the Online->Reconnecting transition's post-hook, but
        // single-flight discipline must absorb it into the existing
        // instance.
        auth.notifyWsClosed()
        runCurrent()
        assertSame(
            "peer+self triggers must share the in-flight ladder regardless of order",
            firstLadder,
            auth.currentLadder,
        )

        // Drain + shutdown.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()

        verify(exactly = 1) { signaling.client.send(any()) }
        verify(exactly = 1) { signaling.client.disconnect() }
        verify(exactly = 1) { signaling.client.connect(any()) }
    }

    @Test
    fun ladder_singleFlight_selfReconnectingAndPeerFailedShareTheLadder() = runTest {
        // Belt-and-suspenders for the two-FAILED-peers single-flight test:
        // verify that a self-trigger and a peer-trigger landing in the same
        // tick share one ladder rather than starting two. The Chrome JS
        // counterpart tests both orderings too, but the assertion is the
        // same — `currentLadder` reference identity stays stable across the
        // second trigger.
        //
        // Sequence: drive self ONLINE, then notifyWsClosed (Online ->
        // Reconnecting kicks ladder #1 with triggerPeerId=null), then drive
        // a peer through Stale -> Failed. The peer->FAILED transition would
        // normally kick a peer-trigger ladder; the single-flight guard in
        // [ConnectionAuthority.kickLadder] absorbs it.
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        assertSame(SelfState.Online, auth.selfState.value)

        // Seed peer X so it can later go Failed.
        auth.notifyPeerOnline("X")
        runCurrent()

        // Self-trigger fires first: Online -> Reconnecting kicks ladder #1.
        auth.notifyWsClosed()
        runCurrent()
        val firstLadder = auth.currentLadder
        assertNotNull("self->RECONNECTING transition kicks the ladder", firstLadder)
        assertTrue(
            "selfState moved into Reconnecting on WsClosed",
            auth.selfState.value is SelfState.Reconnecting,
        )

        // Now drive X -> FAILED. The peer-trigger normally kicks a ladder
        // too, but single-flight discipline must absorb it into the
        // existing instance.
        auth.notifyPingMissed("X") // Unknown -> Stale
        auth.notifyPingMissed("X") // Stale -> Failed (would normally kick)
        runCurrent()
        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])
        assertSame(
            "self+peer triggers must share the in-flight ladder",
            firstLadder,
            auth.currentLadder,
        )

        // Drain to exhaustion before shutdown so we don't leak coroutines.
        // RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS = 20s; the +1s margin matches
        // the existing two-FAILED-peers test.
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
    fun ladder_exhaustion_promotesToRung4_setsSurrenderFlag() = runTest {
        // Task 20 update: was previously the "no surrender on exhaustion"
        // test (Task 17 deferred Rung 4). Now that Rung 4 is wired, an
        // exhausted ladder dispatches `RecoveryGivenUp`, which the
        // selfState reducer translates into Reconnecting(surrenderedToUser=true),
        // and the authority's [surrenderedToUser] flag flips to true.
        // The Rung-4 backoff timer is also armed but is cancelled by the
        // shutdown() at the end of the test BEFORE the test scheduler can
        // advance to its 30s deadline.
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        auth.notifyWsClosed() // Online -> Reconnecting kicks ladder.
        runCurrent()

        // Drive past both budgets so the ladder exhausts. Rung 3 surrenders
        // synchronously in skeleton mode (no forceFullReset hook).
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()

        assertNull("ladder cleared after exhaustion", auth.currentLadder)
        val s = auth.selfState.value
        assertTrue("selfState stays Reconnecting on exhaustion", s is SelfState.Reconnecting)
        assertEquals(
            "surrender flag IS set after Task 20 Rung 4 promotion",
            true,
            (s as SelfState.Reconnecting).surrenderedToUser,
        )
        assertEquals(
            "authority surrenderedToUser tracks the dispatched state",
            true,
            auth.surrenderedToUser,
        )

        // shutdown() cancels the still-armed Rung-4 backoff timer cleanly.
        auth.shutdown()
    }

    @Test
    fun ladder_thrashGuard_secondRung3FailureWithinWindow_thirdKickUsesSurrenderLadder() = runTest {
        // Task 20 / Step E: two full Rung-3 failures within
        // RUNG_3_THRASH_WINDOW_MS (5 min) trigger the thrash guard. The
        // third kick builds a one-rung surrender ladder which returns
        // false synchronously — observable as the third ladder having
        // currentLadderIsSurrender semantics, but since that field is
        // private we observe the structural invariant: the third kick's
        // ladder exhausts WITHOUT making any signaling.client calls
        // (Rung 1 register-rendezvous + Rung 2 disconnect/connect are
        // skipped entirely by the surrender ladder).
        //
        // Sequence:
        //   1. Drive ladder #1 to exhaustion (Rungs 1+2+3 surrender) →
        //      records 1 Rung-3 failure, promotes to Rung 4 (surrender flag,
        //      backoff timer armed).
        //   2. requestReconnect would reset the thrash log; we don't call
        //      it. Instead, manually re-kick by driving a fresh failure.
        //      But the existing ladder is null after the previous exhaustion
        //      so we simply notify another peer-failed.
        //   3. Drive ladder #2 to exhaustion → records 2nd Rung-3 failure.
        //   4. Third kick should use the surrender ladder → exhausts
        //      synchronously without further signaling calls.
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()

        // Ladder #1.
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        assertNotNull("ladder #1 kicked", auth.currentLadder)

        // Drain ladder #1 to exhaustion. RUNG_1+RUNG_2 budgets cover Rungs
        // 1+2; Rung 3 surrenders synchronously in skeleton mode. After this
        // the ladder is null and the thrash log has 1 entry.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        assertNull("ladder #1 cleared after exhaustion", auth.currentLadder)
        assertEquals("first Rung-3 failure recorded", true, auth.surrenderedToUser)

        // Ladder #2 — drive a fresh peer to FAILED. The peer reducer's
        // RecoveryGivenUp dispatch from ladder #1 didn't reset peer X's
        // FAILED state (peer reducer only reacts on RecoverySucceeded /
        // PreFlightFailed / etc.). So we need a fresh peer or to simulate
        // X coming back online and failing again. Simpler: notifyPeerOnline
        // is idempotent; we drive notifyPongReceived to lift X back, then
        // PingMissed twice to fail it again.
        //
        // BUT: peer X is already FAILED, so a new ladder kick from peer
        // failure won't fire (no transition). Use a self-trigger instead:
        // if selfState is Reconnecting(true), notifyAuthComplete moves us
        // to Online; then notifyWsClosed moves Online -> Reconnecting(false)
        // which kicks ladder #2.
        auth.notifyAuthComplete()  // Reconnecting -> Online
        runCurrent()
        auth.notifyWsClosed()      // Online -> Reconnecting kicks ladder #2
        runCurrent()
        assertNotNull("ladder #2 kicked", auth.currentLadder)

        // Drain ladder #2 to exhaustion → 2 Rung-3 failures recorded.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        assertNull("ladder #2 cleared after exhaustion", auth.currentLadder)

        // Snapshot signaling call counts after 2 full ladders.
        // Each non-surrender ladder did 1 send (rung1 register-rendezvous)
        // + 1 disconnect + 1 connect (rung2). So 2 of each so far.

        // Ladder #3 — manual third kick via self-trigger. Auth back to
        // Online then close again. The thrash guard fires inside
        // [kickLadder], so ladder #3 is the synthetic surrender ladder
        // (one rung returning false synchronously). It exhausts inside
        // the same runCurrent() that runs the kick — no additional
        // virtual-time advance needed.
        auth.notifyAuthComplete()  // Reconnecting -> Online
        runCurrent()
        auth.notifyWsClosed()      // kicks ladder #3 (surrender variant)
        runCurrent()
        // ladder #3 is synthetic surrender — by the time runCurrent
        // returns, the synchronous false-return + handleLadderSettled has
        // already run and currentLadder is back to null.
        assertNull(
            "ladder #3 surrender ladder exhausts synchronously inside one runCurrent",
            auth.currentLadder,
        )

        // Shutdown cancels the still-armed Rung-4 backoff timer.
        auth.shutdown()

        // The thrash-guard surrender ladder must NOT have invoked Rungs
        // 1 or 2 — total signaling counts stay at 2 (one per non-thrash
        // ladder).
        verify(exactly = 2) { signaling.client.send(any()) }
        verify(exactly = 2) { signaling.client.disconnect() }
        verify(exactly = 2) { signaling.client.connect(any()) }
    }

    @Test
    fun ladder_backoff_armedOnRung4_cancelledByShutdown() = runTest {
        // Task 20 / Step E: after exhaustion + Rung 4 promotion, a backoff
        // timer is armed for BACKOFF_SCHEDULE_MS[0] (30s). [shutdown] MUST
        // cancel the backoff Job before scope.cancel — without that
        // ordering, runTest's teardown advanceUntilIdle hits the still-
        // armed delay and the test JVM hangs.
        //
        // The structural assertion: shutdown() returns cleanly (no test
        // hang) and post-shutdown advanceTimeBy past the 30s backoff
        // produces NO new ladder kick (no fireBackoffRetry).
        val (auth, signaling, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        auth.notifyWsClosed() // kicks ladder
        runCurrent()
        // Drain to exhaustion → promotes to Rung 4 → arms backoff timer.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        assertEquals("Rung 4 surrender flag set", true, auth.surrenderedToUser)
        assertNull("ladder cleared post-Rung-4 promotion", auth.currentLadder)

        // Snapshot signaling call counts before shutdown.
        // The first ladder did 1 send + 1 disconnect + 1 connect.

        auth.shutdown()
        runCurrent()

        // Past the 30s backoff (BACKOFF_SCHEDULE_MS[0]). If shutdown didn't
        // properly cancel the backoff Job, fireBackoffRetry would call
        // kickLadder → another rung1 send. The shuttingDown latch in
        // kickLadder is the second line of defence; this test pins both.
        testScheduler.advanceTimeBy(60_000L)
        runCurrent()
        assertNull("no backoff-driven ladder post-shutdown", auth.currentLadder)
        verify(exactly = 1) { signaling.client.send(any()) }
        verify(exactly = 1) { signaling.client.disconnect() }
        verify(exactly = 1) { signaling.client.connect(any()) }
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
    fun ladder_shutdownMidRung_propagatesCancellationCleanly_noLeakedCadence() = runTest {
        // Kotlin-specific structured-concurrency hygiene. No JS counterpart
        // (JS has no CancellationException). Extends
        // [ladder_shutdownCancelsTheInFlightLadder] by advancing 2s INTO
        // Rung 1's 5s budget before calling shutdown, so the rung action
        // is mid-flight (suspended inside
        // `withTimeoutOrNull(5_000) { _peerHealth.first { ... } }`) when
        // shutdown lands. Shutdown:
        //   1. cancels the ladder via its own latch (currentLadder.cancel()),
        //   2. clears currentLadder = null,
        //   3. cancels scope (parent of `launch { ladder.run() }`).
        //
        // Cancelling the worker scope propagates CE through the
        // supervisorScope inside RecoveryLadder.runInternal: the child
        // async's CE becomes ActionOutcome.Cancelled, and the
        // supervisorScope block then re-receives CE because its parent
        // launch is cancelled. That CE bubbles out of run() as part of
        // normal structured concurrency — runTest's watchdog would flag a
        // swallowed-then-rethrown CE as a test failure, so the test
        // completing without an unhandled-exception report IS the
        // structural assertion.
        //
        // Integration assertions: currentLadder is null after shutdown;
        // post-shutdown virtual-time advance produces NO new outbound
        // peer-pings AND no peerHealth mutations (catches both leaked
        // cadence reschedules and leaked timeout jobs).
        val (auth, _, sent) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyPeerOnline("X")
        runCurrent()
        auth.notifyPingMissed("X")
        auth.notifyPingMissed("X")
        runCurrent()
        assertNotNull("ladder kicked on peer->FAILED", auth.currentLadder)

        // Advance 2s into Rung 1. The rung is now suspended on the
        // peer-Healthy await inside withTimeoutOrNull.
        testScheduler.advanceTimeBy(2_000L)
        runCurrent()
        assertNotNull("ladder still in flight 2s into Rung 1", auth.currentLadder)
        val sentBeforeShutdown = sent.size

        auth.shutdown()
        runCurrent()
        assertNull("shutdown cleared currentLadder", auth.currentLadder)
        // Snapshot peerHealth immediately post-shutdown — a leaked timeout
        // job would mutate it during the post-shutdown advance below.
        val peerHealthAfterShutdown = auth.peerHealth.value

        // Past both budgets plus a generous margin: no zombie cadence
        // reschedules (sent stays at sentBeforeShutdown), no leaked
        // timeout jobs (peerHealth stays at the post-shutdown snapshot).
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 5_000L)
        runCurrent()
        assertEquals(
            "no new sends post-shutdown — cadence + ladder fully drained",
            sentBeforeShutdown,
            sent.size,
        )
        assertSame(
            "peerHealth must not mutate post-shutdown — no leaked timeout/rung jobs",
            peerHealthAfterShutdown,
            auth.peerHealth.value,
        )
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
    fun ladder_rung3_successPath_resetHookDrivesServiceRunning_andSelfOnline() = runTest {
        // Task 20 / Step D: Rung 3 with a non-null `forceFullReset` hook
        // exercises the cancellation-discipline code (pre/post `isActive`
        // checks, the inner `coroutineScope { ... }` wrapper, the
        // `combine(_selfState, serviceLifecycle.state).first { ... }`
        // predicate). The skeleton-mode test above only covers the early-
        // return at line ~1255 — without this success-path test, the
        // exact code that hung the FIRST attempt at Task 20 ships
        // untested.
        //
        // The test injects a reset lambda that simulates the
        // foreground-service stop→clear→start dance:
        //   1. Dispatch ServiceState.Stopping → Stopped
        //   2. Dispatch ServiceState.Starting
        //   3. Drive selfState to Online (notifyAuthComplete)
        //   4. Dispatch ServiceState.Running — the combine() predicate
        //      now fires (`selfState===Online && serviceState===Running`)
        // and Rung 3 returns `true` → ladder Success.
        val signaling = newFakeSignaling()
        val sl = com.zaptransfer.android.service.ServiceLifecycle()
        var authHolder: ConnectionAuthority? = null
        val auth = ConnectionAuthority(
            signalingClient = signaling.client,
            dispatcher = StandardTestDispatcher(testScheduler),
            pingTracker = null,
            now = { 0L },
            serviceLifecycle = sl,
            forceFullReset = {
                sl.dispatch(com.zaptransfer.android.service.ServiceState.Stopping)
                sl.dispatch(com.zaptransfer.android.service.ServiceState.Stopped)
                sl.dispatch(com.zaptransfer.android.service.ServiceState.Starting)
                authHolder!!.notifyAuthComplete()
                sl.dispatch(com.zaptransfer.android.service.ServiceState.Running)
            },
        )
        authHolder = auth
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        auth.notifyWsClosed() // Online -> Reconnecting kicks ladder.
        runCurrent()
        assertNotNull("ladder kicked", auth.currentLadder)

        // Drive past Rungs 1+2 (no peer Healthy → Rung 1 timeouts at 5s;
        // no service Running → Rung 2 timeouts at 20s). Then Rung 3
        // fires the reset lambda which drives the success criterion.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        // Allow the settle handler to run.
        runCurrent()

        assertNull(
            "ladder released after Rung 3 success (forceFullReset drove " +
                "selfState=Online + serviceState=Running)",
            auth.currentLadder,
        )
        assertSame(
            "selfState lifted back to Online after Rung 3 success",
            SelfState.Online,
            auth.selfState.value,
        )

        auth.shutdown()
    }

    @Test
    fun ladder_rung3_skeletonMode_noResetHook_advancesPastRung3() = runTest {
        // Task 20 / Step D: Rung 3 with `forceFullReset == null` surrenders
        // synchronously, so the ladder advances cleanly to Exhausted (Rung
        // 4 surrender lands in Step E). The existing
        // [ladder_exhaustion_keepsSelfStateInReconnecting_noSurrender] test
        // already drains through Rungs 1+2; this test pins the additional
        // contract that Rung 3 in skeleton mode adds zero time-budget to
        // the drain (return false synchronously) — so the same
        // RUNG_1_BUDGET + RUNG_2_BUDGET advance suffices to exhaust.
        //
        // Wire-shape verification: forceFullReset is NOT in the
        // buildCadenceAuthority signature — skeleton-mode is the default.
        val (auth, _, _) = buildCadenceAuthority(StandardTestDispatcher(testScheduler))
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        auth.notifyWsClosed() // Online -> Reconnecting kicks ladder.
        runCurrent()
        assertNotNull(auth.currentLadder)

        // Drive past Rungs 1 and 2 budgets only — Rung 3 surrenders
        // synchronously in skeleton mode (no extra advance needed).
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()

        assertNull(
            "ladder cleared after Rung 3 skeleton-mode synchronous surrender",
            auth.currentLadder,
        )

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

    // ── Task 18: ensureSendable async upgrade ──────────────────────────────
    //
    // Mirrors `extension/test/connection-authority.test.js`'s
    // `describe('ConnectionAuthority: ensureSendable (Task 9 pre-flight)')`
    // block test-for-test, with these adaptations:
    //
    //   - Wire-frame *content* assertions ("registerFrame.rendezvousId ===
    //     'self-device-id'") become call-count assertions on the captured
    //     `sent: MutableList<PeerPingMessage>` list — that list IS the wire-
    //     shape capture (the typed message, not a JSONObject), so we can
    //     introspect type/targetDeviceId/rendezvousId directly without
    //     fighting the relaxed JSONObject mock (gotcha #3 from the Task 17
    //     KDoc above).
    //
    //   - The pre-flight 5s timer, the 30s recent-traffic window, and the
    //     ladder budgets all live on virtual time — `testScheduler
    //     .advanceTimeBy(...)` + `runCurrent()` is the canonical drive
    //     pattern. We run pre-flight tests under the cadence-enabled
    //     authority (built via [buildCadenceAuthority]) so the real
    //     [PeerPingTracker] participates in the probe.
    //
    //   - The recent-traffic window's wall-clock comparison goes through an
    //     injected `now: () -> Long` lambda so tests can advance the
    //     pre-flight clock independently of the cadence engine's virtual-
    //     time `delay(...)` ticks. (Cadence delays still drive cadence;
    //     the recent-traffic clock drives only the Step-2 skip predicate.)
    //
    //   - Drain-then-shutdown discipline applies (gotcha #2 from the Task
    //     17 KDoc). Every test that arms cadence or kicks the ladder
    //     drains to exhaustion + calls shutdown() before the test ends.

    /**
     * Mutable wall-clock for the pre-flight `lastTrafficAt` window. Tests
     * advance via [tick]; the captured lambda is passed to the authority's
     * `now: () -> Long` constructor parameter.
     *
     * Decoupled from the [StandardTestDispatcher]'s virtual time on
     * purpose (see Task 18 KDoc on [ConnectionAuthority] for why): the
     * recent-traffic window compares wall-clock-shaped timestamps, while
     * the cadence engine and ladder budgets live on the test scheduler's
     * virtual time. Coupling the two would force pre-flight skip tests to
     * advance virtual time even when the test's whole point is "no
     * cadence interaction occurs".
     */
    private class FakePreFlightClock(private var t: Long = 0L) {
        fun now(): Long = t
        fun tick(deltaMs: Long) { t += deltaMs }
    }

    /**
     * Bundle of an ensureSendable-ready authority + helpers. Mirrors
     * [makePreFlightAuthority] in the JS suite: drives selfState ONLINE
     * during construction so each test can focus on per-peer logic.
     */
    private data class PreFlightFixture(
        val auth: ConnectionAuthority,
        val signaling: FakeSignaling,
        val sent: MutableList<PeerPingMessage>,
        val clock: FakePreFlightClock,
    )

    /**
     * Build a pre-flight-ready authority. Drives self ONLINE, returns the
     * cadence-engine `sent` list for probe-count assertions, and exposes
     * the [FakePreFlightClock] for `lastTrafficAt` window manipulation.
     *
     * The internal `runCurrent()` flushes the authority's `init`-time
     * connection-state collector launch and the WsOpening/AuthComplete
     * dispatches so the caller starts in a clean ONLINE state.
     */
    private fun TestScope.buildPreFlightAuthority(
        ownDeviceId: String = "self-device-id",
    ): PreFlightFixture {
        val signaling = newFakeSignaling()
        val sent = mutableListOf<PeerPingMessage>()
        val tracker = PeerPingTracker(
            sendMessage = { sent += it },
            timeoutMs = PING_TIMEOUT_MS,
            ownDeviceId = ownDeviceId,
        )
        val clock = FakePreFlightClock()
        val auth = ConnectionAuthority(
            signaling.client,
            StandardTestDispatcher(testScheduler),
            tracker,
            now = clock::now,
        )
        runCurrent()
        auth.notifyWsOpening()
        auth.notifyAuthComplete()
        runCurrent()
        return PreFlightFixture(auth, signaling, sent, clock)
    }

    /** Helper: count outbound peer-ping messages in `sent`. */
    private fun countPings(sent: List<PeerPingMessage>): Int =
        sent.count { it.type == "peer-ping" }

    @Test
    fun ensureSendable_returnsSelfOffline_withoutProbing_whenSelfNotOnline() = runTest {
        // Mirror of Chrome JS `returns SELF_OFFLINE without probing when
        // selfState != ONLINE`. Step 1 short-circuits the algorithm; no
        // peer-ping should be issued.
        val (auth, _, sent, _) = buildPreFlightAuthority()
        // Drop selfState back to RECONNECTING.
        auth.notifyWsClosed()
        runCurrent()
        assertTrue(auth.selfState.value is SelfState.Reconnecting)

        val before = countPings(sent)
        val result = auth.ensureSendable("X")
        assertSame(SendGate.SelfOffline, result)
        assertEquals("no peer-ping fired on self-offline gate", before, countPings(sent))

        // Drain the self-RECONNECTING-kicked ladder so it doesn't leak.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()
        auth.shutdown()
    }

    @Test
    fun ensureSendable_returnsOkImmediately_whenPeerHealthyWithRecentTraffic() = runTest {
        // Mirror of Chrome JS `returns ok immediately when peer is HEALTHY
        // with traffic in last 30s`. Step 2 skip path — no probe.
        val (auth, _, sent, clock) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X")
        // Real frame at t=0 promotes X to HEALTHY and records lastTrafficAt.
        auth.notifyFrameReceived("X")
        runCurrent()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        // 5s later (well within the 30s window) → skip the probe.
        clock.tick(5_000L)
        val beforePings = countPings(sent)
        val result = auth.ensureSendable("X")
        runCurrent()
        assertSame(SendGate.Ok, result)
        assertEquals(
            "no peer-ping fired when within 30s of fresh traffic",
            beforePings,
            countPings(sent),
        )

        auth.shutdown()
    }

    @Test
    fun ensureSendable_issuesProbe_whenHealthyButTrafficStale() = runTest {
        // Mirror of Chrome JS `issues a peer-ping when HEALTHY but traffic
        // is older than 30s; ok on pong`.
        val (auth, _, sent, clock) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X")
        auth.notifyFrameReceived("X")
        runCurrent()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        // Advance the recent-traffic clock past the 30s window. The cadence
        // engine's `delay(120s)` still hasn't fired (we don't advance virtual
        // time), so any ping observed in `sent` is from pre-flight, not
        // background cadence.
        clock.tick(RECENT_TRAFFIC_WINDOW_MS + 1_000L)
        val beforePings = countPings(sent)

        val gateAsync = async { auth.ensureSendable("X") }
        runCurrent()
        assertEquals("pre-flight peer-ping issued", beforePings + 1, countPings(sent))

        // Pong the most recent peer-ping.
        val ping = sent.last { it.type == "peer-ping" }
        auth.notifyPongReceived(ping.nonce)
        runCurrent()

        assertSame(SendGate.Ok, gateAsync.await())

        auth.shutdown()
    }

    @Test
    fun ensureSendable_issuesProbe_whenPeerUnknown_okOnPong() = runTest {
        // Mirror of Chrome JS `issues a peer-ping when peer is UNKNOWN
        // regardless of lastTrafficAt; ok on pong`. UNKNOWN never satisfies
        // Step 2 because it's not HEALTHY — probe fires immediately.
        val (auth, _, sent, _) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X") // UNKNOWN, no traffic recorded.
        runCurrent()
        val beforePings = countPings(sent)

        val gateAsync = async { auth.ensureSendable("X") }
        runCurrent()
        assertEquals("UNKNOWN peer triggers a probe", beforePings + 1, countPings(sent))

        val ping = sent.last { it.type == "peer-ping" }
        auth.notifyPongReceived(ping.nonce)
        runCurrent()

        assertSame(SendGate.Ok, gateAsync.await())

        auth.shutdown()
    }

    @Test
    fun ensureSendable_coalescesConcurrentCallsForSamePeerIntoOneProbe() = runTest {
        // Mirror of Chrome JS `coalesces concurrent ensureSendable calls for
        // the same peer into one probe`. The per-peer in-flight Deferred
        // is the load-bearing mechanism; without it a clipboard-burst (5
        // files) would issue 5 redundant peer-pings.
        val (auth, _, sent, _) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X")
        runCurrent()
        val beforePings = countPings(sent)

        val a = async { auth.ensureSendable("X") }
        val b = async { auth.ensureSendable("X") }
        val c = async { auth.ensureSendable("X") }
        runCurrent()
        assertEquals(
            "one probe shared across concurrent callers",
            beforePings + 1,
            countPings(sent),
        )

        val ping = sent.last { it.type == "peer-ping" }
        auth.notifyPongReceived(ping.nonce)
        runCurrent()

        assertSame(SendGate.Ok, a.await())
        assertSame(SendGate.Ok, b.await())
        assertSame(SendGate.Ok, c.await())

        auth.shutdown()
    }

    @Test
    fun ensureSendable_onProbeTimeout_kicksLadder_andRePingsOnSuccess() = runTest {
        // Mirror of Chrome JS `on 5s ping timeout, kicks ladder; if ladder
        // succeeds, re-pings and returns ok`. Step 3a → 3b → 3c → 3d
        // happy path: ladder Rung 1 succeeds via FrameReceived, post-
        // success retry probe gets a pong.
        val (auth, _, sent, _) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X")
        runCurrent()
        val beforePings = countPings(sent)

        val gateAsync = async { auth.ensureSendable("X") }
        runCurrent()
        assertEquals("first probe-ping issued", beforePings + 1, countPings(sent))

        // Advance past the 5s pre-flight timeout so the probe surrenders.
        // The cadence-tracker's own 10s timeout has not yet fired — our
        // 5s racer is what produces the failed result.
        testScheduler.advanceTimeBy(PRE_FLIGHT_PING_TIMEOUT_MS + 1L)
        runCurrent()

        assertSame(PeerHealth.Failed, auth.peerHealth.value["X"])
        assertNotNull("ladder kicked after pre-flight timeout", auth.currentLadder)

        // Drive Rung 1 to success via a frame from X. The reducer promotes
        // X → HEALTHY, the rung's `_peerHealth.first { Healthy }` predicate
        // fires, and the ladder settles with Success.
        auth.notifyFrameReceived("X")
        runCurrent()
        runCurrent() // second pump for the settle handler

        assertNull("ladder released after Rung 1 success", auth.currentLadder)

        // The post-success retry probe must have been issued. Pong it.
        assertEquals(
            "retry probe issued after ladder success",
            beforePings + 2,
            countPings(sent),
        )
        val retry = sent.last { it.type == "peer-ping" }
        auth.notifyPongReceived(retry.nonce)
        runCurrent()

        assertSame(SendGate.Ok, gateAsync.await())

        auth.shutdown()
    }

    @Test
    fun ensureSendable_onProbeTimeout_returnsPeerUnreachable_onLadderExhaustion() = runTest {
        // Mirror of Chrome JS `on 5s ping timeout with ladder failure,
        // returns PEER_UNREACHABLE`. Step 3a fails → 3b kick → 3c await
        // ladder → ladder exhausts → return PEER_UNREACHABLE.
        val (auth, _, sent, _) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X")
        runCurrent()
        val beforePings = countPings(sent)

        val gateAsync = async { auth.ensureSendable("X") }
        runCurrent()
        assertEquals("probe issued", beforePings + 1, countPings(sent))

        // 5s → pre-flight timeout → FAILED → ladder kicks.
        testScheduler.advanceTimeBy(PRE_FLIGHT_PING_TIMEOUT_MS + 1L)
        runCurrent()
        assertNotNull("ladder kicked", auth.currentLadder)

        // Burn both ladder budgets. With no driver to flip peerHealth →
        // Healthy or selfState → Online, both rungs surrender on
        // withTimeoutOrNull → ladder.run() resolves Exhausted.
        testScheduler.advanceTimeBy(RUNG_1_BUDGET_MS + RUNG_2_BUDGET_MS + 1_000L)
        runCurrent()

        val result = gateAsync.await()
        assertTrue(
            "ladder exhausted → PEER_UNREACHABLE",
            result is SendGate.PeerUnreachable,
        )
        assertNull("ladder released after exhaustion", auth.currentLadder)

        auth.shutdown()
    }

    @Test
    fun ensureSendable_lastTrafficAt_isUpdatedBySendCompleted_notJustFrameReceived() = runTest {
        // Mirror of Chrome JS `lastTrafficAt is updated by send-completed
        // (not just frame-received)`. Both producers count as recent
        // traffic for the Step 2 skip.
        val (auth, _, sent, clock) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X")
        auth.notifySendCompleted("X") // promotes to HEALTHY + records traffic
        runCurrent()
        assertSame(PeerHealth.Healthy, auth.peerHealth.value["X"])

        clock.tick(5_000L)
        val beforePings = countPings(sent)
        val result = auth.ensureSendable("X")
        runCurrent()
        assertSame(SendGate.Ok, result)
        assertEquals(
            "no probe — send-completed counted as recent traffic",
            beforePings,
            countPings(sent),
        )

        auth.shutdown()
    }

    @Test
    fun ensureSendable_preFlightPongPromotesPeerToHealthyThroughTheReducer() = runTest {
        // Mirror of Chrome JS `Task 11 follow-up F: pre-flight pong
        // promotes peer to HEALTHY through the reducer`. Without this, an
        // UNKNOWN peer probed by ensureSendable would resolve Ok but stay
        // UNKNOWN — the popup dot would be stuck yellow.
        val (auth, _, sent, _) = buildPreFlightAuthority()
        auth.notifyPeerOnline("X") // UNKNOWN
        runCurrent()
        assertSame(PeerHealth.Unknown, auth.peerHealth.value["X"])

        val gateAsync = async { auth.ensureSendable("X") }
        runCurrent()
        val ping = sent.last { it.type == "peer-ping" }
        auth.notifyPongReceived(ping.nonce)
        runCurrent()

        assertSame(SendGate.Ok, gateAsync.await())
        assertSame(
            "pre-flight pong promoted peer through the reducer",
            PeerHealth.Healthy,
            auth.peerHealth.value["X"],
        )

        auth.shutdown()
    }
}

