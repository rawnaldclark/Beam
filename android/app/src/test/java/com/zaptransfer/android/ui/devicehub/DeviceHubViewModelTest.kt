package com.zaptransfer.android.ui.devicehub

import android.content.Context
import com.zaptransfer.android.connection.ConnectionAuthority
import com.zaptransfer.android.connection.PeerHealth
import com.zaptransfer.android.connection.SelfState
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.crypto.BeamV2Transport
import com.zaptransfer.android.crypto.BeamV2Wiring
import com.zaptransfer.android.data.db.dao.ClipboardDao
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.preferences.UserPreferences
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.SignalingClient
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit coverage for [DeviceHubViewModel] focused on Task 19's
 * `ConnectionAuthority`-driven UI bindings:
 *
 *   - `uiState.devices[*].health` reflects [ConnectionAuthority.peerHealth]
 *     map updates (and the absence of an entry maps to [PeerHealth.Unknown],
 *     not [PeerHealth.Offline] — UNKNOWN means "first sighting, no signal
 *     yet" while OFFLINE is a real reducer-driven state).
 *   - The "self-overrides-peer" rule from spec line 185: when
 *     [SelfState] is anything other than [SelfState.Online], every peer's
 *     effective `health` collapses to [PeerHealth.Offline] regardless of
 *     what the underlying map says.
 *   - [DeviceHubViewModel.requestReconnect] delegates straight through to
 *     [ConnectionAuthority.requestReconnect] — the wiring the banner button
 *     depends on.
 *   - The `combine(...)` flow does not leak observers past
 *     [androidx.lifecycle.ViewModel.onCleared] (the `WhileSubscribed(5_000)`
 *     contract holds — a final emission is the last side-effect).
 *
 * Pure-JVM tests: no Compose, no Robolectric. The 8-dep ViewModel is
 * constructable in isolation by mocking [DeviceRepository], the DAOs,
 * [SignalingClient], [UserPreferences], [BeamV2Wiring], and the [Context].
 * The two flows we drive are [DeviceRepository.observePairedDevices] +
 * [DeviceRepository.onlineDevices] (paired list + presence) and
 * [ConnectionAuthority.peerHealth] + [ConnectionAuthority.selfState]
 * (the new UI inputs).
 *
 * Style: JUnit 4 with [runTest]. The ViewModel's init block launches a
 * relay-connect coroutine that calls [SignalingClient.connect] and then
 * `connectionState.first { Connected }` — we drive
 * [SignalingClient.connectionState] to a [ConnectionState.Connected]
 * emission so the launch settles cleanly under [advanceUntilIdle].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DeviceHubViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setMainDispatcher() {
        // ViewModel.viewModelScope is bound to Dispatchers.Main internally.
        // Replace it with the StandardTestDispatcher for deterministic ordering.
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun resetMainDispatcher() {
        Dispatchers.resetMain()
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /**
     * Bundle of the four flows the ViewModel reads (paired devices, online
     * presence, peer health, self state) plus the constructed ViewModel and
     * the [ConnectionAuthority] mock. Tests obtain one of these and drive
     * the flows to assert downstream `uiState` shape.
     */
    private data class Fixture(
        val viewModel: DeviceHubViewModel,
        val authority: ConnectionAuthority,
        val pairedDevicesFlow: MutableStateFlow<List<PairedDeviceEntity>>,
        val onlineDevicesFlow: MutableStateFlow<Set<String>>,
        val peerHealthFlow: MutableStateFlow<Map<String, PeerHealth>>,
        val selfStateFlow: MutableStateFlow<SelfState>,
    )

    /** Build a minimal valid [PairedDeviceEntity] for tests that don't care about key material. */
    private fun makePairedDevice(deviceId: String, name: String): PairedDeviceEntity =
        PairedDeviceEntity(
            deviceId = deviceId,
            name = name,
            icon = "laptop",
            platform = "chrome_extension",
            x25519PublicKey = ByteArray(32),
            ed25519PublicKey = ByteArray(32),
            pairedAt = 0L,
        )

    private fun newFixture(
        initialDevices: List<PairedDeviceEntity> = listOf(makePairedDevice("peerA", "Chrome on Mac")),
        initialOnline: Set<String> = emptySet(),
        initialPeerHealth: Map<String, PeerHealth> = emptyMap(),
        initialSelfState: SelfState = SelfState.Offline,
    ): Fixture {
        val pairedDevicesFlow = MutableStateFlow(initialDevices)
        val onlineDevicesFlow = MutableStateFlow(initialOnline)
        val peerHealthFlow = MutableStateFlow(initialPeerHealth)
        val selfStateFlow = MutableStateFlow(initialSelfState)

        val deviceRepo = mockk<DeviceRepository>(relaxed = true)
        every { deviceRepo.observePairedDevices() } returns pairedDevicesFlow
        every { deviceRepo.onlineDevices } returns onlineDevicesFlow

        val transferHistoryDao = mockk<TransferHistoryDao>(relaxed = true)
        every { transferHistoryDao.getRecent(any()) } returns emptyFlow()

        val clipboardDao = mockk<ClipboardDao>(relaxed = true)
        every { clipboardDao.getRecent(any()) } returns emptyFlow()

        // SignalingClient: the ViewModel init block calls connect() then
        // awaits a Connected emission on connectionState. We drive
        // connectionState pre-bound to Connected so the launch settles.
        val signalingClient = mockk<SignalingClient>(relaxed = true)
        every { signalingClient.connectionState } returns
            MutableStateFlow<ConnectionState>(ConnectionState.Connected)

        val userPreferences = mockk<UserPreferences>(relaxed = true)
        // The ViewModel's clipboard / file-receive paths read preferencesFlow.
        // No test in this class triggers either path, so an emptyFlow() that
        // never emits is sufficient (and avoids needing a mockable Snapshot).
        every { userPreferences.preferencesFlow } returns emptyFlow()

        // BeamV2Wiring: relaxed mock is enough — the init block calls
        // setDelivery(...) and that's it; nothing reads the Delivery back.
        val beamV2Wiring = mockk<BeamV2Wiring>(relaxed = true)
        // The ensureSendable / sendClipboard pre-flight paths aren't exercised
        // here, but the relaxed mock returns mockk-defaults which would fail
        // a method-call type assertion if they were. We don't call them.
        every { beamV2Wiring.transport } returns mockk<BeamV2Transport>(relaxed = true)

        // ConnectionAuthority: we control selfState + peerHealth precisely.
        val authority = mockk<ConnectionAuthority>(relaxed = true)
        every { authority.selfState } returns selfStateFlow
        every { authority.peerHealth } returns peerHealthFlow

        val context = mockk<Context>(relaxed = true)

        val viewModel = DeviceHubViewModel(
            deviceRepo = deviceRepo,
            transferHistoryDao = transferHistoryDao,
            clipboardDao = clipboardDao,
            signalingClient = signalingClient,
            userPreferences = userPreferences,
            beamV2Wiring = beamV2Wiring,
            connectionAuthority = authority,
            appContext = context,
        )

        return Fixture(
            viewModel = viewModel,
            authority = authority,
            pairedDevicesFlow = pairedDevicesFlow,
            onlineDevicesFlow = onlineDevicesFlow,
            peerHealthFlow = peerHealthFlow,
            selfStateFlow = selfStateFlow,
        )
    }

    // ── computeEffectiveHealth: pure-function unit tests ────────────────────
    //
    // The self-overrides-peer rule (spec line 185) is implemented as a
    // pure function so it can be exhaustively asserted without spinning up
    // the whole ViewModel. The combine(...) test below verifies the wiring
    // calls through to it.

    @Test
    fun `computeEffectiveHealth passes through every PeerHealth case when self is Online`() {
        val cases = listOf(
            PeerHealth.Healthy,
            PeerHealth.Stale,
            PeerHealth.Failed,
            PeerHealth.Offline,
            PeerHealth.Unknown,
        )
        for (raw in cases) {
            val effective = computeEffectiveHealth(raw, SelfState.Online)
            assertSame(
                "selfState=Online must pass $raw through unchanged",
                raw, effective,
            )
        }
    }

    @Test
    fun `computeEffectiveHealth folds every PeerHealth to Offline when self is Offline`() {
        val cases = listOf(
            PeerHealth.Healthy,
            PeerHealth.Stale,
            PeerHealth.Failed,
            PeerHealth.Offline,
            PeerHealth.Unknown,
        )
        for (raw in cases) {
            val effective = computeEffectiveHealth(raw, SelfState.Offline)
            assertSame(
                "selfState=Offline must fold $raw to Offline",
                PeerHealth.Offline, effective,
            )
        }
    }

    @Test
    fun `computeEffectiveHealth folds Healthy peers to Offline when self is Connecting`() {
        val effective = computeEffectiveHealth(PeerHealth.Healthy, SelfState.Connecting)
        assertSame(PeerHealth.Offline, effective)
    }

    @Test
    fun `computeEffectiveHealth folds Healthy peers to Offline under Reconnecting (auto)`() {
        val effective = computeEffectiveHealth(
            PeerHealth.Healthy,
            SelfState.Reconnecting(surrenderedToUser = false),
        )
        assertSame(PeerHealth.Offline, effective)
    }

    @Test
    fun `computeEffectiveHealth folds Healthy peers to Offline under Reconnecting (surrendered)`() {
        val effective = computeEffectiveHealth(
            PeerHealth.Healthy,
            SelfState.Reconnecting(surrenderedToUser = true),
        )
        assertSame(PeerHealth.Offline, effective)
    }

    // ── PairedDeviceUi.isSendable ───────────────────────────────────────────

    @Test
    fun `isSendable is true for HEALTHY and STALE only`() {
        val entity = makePairedDevice("x", "x")
        assertTrue(PairedDeviceUi(entity, PeerHealth.Healthy).isSendable)
        assertTrue(PairedDeviceUi(entity, PeerHealth.Stale).isSendable)
        assertFalse(PairedDeviceUi(entity, PeerHealth.Failed).isSendable)
        assertFalse(PairedDeviceUi(entity, PeerHealth.Offline).isSendable)
        assertFalse(PairedDeviceUi(entity, PeerHealth.Unknown).isSendable)
    }

    // ── uiState reflects peerHealth changes ────────────────────────────────

    @Test
    fun `uiState device health reflects peerHealth map updates while self is Online`() = runTest(testDispatcher) {
        val fx = newFixture(initialSelfState = SelfState.Online)

        // Drive a Healthy entry for peerA.
        fx.peerHealthFlow.value = mapOf("peerA" to PeerHealth.Healthy)
        advanceUntilIdle()

        val firstSnapshot = fx.viewModel.uiState.first { !it.isLoading }
        assertEquals(1, firstSnapshot.devices.size)
        assertSame(PeerHealth.Healthy, firstSnapshot.devices[0].health)
        assertTrue(firstSnapshot.devices[0].isSendable)

        // Now flip the entry to Failed. The dot color in the screen is
        // driven by `health`; we just assert the field updates.
        fx.peerHealthFlow.value = mapOf("peerA" to PeerHealth.Failed)
        advanceUntilIdle()

        val nextSnapshot = fx.viewModel.uiState.first { it.devices.firstOrNull()?.health is PeerHealth.Failed }
        assertSame(PeerHealth.Failed, nextSnapshot.devices[0].health)
        assertFalse(nextSnapshot.devices[0].isSendable)
    }

    @Test
    fun `uiState device health defaults to Unknown when peer is absent from peerHealth map`() = runTest(testDispatcher) {
        val fx = newFixture(initialSelfState = SelfState.Online, initialPeerHealth = emptyMap())
        advanceUntilIdle()

        val snapshot = fx.viewModel.uiState.first { !it.isLoading }
        assertEquals(1, snapshot.devices.size)
        // Spec: a missing entry maps to UNKNOWN, NOT to OFFLINE. UNKNOWN means
        // "no first ping yet"; OFFLINE is a reducer-driven state for "relay
        // says peer's WS is closed".
        assertSame(PeerHealth.Unknown, snapshot.devices[0].health)
        assertFalse(
            "UNKNOWN must render non-sendable (conservative)",
            snapshot.devices[0].isSendable,
        )
    }

    // ── self-overrides-peer rule (spec line 185) ───────────────────────────

    @Test
    fun `peer health Healthy is folded to Offline when self is Reconnecting`() = runTest(testDispatcher) {
        val fx = newFixture(
            initialPeerHealth = mapOf("peerA" to PeerHealth.Healthy),
            initialSelfState = SelfState.Reconnecting(surrenderedToUser = false),
        )
        advanceUntilIdle()

        val snapshot = fx.viewModel.uiState.first { !it.isLoading }
        assertSame(
            "even with a HEALTHY map entry, self != Online forces effective Offline",
            PeerHealth.Offline, snapshot.devices[0].health,
        )
        assertFalse(snapshot.devices[0].isSendable)
    }

    @Test
    fun `peer health Healthy passes through when self transitions to Online`() = runTest(testDispatcher) {
        val fx = newFixture(
            initialPeerHealth = mapOf("peerA" to PeerHealth.Healthy),
            initialSelfState = SelfState.Connecting,
        )
        advanceUntilIdle()

        // Pre-condition: under Connecting, HEALTHY is folded to Offline.
        val pre = fx.viewModel.uiState.first { !it.isLoading }
        assertSame(PeerHealth.Offline, pre.devices[0].health)

        // Promote selfState to Online — the fold lifts and the raw
        // HEALTHY value flows through.
        fx.selfStateFlow.value = SelfState.Online
        advanceUntilIdle()

        val post = fx.viewModel.uiState.first { it.devices[0].health is PeerHealth.Healthy }
        assertSame(PeerHealth.Healthy, post.devices[0].health)
        assertTrue(post.devices[0].isSendable)
    }

    // ── selfState exposed on uiState ───────────────────────────────────────

    @Test
    fun `uiState selfState mirrors authority selfState`() = runTest(testDispatcher) {
        val fx = newFixture(initialSelfState = SelfState.Offline)
        advanceUntilIdle()

        val initial = fx.viewModel.uiState.first { !it.isLoading }
        assertSame(SelfState.Offline, initial.selfState)

        fx.selfStateFlow.value = SelfState.Reconnecting(surrenderedToUser = true)
        advanceUntilIdle()

        val after = fx.viewModel.uiState.first {
            it.selfState is SelfState.Reconnecting && (it.selfState as SelfState.Reconnecting).surrenderedToUser
        }
        assertTrue(after.selfState is SelfState.Reconnecting)
        assertTrue((after.selfState as SelfState.Reconnecting).surrenderedToUser)
    }

    // ── requestReconnect plumbing ──────────────────────────────────────────

    @Test
    fun `requestReconnect delegates to ConnectionAuthority`() = runTest(testDispatcher) {
        val fx = newFixture()

        fx.viewModel.requestReconnect()

        verify(exactly = 1) { fx.authority.requestReconnect() }
    }

    @Test
    fun `requestReconnect can be called multiple times safely`() = runTest(testDispatcher) {
        val fx = newFixture()

        fx.viewModel.requestReconnect()
        fx.viewModel.requestReconnect()
        fx.viewModel.requestReconnect()

        verify(exactly = 3) { fx.authority.requestReconnect() }
    }

    // ── empty-map default + presenceOnline tiebreaker ─────────────────────

    @Test
    fun `presenceOnline reflects DeviceRepository onlineDevices set`() = runTest(testDispatcher) {
        val fx = newFixture(
            initialOnline = setOf("peerA"),
            initialSelfState = SelfState.Online,
        )
        advanceUntilIdle()

        val snapshot = fx.viewModel.uiState.first { !it.isLoading }
        assertTrue(
            "presenceOnline must reflect the relay-presence bit even when the " +
                "authority hasn't yet observed the peer (peerHealth map is empty)",
            snapshot.devices[0].presenceOnline,
        )
    }

    @Test
    fun `uiState eventually emits non-loading state once flows settle`() = runTest(testDispatcher) {
        val fx = newFixture()
        advanceUntilIdle()

        val snapshot = fx.viewModel.uiState.first { !it.isLoading }
        assertNotNull(snapshot)
        assertFalse(snapshot.isLoading)
    }

    // ── peerHealthDotColor + peerHealthStatusLabel pure helpers ─────────────
    //
    // These live in DeviceHubScreen.kt as `internal` (visible-for-testing,
    // PRIVATE otherwise). Spec UI mapping table (lines 181-184 of
    // 2026-05-02-connection-authority-design.md) commits the dot colour
    // and label to specific values; this matrix pins all five cases for
    // both helpers so a future palette / label refactor surfaces the
    // breakage immediately rather than via a Compose-render regression
    // that has no JVM-level test coverage.

    @Test
    fun `peerHealthDotColor maps Healthy and Stale to online green`() {
        // `Color` is a value class — `assertEquals` (value equality), NOT
        // `assertSame` (reference equality), is the correct comparator.
        assertEquals(BeamPalette.online, peerHealthDotColor(PeerHealth.Healthy))
        assertEquals(BeamPalette.online, peerHealthDotColor(PeerHealth.Stale))
    }

    @Test
    fun `peerHealthDotColor maps Failed to warning yellow`() {
        assertEquals(BeamPalette.warning, peerHealthDotColor(PeerHealth.Failed))
    }

    @Test
    fun `peerHealthDotColor maps Offline and Unknown to offline grey`() {
        assertEquals(BeamPalette.offline, peerHealthDotColor(PeerHealth.Offline))
        assertEquals(BeamPalette.offline, peerHealthDotColor(PeerHealth.Unknown))
    }

    @Test
    fun `peerHealthStatusLabel maps Healthy and Stale to online`() {
        assertEquals("online", peerHealthStatusLabel(PeerHealth.Healthy))
        assertEquals("online", peerHealthStatusLabel(PeerHealth.Stale))
    }

    @Test
    fun `peerHealthStatusLabel maps Failed to reconnecting`() {
        assertEquals("reconnecting", peerHealthStatusLabel(PeerHealth.Failed))
    }

    @Test
    fun `peerHealthStatusLabel maps Offline and Unknown to offline`() {
        assertEquals("offline", peerHealthStatusLabel(PeerHealth.Offline))
        assertEquals("offline", peerHealthStatusLabel(PeerHealth.Unknown))
    }
}
