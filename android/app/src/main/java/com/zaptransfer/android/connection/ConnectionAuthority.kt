package com.zaptransfer.android.connection

import androidx.annotation.VisibleForTesting
import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Single source of truth for relay-connection and peer-health state.
 *
 * Composes the pure pieces from Tasks 13-14 (`PeerHealth.reduce`,
 * `SelfState.reduce`) into the object the rest of the Android app reads
 * from. Mirror of the Chrome JS skeleton in
 * `extension/connection/connection-authority.js` (commit `68e3c9f`); this
 * is the **skeleton** form — Task 16 wires the ping cadence, Task 17 wires
 * the recovery ladder, Task 18 wires the real `ensureSendable` pre-flight.
 *
 * Responsibilities (Task 15 only):
 *   1. Expose `selfState` and `peerHealth` as hot [StateFlow]s.
 *   2. Translate `signalingClient.connectionState` transitions and relay
 *      `peer-online`/`peer-offline` text messages into reducer events.
 *   3. Provide `notifyXxx` entry points for producers (BeamV2Wiring,
 *      TransferEngine) to push proof-of-life evidence into peer-health.
 *   4. Provide `ensureSendable(peerId)` — synchronous classifier returning
 *      one of the three [SendGate] cases.
 *   5. Provide `requestReconnect()` — skeleton stub that dispatches
 *      [SelfStateEvent.RecoveryBegan]; Task 17 replaces with a full ladder.
 *
 * ### Threading contract
 *
 * Every reducer dispatch is a read-modify-write on a [MutableStateFlow]'s
 * `value`. To eliminate races between concurrent producers (a v2 frame
 * decoded on Dispatchers.Default racing a `peer-online` arrival on the
 * OkHttp reader thread), all dispatches are confined to a single worker
 * thread via [Dispatchers.Default.limitedParallelism] = 1. The notify
 * methods marshal onto [scope] with `launch` and return immediately; the
 * reducer + `value =` write happens on the worker thread.
 *
 * Reads (`selfState.value`, `peerHealth.value`, `selfState`/`peerHealth`
 * StateFlow collection) are safe from any thread — [StateFlow] is
 * documented thread-safe.
 *
 * [ensureSendable] reads only the current snapshots — no dispatch — so it
 * is safe to call from any thread, including the send path's caller.
 *
 * [requestReconnect] dispatches [SelfStateEvent.RecoveryBegan]
 * asynchronously; the state transition lands on the worker thread.
 *
 * [shutdown] cancels the supervisor [scope] and stops observation. After
 * shutdown, further notify calls drop their dispatches silently
 * (the cancelled scope rejects new launches).
 *
 * ### Lazy-by-Hilt construction
 *
 * The Hilt singleton is constructed eagerly the first time anything injects
 * it. Once constructed, [init] starts the `signalingClient.connectionState`
 * collector and registers the relay-message listener — no further bootstrap
 * is required from callers.
 *
 * @param signalingClient The relay WebSocket adapter. Drives [selfState]
 *        via its `connectionState` flow and supplies `peer-online` /
 *        `peer-offline` text frames via `addListener`.
 * @param dispatcher Reducer-confinement dispatcher. Production uses the
 *        single-arg `@Inject` constructor which constructs a single-threaded
 *        slice of [Dispatchers.Default]; tests use this primary constructor
 *        to inject a `StandardTestDispatcher` for deterministic ordering.
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 */
@Singleton
class ConnectionAuthority @VisibleForTesting internal constructor(
    private val signalingClient: SignalingClient,
    private val dispatcher: CoroutineDispatcher,
) {

    /**
     * Production constructor. Hilt sees this and provides the
     * [SignalingClient] singleton. The reducer-confinement dispatcher is
     * a private single-threaded slice of [Dispatchers.Default]; tests use
     * the [VisibleForTesting] primary constructor to inject a
     * [kotlinx.coroutines.test.StandardTestDispatcher] instead.
     *
     * Hilt does not see the [VisibleForTesting] primary constructor as an
     * injection target because the secondary constructor is the only one
     * carrying [Inject] — keeping the [CoroutineDispatcher] dependency out
     * of the Hilt graph (it has no default binding and we do not want to
     * bind one).
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    @Inject
    constructor(signalingClient: SignalingClient) : this(
        signalingClient,
        Dispatchers.Default.limitedParallelism(1),
    )

    // ── Internal state ────────────────────────────────────────────────────

    /**
     * Supervisor scope confined to a single worker thread. Reducer dispatch,
     * `value =` writes, and the `signalingClient.connectionState` collector
     * all live on this scope. Cancelled by [shutdown].
     *
     * **Task 16 note.** The cadence engine that owns [PeerPingTracker]
     * MUST share this scope rather than introducing a second confinement
     * context. The tracker's mutable bookkeeping reads/writes the same
     * `_peerHealth` map this authority dispatches into, and a second worker
     * thread would re-introduce the read-modify-write race the single-thread
     * dispatcher exists to prevent.
     */
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    private val _selfState = MutableStateFlow<SelfState>(SelfState.Offline)
    private val _peerHealth = MutableStateFlow<Map<String, PeerHealth>>(emptyMap())

    /** SignalingListener registration — held so [shutdown] can deregister cleanly. */
    private val relayListener = object : SignalingListener {
        override fun onMessage(message: RelayMessage) {
            if (message !is RelayMessage.Text) return
            val type = message.json.optString("type")
            val peerId = message.json.optString("deviceId", "")
            if (peerId.isEmpty()) return
            when (type) {
                "peer-online" -> notifyPeerOnline(peerId)
                "peer-offline" -> notifyPeerOffline(peerId)
            }
        }
    }

    /** Job for the `signalingClient.connectionState` collector. */
    private val connectionStateJob: Job

    init {
        signalingClient.addListener(relayListener)
        connectionStateJob = scope.launch {
            // Collect the WS lifecycle and translate to SelfStateEvents.
            // Authenticating is treated as part of "Connecting" — no separate
            // event. Error is handled the same as Disconnected (the
            // SignalingClient's reconnect loop will drive us back to
            // Connecting, which dispatches StartConnect again).
            signalingClient.connectionState.collect { state ->
                when (state) {
                    is ConnectionState.Connecting -> dispatchSelf(SelfStateEvent.StartConnect)
                    ConnectionState.Authenticating -> { /* no-op; CONNECTING covers this */ }
                    ConnectionState.Connected -> dispatchSelf(SelfStateEvent.AuthComplete)
                    ConnectionState.Disconnected -> dispatchSelf(SelfStateEvent.WsClosed)
                    is ConnectionState.Error -> dispatchSelf(SelfStateEvent.WsClosed)
                }
            }
        }
    }

    // ── Observable getters ────────────────────────────────────────────────

    /**
     * Hot [StateFlow] of self-side connection state. Initial value is
     * [SelfState.Offline]. Replays the current value on every new
     * collector. Never null.
     */
    val selfState: StateFlow<SelfState> = _selfState.asStateFlow()

    /**
     * Hot [StateFlow] of per-peer health. Map keys are device IDs (matching
     * [SignalingClient]/[com.zaptransfer.android.data.repository.DeviceRepository]
     * convention). Map values are immutable [PeerHealth] snapshots — every
     * dispatch publishes a fresh map so subscribers comparing references
     * see a new value.
     */
    val peerHealth: StateFlow<Map<String, PeerHealth>> = _peerHealth.asStateFlow()

    // ── Notify methods (event ingestion) ──────────────────────────────────
    // Each marshals the matching SelfStateEvent / PeerHealthEvent onto the
    // worker thread and dispatches through the reducer. Safe to call from
    // any thread; returns immediately.
    //
    // Surface scope: this skeleton intentionally exposes three notify methods
    // ahead of their callers — `notifyStop`, `notifyPingMissed`,
    // `notifyPreFlightFailed`. Tasks 16 (cadence) and 18 (ensureSendable)
    // will wire them. Landing the public surface now lets those tasks be a
    // pure caller-side change rather than re-opening this class to add API,
    // which keeps the per-task review surface tight and avoids signature
    // drift between Chrome's JS and Android's Kotlin while the port catches
    // up. Each unwired method's KDoc names the task that will own its
    // caller.

    /** WebSocket connect attempt has started. */
    fun notifyWsOpening() = dispatchSelfAsync(SelfStateEvent.StartConnect)

    /**
     * Relay accepted our auth frame; we are ONLINE. Lifts both
     * `Connecting -> Online` and `Reconnecting -> Online` per the
     * deadlock-fix branch (Chrome commit `bd56305`).
     */
    fun notifyAuthComplete() = dispatchSelfAsync(SelfStateEvent.AuthComplete)

    /** WebSocket closed unexpectedly. */
    fun notifyWsClosed() = dispatchSelfAsync(SelfStateEvent.WsClosed)

    /** Hard tear-down (user unpaired all devices, app shutting down). */
    fun notifyStop() = dispatchSelfAsync(SelfStateEvent.Stop)

    /** Relay reports `peerId`'s WebSocket is open (weaker-than-pong evidence). */
    fun notifyPeerOnline(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.RelayPeerOnline)

    /** Relay reports `peerId`'s WebSocket is closed. */
    fun notifyPeerOffline(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.RelayPeerOffline)

    /** A real v2 frame was decoded from `peerId` — strong proof of life. */
    fun notifyFrameReceived(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.FrameReceived)

    /** A frame send to `peerId` succeeded end-to-end — strong proof of life. */
    fun notifySendCompleted(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.SendCompleted)

    /**
     * A `peer-pong` was matched for `peerId`. Promotes [PeerHealth] to
     * [PeerHealth.Healthy] (unless the peer is currently
     * [PeerHealth.Offline], where the relay's offline claim wins).
     *
     * Wired by Task 16's cadence engine; Task 15's skeleton does not call
     * this from anywhere in the app — it is exposed so Task 16 can inject
     * pong events without modifying the authority's public surface.
     */
    fun notifyPongReceived(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.PongReceived)

    /**
     * A peer-ping deadline elapsed without a pong for `peerId`. Drives
     * [PeerHealth.Healthy]/[PeerHealth.Unknown] -> [PeerHealth.Stale] and
     * [PeerHealth.Stale] -> [PeerHealth.Failed].
     *
     * Wired by Task 16's cadence engine.
     */
    fun notifyPingMissed(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.PingMissed)

    /**
     * Send-time pre-flight check failed for `peerId`. Drives [PeerHealth]
     * to [PeerHealth.Failed] from any state. Wired by Task 18's
     * `ensureSendable` upgrade.
     */
    fun notifyPreFlightFailed(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.PreFlightFailed)

    // ── Public actions ────────────────────────────────────────────────────

    /**
     * Pre-send gate. Synchronous classification based on the current
     * [selfState] and [peerHealth] snapshots:
     *
     *  - [SendGate.Ok] when [selfState] is [SelfState.Online] AND
     *    `peerHealth[peerId]` is [PeerHealth.Healthy], [PeerHealth.Stale],
     *    or [PeerHealth.Unknown] (or absent — UNKNOWN is the implicit
     *    default for unseen peers).
     *  - [SendGate.SelfOffline] when [selfState] is anything other than
     *    [SelfState.Online].
     *  - [SendGate.PeerUnreachable] when self is online but the peer is
     *    [PeerHealth.Failed] or [PeerHealth.Offline]. The carried
     *    `reason` is the literal string `"PEER_UNREACHABLE"`, matching
     *    the JS contract.
     *
     * **Skeleton form.** Task 18 will replace this with the full
     * `ensureSendable` algorithm: recent-traffic skip, peer-ping probe,
     * recovery-ladder trigger on failure.
     *
     * Safe to call from any thread — reads only the [StateFlow] snapshots,
     * does not dispatch.
     *
     * @param peerId Target peer's device ID.
     */
    fun ensureSendable(peerId: String): SendGate {
        if (_selfState.value !is SelfState.Online) return SendGate.SelfOffline
        val health = _peerHealth.value[peerId] ?: PeerHealth.Unknown
        return when (health) {
            PeerHealth.Healthy,
            PeerHealth.Stale,
            PeerHealth.Unknown -> SendGate.Ok
            PeerHealth.Failed,
            PeerHealth.Offline -> SendGate.PeerUnreachable(reason = "PEER_UNREACHABLE")
        }
    }

    /**
     * Manual reconnect entry point (e.g. UI "Reconnect" tap, lifecycle
     * resume).
     *
     * **Skeleton form is a no-op stub** — matches the Chrome JS skeleton at
     * commit `68e3c9f`. The actual ladder kickoff (cancel in-flight ladder,
     * dispatch a fresh one starting at Rung 3, drive
     * [signalingClient.connect] to cycle the WebSocket) lands in Task 17.
     * Today's call sites (popup-equivalent UI taps once Task 19 ships) get
     * a guaranteed-non-throwing no-op so they can wire the button without
     * waiting on the recovery ladder.
     */
    fun requestReconnect() {
        // Intentionally empty until Task 17. See KDoc.
    }

    /**
     * Tear-down hook. Cancels the supervisor [scope] (stopping the
     * connection-state collector and any in-flight reducer dispatches) and
     * deregisters the relay listener. Idempotent — calling twice is safe.
     *
     * After [shutdown], further notify calls drop their dispatches silently
     * (the cancelled scope rejects new launches). Reads of [selfState] and
     * [peerHealth] still return the last published values, but no further
     * updates will occur.
     */
    fun shutdown() {
        signalingClient.removeListener(relayListener)
        scope.cancel()
    }

    // ── Internal dispatch helpers ─────────────────────────────────────────

    /**
     * Asynchronously dispatch a [SelfStateEvent] on the worker thread.
     * Returns immediately; the reducer + `value =` write happens on
     * [scope]. If [scope] is cancelled (post-[shutdown]), the launch is a
     * silent no-op.
     */
    private fun dispatchSelfAsync(event: SelfStateEvent) {
        scope.launch { dispatchSelf(event) }
    }

    /**
     * Synchronous reducer dispatch — MUST only be called from a coroutine
     * already running on [scope]. Skips emission on no-op transitions
     * (reducer returned the same `state` instance) so [StateFlow] does not
     * re-emit on a non-change.
     */
    private fun dispatchSelf(event: SelfStateEvent) {
        val current = _selfState.value
        val next = SelfState.reduce(current, event)
        if (next !== current) _selfState.value = next
    }

    /**
     * Asynchronously dispatch a [PeerHealthEvent] for `peerId`. Returns
     * immediately; the reducer + `value =` write happens on [scope].
     */
    private fun dispatchPeerAsync(peerId: String, event: PeerHealthEvent) {
        scope.launch { dispatchPeer(peerId, event) }
    }

    /**
     * Synchronous per-peer reducer dispatch — MUST only be called from a
     * coroutine already running on [scope].
     *
     * **First-sighting seeding**: if `peerId` is not yet in the map, the
     * reducer's input state is [PeerHealth.Unknown] and the resulting entry
     * is always added to the map even if the reducer returns the same
     * [PeerHealth.Unknown] (the typical case for the first
     * `relay-peer-online` event). Without this, a peer's first appearance
     * would not produce a [StateFlow] emission and the UI would miss it.
     *
     * For peers already in the map, no-op transitions skip emission so
     * [StateFlow] does not re-emit on a non-change.
     */
    private fun dispatchPeer(peerId: String, event: PeerHealthEvent) {
        val current = _peerHealth.value
        val had = current.containsKey(peerId)
        val before = if (had) current.getValue(peerId) else PeerHealth.Unknown
        val next = PeerHealth.reduce(before, event)
        if (had && next === before) return
        val newMap = LinkedHashMap(current)
        newMap[peerId] = next
        _peerHealth.value = newMap
    }
}
