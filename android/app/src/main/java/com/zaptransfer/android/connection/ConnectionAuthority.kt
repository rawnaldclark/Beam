package com.zaptransfer.android.connection

import android.util.Log
import androidx.annotation.VisibleForTesting
import com.zaptransfer.android.crypto.KeyManager
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "ConnectionAuthority"

/**
 * Single source of truth for relay-connection and peer-health state.
 *
 * Composes the pure pieces from Tasks 13-14 (`PeerHealth.reduce`,
 * `SelfState.reduce`) into the object the rest of the Android app reads
 * from. Mirror of the Chrome JS module in
 * `extension/connection/connection-authority.js` (commit `3cd69a7`).
 *
 * Responsibilities:
 *   1. Expose `selfState` and `peerHealth` as hot [StateFlow]s.
 *   2. Translate `signalingClient.connectionState` transitions and relay
 *      `peer-online` / `peer-offline` / `peer-pong` text messages into
 *      reducer events.
 *   3. Provide `notifyXxx` entry points for producers (BeamV2Wiring,
 *      TransferEngine) to push proof-of-life evidence into peer-health.
 *   4. **Run the background peer-ping cadence engine (Task 16).** Each
 *      peer in [peerHealth] is pinged every [BG_PING_INTERVAL_MS] after
 *      its last activity; on [PING_TIMEOUT_MS] without a pong, the
 *      reducer is dispatched [PeerHealthEvent.PingMissed].
 *   5. Provide `ensureSendable(peerId)` — synchronous classifier returning
 *      one of the three [SendGate] cases (Task 18 will replace with the
 *      full algorithm).
 *   6. Provide `requestReconnect()` — skeleton stub; Task 17 wires the
 *      recovery ladder.
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
 * The cadence engine's per-peer `pingJob` / `timeoutJob` coroutines also
 * run on the same [scope]: per-peer state mutations (the `peerCadence`
 * map, the `nonceToPeer` map, an entry's `pendingNonce`) are therefore
 * trivially safe to read/write without further synchronization, because
 * they only happen on this one worker thread. The KDoc warning on [scope]
 * spells this out — adding a second dispatcher would re-introduce the
 * race the single-thread confinement exists to prevent.
 *
 * Reads (`selfState.value`, `peerHealth.value`, StateFlow collection) are
 * safe from any thread — [StateFlow] is documented thread-safe.
 *
 * [ensureSendable] reads only the current snapshots — no dispatch — so it
 * is safe to call from any thread, including the send path's caller.
 *
 * [shutdown] cancels the supervisor [scope] and stops observation. After
 * shutdown, further notify calls drop their dispatches silently
 * (the cancelled scope rejects new launches).
 *
 * ### Lazy-by-Hilt construction
 *
 * The Hilt singleton is constructed eagerly the first time anything
 * injects it. The production secondary constructor builds the
 * [PeerPingTracker] eagerly from [KeyManager] (the device ID is
 * synchronously derivable) — there is no lazy "build on auth-complete"
 * path on the Android side, which keeps the cadence engine ready to
 * fire as soon as a peer first appears via the relay listener.
 *
 * @param signalingClient The relay WebSocket adapter. Drives [selfState]
 *        via its `connectionState` flow and supplies `peer-online` /
 *        `peer-offline` / `peer-pong` text frames via `addListener`.
 * @param dispatcher Reducer-confinement dispatcher. Production uses the
 *        single-arg `@Inject` constructor which constructs a single-threaded
 *        slice of [Dispatchers.Default]; tests use this primary constructor
 *        to inject a `StandardTestDispatcher` for deterministic ordering.
 * @param pingTracker Outbound peer-ping tracker. Production wires a real
 *        one bound to [SignalingClient.send]; tests inject a stub or pass
 *        `null` to disable cadence entirely (skeleton-mode coverage).
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 */
@Singleton
class ConnectionAuthority @VisibleForTesting internal constructor(
    private val signalingClient: SignalingClient,
    private val dispatcher: CoroutineDispatcher,
    private val pingTracker: PeerPingTracker? = null,
) {

    /**
     * Production constructor. Hilt sees this and provides the
     * [SignalingClient] and [KeyManager] singletons. The reducer-confinement
     * dispatcher is a private single-threaded slice of [Dispatchers.Default];
     * tests use the [VisibleForTesting] primary constructor to inject a
     * [kotlinx.coroutines.test.StandardTestDispatcher] instead.
     *
     * Builds the production [PeerPingTracker] eagerly: we need own deviceId
     * to populate the `rendezvousId` field on outbound peer-ping frames, and
     * [KeyManager.deriveDeviceId] is synchronous so there is no benefit to
     * lazy construction. If key derivation fails (e.g. keystore corruption
     * surfaced via [KeyManager.getOrCreateKeys] throwing) we log and fall
     * back to a null tracker — cadence becomes a silent no-op until the
     * authority is reconstructed, which matches Chrome's "no ownDeviceId =>
     * skeleton mode" behaviour.
     *
     * The `sendMessage` adapter in [buildProductionTracker] is the one-liner
     * called out in Task 13's review: translates the typed [PeerPingMessage]
     * into the relay's wire JSON via [SignalingClient.send].
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    @Inject
    constructor(
        signalingClient: SignalingClient,
        keyManager: KeyManager,
    ) : this(
        signalingClient,
        Dispatchers.Default.limitedParallelism(1),
        buildProductionTracker(signalingClient, keyManager),
    )

    // ── Internal state ────────────────────────────────────────────────────

    /**
     * Supervisor scope confined to a single worker thread. Reducer dispatch,
     * `value =` writes, the `signalingClient.connectionState` collector, and
     * the cadence engine's per-peer `pingJob` / `timeoutJob` coroutines all
     * live on this scope. Cancelled by [shutdown].
     *
     * **Cadence engine (Task 16) note.** Per-peer cadence bookkeeping
     * ([peerCadence], [nonceToPeer], the in-flight `pendingNonce`) lives on
     * this same single-thread confinement context — introducing a second
     * dispatcher would re-introduce the read-modify-write race the
     * single-thread confinement exists to prevent.
     */
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    private val _selfState = MutableStateFlow<SelfState>(SelfState.Offline)
    private val _peerHealth = MutableStateFlow<Map<String, PeerHealth>>(emptyMap())

    /**
     * Per-peer cadence bookkeeping. Created lazily via [ensureCadenceFor] —
     * any peer that lands in `_peerHealth` gets an entry the first time we
     * see proof-of-life-or-presence. Torn down on `notifyPeerOffline` / on
     * shutdown.
     *
     * All reads/writes happen on the single-threaded [scope], so no extra
     * synchronization is required (per the threading contract on [scope]).
     */
    private val peerCadence = mutableMapOf<String, PeerCadence>()

    /**
     * Reverse lookup `nonce -> peerId` so [notifyPongReceived] can dispatch
     * the matching peer's reducer event without scanning [peerCadence].
     * Cleared on pong arrival, on cadence stop, and on shutdown.
     */
    private val nonceToPeer = mutableMapOf<String, String>()

    /**
     * Per-peer cadence record. `pingJob` is the scheduled "next ping fires"
     * coroutine; `timeoutJob` is the armed deadline for an in-flight ping.
     * `pendingNonce` is non-null while a ping is awaiting its pong.
     *
     * The Chrome counterpart additionally stores `lastActivityAt` for the
     * `dueAt - now()` math in `_schedulePing`. The Kotlin port does not
     * need it: every code path that schedules a fresh ping cancels the
     * existing `pingJob` first (or starts from zero on a freshly seeded
     * entry), then `delay(BG_PING_INTERVAL_MS)`s — semantically identical
     * to "now + interval" without the wall-clock arithmetic.
     */
    private data class PeerCadence(
        var pingJob: Job? = null,
        var timeoutJob: Job? = null,
        var pendingNonce: String? = null,
    )

    /** SignalingListener registration — held so [shutdown] can deregister cleanly. */
    private val relayListener = object : SignalingListener {
        override fun onMessage(message: RelayMessage) {
            if (message !is RelayMessage.Text) return
            val type = message.json.optString("type")
            when (type) {
                "peer-online" -> {
                    val peerId = message.json.optString("deviceId", "")
                    if (peerId.isNotEmpty()) notifyPeerOnline(peerId)
                }
                "peer-offline" -> {
                    val peerId = message.json.optString("deviceId", "")
                    if (peerId.isNotEmpty()) notifyPeerOffline(peerId)
                }
                "peer-pong" -> {
                    // Pong path: nonce, not deviceId — the authority resolves
                    // the nonce -> peerId mapping internally so the wire
                    // shape stays minimal.
                    val nonce = message.json.optString("nonce", "")
                    if (nonce.isNotEmpty()) notifyPongReceived(nonce)
                }
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

    /**
     * Relay reports `peerId`'s WebSocket is open (weaker-than-pong evidence).
     * Seeds the cadence entry if absent so the 120s clock starts ticking.
     * Resurrects a peer that had been [PeerHealth.Offline] back through
     * [PeerHealth.Unknown].
     */
    fun notifyPeerOnline(peerId: String) {
        scope.launch {
            dispatchPeer(peerId, PeerHealthEvent.RelayPeerOnline)
            ensureCadenceFor(peerId)
        }
    }

    /**
     * Relay reports `peerId`'s WebSocket is closed. Tears down the cadence
     * entry — OFFLINE owns the floor; no pings until the relay tells us the
     * peer is back, at which point [notifyPeerOnline] re-seeds the cadence.
     */
    fun notifyPeerOffline(peerId: String) {
        scope.launch {
            dispatchPeer(peerId, PeerHealthEvent.RelayPeerOffline)
            stopCadence(peerId)
        }
    }

    /**
     * A real v2 frame was decoded from `peerId` — strong proof of life.
     * Resets the cadence's "next ping" timer to `now + BG_PING_INTERVAL_MS`.
     * Does NOT cancel an in-flight ping (one whose [PING_TIMEOUT_MS] timer
     * is armed) — recent inbound activity proves liveness, but interrupting
     * the in-flight ping would leak the tracker entry without resolving it.
     */
    fun notifyFrameReceived(peerId: String) {
        scope.launch {
            dispatchPeer(peerId, PeerHealthEvent.FrameReceived)
            ensureCadenceFor(peerId)
            noteActivity(peerId)
        }
    }

    /**
     * A frame send to `peerId` succeeded end-to-end — strong proof of life.
     * Same cadence-reset semantics as [notifyFrameReceived].
     */
    fun notifySendCompleted(peerId: String) {
        scope.launch {
            dispatchPeer(peerId, PeerHealthEvent.SendCompleted)
            ensureCadenceFor(peerId)
            noteActivity(peerId)
        }
    }

    /**
     * A `peer-pong` was matched against an in-flight cadence ping. The
     * authority owns the `nonce -> peerId` mapping (via [nonceToPeer]) so
     * the wire frame can be minimal — only the nonce is needed.
     *
     * On a known nonce: dispatches [PeerHealthEvent.PongReceived],
     * cancels the armed timeout, and reschedules the next cadence cycle.
     * Forwards the nonce to the [PeerPingTracker] so any pre-flight probe
     * (Task 18) awaiting the same tracker promise can resolve.
     *
     * On an unknown nonce (stale, duplicate, or after `notifyPeerOffline`
     * cleared the entry): silent no-op. The tracker call is still issued —
     * `recordPong` is a no-op on unknown nonces.
     *
     * **Signature change from Task 15.** This used to be
     * `notifyPongReceived(peerId: String)` (a stub-shaped surface that
     * dispatched [PeerHealthEvent.PongReceived] directly). Task 16 rewires
     * it to take the wire's `nonce` instead — there are no production
     * callers of the old form yet (Task 15 had zero call sites for it
     * beyond tests), so this is a clean rewire.
     *
     * @param nonce 22-char base64url nonce echoed back in the
     *              `peer-pong` text frame.
     */
    fun notifyPongReceived(nonce: String) {
        scope.launch {
            // Always feed the tracker — its bookkeeping is independent of
            // the cadence engine's nonce map (Task 18 ensureSendable will
            // await tracker promises directly), and recordPong on an
            // unknown nonce is a harmless no-op.
            pingTracker?.recordPong(nonce)

            val peerId = nonceToPeer.remove(nonce) ?: return@launch
            val entry = peerCadence[peerId] ?: return@launch
            if (entry.pendingNonce != nonce) {
                // Cadence was torn down between sendPing and pong, or a
                // newer ping superseded this one. Tracker handled the
                // promise resolution above; nothing further to do.
                return@launch
            }
            // Clear the in-flight bookkeeping before dispatching so any
            // observer that introspects state sees a quiescent cadence.
            entry.timeoutJob?.cancel()
            entry.timeoutJob = null
            entry.pendingNonce = null

            dispatchPeer(peerId, PeerHealthEvent.PongReceived)
            // Reset the next ping to now + interval. A pong is also
            // proof-of-life, so the cadence cycle restarts here.
            rescheduleNextPing(peerId)
        }
    }

    /**
     * A peer-ping deadline elapsed without a pong for `peerId`. Drives
     * [PeerHealth.Healthy]/[PeerHealth.Unknown] -> [PeerHealth.Stale] and
     * [PeerHealth.Stale] -> [PeerHealth.Failed].
     *
     * Public surface preserved from Task 15 for two reasons:
     *   1. Callers that want to surface a missed ping from outside the
     *      cadence engine (e.g. an upcoming Task 18 pre-flight probe that
     *      needs the same reducer effect) can dispatch directly without
     *      reaching into the cadence engine's internals.
     *   2. Tests can drive escalation deterministically without standing up
     *      a full cadence cycle.
     *
     * The cadence engine's internal timeout path does NOT call this method;
     * it dispatches the same event directly while already on the worker
     * thread (one fewer scope-launch hop).
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
     */
    fun requestReconnect() {
        // Intentionally empty until Task 17. See KDoc.
    }

    /**
     * Tear-down hook. Cancels every per-peer cadence job, clears the
     * nonce map, cancels the supervisor [scope] (stopping the connection-
     * state collector and any in-flight reducer dispatches), and
     * deregisters the relay listener. Idempotent — calling twice is safe.
     *
     * After [shutdown], further notify calls drop their dispatches silently
     * (the cancelled scope rejects new launches). Reads of [selfState] and
     * [peerHealth] still return the last published values, but no further
     * updates will occur.
     */
    fun shutdown() {
        signalingClient.removeListener(relayListener)
        // Cancel cadence jobs explicitly before tearing down the scope.
        // scope.cancel() would cancel them too, but doing it here keeps the
        // bookkeeping consistent for the tests that introspect peerCadence
        // directly post-shutdown to verify "no leaked jobs".
        for (entry in peerCadence.values) {
            entry.pingJob?.cancel()
            entry.timeoutJob?.cancel()
        }
        peerCadence.clear()
        nonceToPeer.clear()
        scope.cancel()
    }

    // ── Cadence engine (Task 16) ──────────────────────────────────────────
    //
    // All cadence helpers run on `scope` (the single-threaded confinement
    // dispatcher) — they MUST only be called from a coroutine already on
    // that scope. The notify methods enter through `scope.launch { ... }`
    // and call these helpers inline.

    /**
     * Idempotently seed a cadence entry for `peerId`. Called from every
     * notify path that adds a peer to `_peerHealth` (`notifyPeerOnline`,
     * `notifyFrameReceived`, `notifySendCompleted`). No-op when:
     *
     *   - the entry already exists, or
     *   - no [pingTracker] is configured (skeleton-mode: nothing to send).
     *
     * MUST be called on [scope]. The `pingJob` armed here counts down by
     * [BG_PING_INTERVAL_MS] before firing the first ping.
     */
    private fun ensureCadenceFor(peerId: String) {
        if (pingTracker == null) return
        if (peerCadence.containsKey(peerId)) return
        val entry = PeerCadence()
        peerCadence[peerId] = entry
        entry.pingJob = scope.launch {
            delay(BG_PING_INTERVAL_MS)
            firePingTick(peerId)
        }
    }

    /**
     * Cancel `peerId`'s cadence jobs and forget the entry. Called from
     * [notifyPeerOffline] and [shutdown]. Removes any in-flight nonce
     * mapping so a late pong cannot resurrect cadence.
     *
     * MUST be called on [scope].
     */
    private fun stopCadence(peerId: String) {
        val entry = peerCadence.remove(peerId) ?: return
        entry.pingJob?.cancel()
        entry.timeoutJob?.cancel()
        entry.pendingNonce?.let { nonceToPeer.remove(it) }
    }

    /**
     * Reset `peerId`'s next-ping timer to `now + BG_PING_INTERVAL_MS`.
     * Called from [notifyFrameReceived], [notifySendCompleted], and the
     * pong path. Does NOT interrupt an in-flight ping (one whose
     * `timeoutJob` is armed) — the in-flight ping settles via pong or
     * timeout naturally; we just push the next cycle out.
     *
     * MUST be called on [scope].
     */
    private fun noteActivity(peerId: String) {
        val entry = peerCadence[peerId] ?: return
        // In-flight: don't disturb. The next cadence cycle is rescheduled
        // when the pong/timeout settles.
        if (entry.timeoutJob != null) return
        rescheduleNextPing(peerId)
    }

    /**
     * Cancel the existing `pingJob` (if any) and arm a fresh one to fire
     * after [BG_PING_INTERVAL_MS]. Called from [noteActivity], the pong
     * path, and the timeout path.
     *
     * MUST be called on [scope].
     */
    private fun rescheduleNextPing(peerId: String) {
        val entry = peerCadence[peerId] ?: return
        entry.pingJob?.cancel()
        entry.pingJob = scope.launch {
            delay(BG_PING_INTERVAL_MS)
            firePingTick(peerId)
        }
    }

    /**
     * Cadence-timer body: actually issue the peer-ping (or skip it for an
     * OFFLINE peer) and arm the timeout. Runs on [scope] inside the
     * `delay`-then-fire coroutine.
     *
     * Skip rules:
     *   - The cadence entry has been torn down (peer went offline mid-tick).
     *   - The peer is currently [PeerHealth.Offline] — relay owns the floor;
     *     `notifyPeerOnline` will resurrect via UNKNOWN before any ping
     *     fires. Pinging an OFFLINE peer would just produce a guaranteed
     *     timeout and a misleading FAILED state.
     *   - No tracker (skeleton-mode) — there is no transport.
     */
    private fun firePingTick(peerId: String) {
        val entry = peerCadence[peerId] ?: return
        entry.pingJob = null

        val currentHealth = _peerHealth.value[peerId] ?: return
        if (currentHealth is PeerHealth.Offline) return
        val tracker = pingTracker ?: return

        // sendPing routes through the SignalingClient.send adapter, which can
        // throw if the underlying socket is closed or the JSON serializer
        // fails. Without this guard the exception escapes to the supervisor
        // scope, leaks a PendingPing in the tracker, and kills cadence for
        // this peer (no pingJob, no timeoutJob ever fires again). Self-heal
        // by rescheduling — the next interval gets a fresh attempt and the
        // recovery ladder owns the long-tail "still broken" case in Task 17.
        val nonce = try {
            val (n, _) = tracker.sendPing(peerId)
            n
        } catch (e: Exception) {
            Log.w(TAG, "firePingTick: sendPing failed for $peerId; rescheduling", e)
            rescheduleNextPing(peerId)
            return
        }
        entry.pendingNonce = nonce
        nonceToPeer[nonce] = peerId

        entry.timeoutJob = scope.launch {
            delay(PING_TIMEOUT_MS)
            handlePingTimeout(peerId, nonce)
        }
    }

    /**
     * Timeout-body: pong did not arrive within [PING_TIMEOUT_MS]. Dispatch
     * `PingMissed` (reducer escalates UNKNOWN/HEALTHY -> STALE -> FAILED)
     * and schedule the next cadence cycle from now.
     *
     * Guarded by nonce match: if a pong landed first and cleared
     * `pendingNonce`, the timeout is a stale callback — skip. (Hard to hit
     * with the cancellation discipline above, but defensive against any
     * race the dispatch model didn't anticipate.)
     */
    private fun handlePingTimeout(peerId: String, nonce: String) {
        val entry = peerCadence[peerId] ?: return
        if (entry.pendingNonce != nonce) return // pong already cleared
        entry.pendingNonce = null
        entry.timeoutJob = null
        nonceToPeer.remove(nonce)

        dispatchPeer(peerId, PeerHealthEvent.PingMissed)

        // Spec budgets two consecutive misses before FAILED; the next cycle
        // starts immediately from now (one full BG_PING_INTERVAL_MS away).
        rescheduleNextPing(peerId)
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

    private companion object {
        /**
         * Build the production [PeerPingTracker] from the injected
         * [SignalingClient] and [KeyManager]. Returns `null` (logged) if
         * key derivation fails — cadence quietly disables, matching
         * Chrome's "no ownDeviceId => skeleton mode" behaviour. The
         * `sendMessage` adapter is the [PeerPingMessage] -> wire-JSON
         * translation called out in Task 13's review.
         */
        fun buildProductionTracker(
            signalingClient: SignalingClient,
            keyManager: KeyManager,
        ): PeerPingTracker? = try {
            val keys = keyManager.getOrCreateKeys()
            val ownDeviceId = keyManager.deriveDeviceId(keys.ed25519Pk)
            PeerPingTracker(
                sendMessage = { msg ->
                    val json = JSONObject().apply {
                        put("type", msg.type)
                        put("nonce", msg.nonce)
                        put("targetDeviceId", msg.targetDeviceId)
                        put("rendezvousId", msg.rendezvousId)
                    }
                    signalingClient.send(json)
                },
                timeoutMs = PING_TIMEOUT_MS,
                ownDeviceId = ownDeviceId,
            )
        } catch (e: Exception) {
            // Catch Exception, NOT Throwable — we must not swallow OOM,
            // StackOverflowError, or coroutine CancellationException.
            // Recoverable failure modes here are KeyManager keystore errors
            // (KeyStoreException / GeneralSecurityException) and JSON I/O
            // surfaced via SignalingClient.send; null-tracker disables
            // cadence until the authority is reconstructed.
            Log.w(TAG, "Failed to build PeerPingTracker; cadence disabled", e)
            null
        }
    }
}
