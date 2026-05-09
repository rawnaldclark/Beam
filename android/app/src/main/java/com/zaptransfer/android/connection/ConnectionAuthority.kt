package com.zaptransfer.android.connection

import android.util.Log
import androidx.annotation.VisibleForTesting
import com.zaptransfer.android.crypto.KeyManager
import com.zaptransfer.android.service.ServiceLifecycle
import com.zaptransfer.android.service.ServiceState
import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
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
 *   5. Provide `ensureSendable(peerId)` — full async pre-flight: HEALTHY-
 *      with-recent-traffic skip, 5s peer-ping probe, recovery-ladder
 *      kick on probe failure, await-and-re-probe on ladder success.
 *      Returns one of the three [SendGate] cases.
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
 * [ensureSendable] is `suspend` (Task 18). It is safe to invoke from any
 * caller's coroutine context: the per-peer coalescing map mutation is
 * guarded by [preflightMutex], and the inner pre-flight algorithm runs
 * on [scope] via `scope.async` so its reducer dispatches stay confined.
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
    /**
     * Wall-clock source for the pre-flight `lastTrafficAt` window
     * (Task 18 / §"Send-time pre-flight"). Tests inject a fake clock
     * lambda to drive the 30s recent-traffic skip deterministically;
     * production uses [System.currentTimeMillis].
     *
     * Why a separate lambda (vs. relying on virtual time): the cadence
     * engine's `delay(...)` participates in [StandardTestDispatcher]
     * virtual time, but the recent-traffic window compares wall-clock
     * timestamps written from the worker thread. Using the test
     * scheduler's virtual time would couple the two clocks and force
     * pre-flight tests to advance virtual time even when probing a
     * peer that is HEALTHY-with-recent-traffic (a path that should
     * issue zero pings). The lambda decouples the two cleanly.
     */
    private val now: () -> Long = System::currentTimeMillis,
    /**
     * Process-scoped service-lifecycle observable consumed by Rung 3
     * (Task 20). Defaults to a fresh disconnected instance for tests
     * that don't drive Rung 3; production wires the Hilt @Singleton.
     */
    private val serviceLifecycle: ServiceLifecycle = ServiceLifecycle(),
    /**
     * Full session-reset hook for Rung 3 (Task 20). Production wires
     * this post-construction via [setForceFullReset] from a Hilt module
     * (avoiding a `BeamV2Wiring ↔ ConnectionAuthority` DI cycle); tests
     * inject directly.
     *
     * Hook contract:
     *   1. Stop the foreground service (await `serviceLifecycle = Stopped`).
     *   2. Clear v2 transport in-memory state (outbox / inbox / inflight).
     *   3. Restart the foreground service (await `serviceLifecycle = Running`).
     *
     * Throws → swallowed by Rung 3; the budget-timer race observes
     * success-by-other-path before surrendering. `null` → Rung 3
     * surrenders synchronously (skeleton mode).
     */
    forceFullReset: (suspend () -> Unit)? = null,
) {

    /**
     * Mutable so production wiring can install the hook AFTER construction
     * (resolves the BeamV2Wiring ↔ ConnectionAuthority DI cycle that
     * caching the hook eagerly would force). Read-only from the rung
     * action's perspective — once set, the reference is stable for the
     * life of the authority.
     */
    private var forceFullReset: (suspend () -> Unit)? = forceFullReset

    /**
     * Production-side wiring hook: install the `forceFullReset` callback
     * after construction. The Hilt module that builds [ConnectionAuthority]
     * cannot inject a callback that closes over [BeamV2Wiring] in the
     * primary constructor without a DI cycle — so the wiring layer calls
     * this from its own `init` once both singletons are live.
     *
     * Idempotent: re-installing the hook overwrites the previous reference.
     * The replacement takes effect on the NEXT Rung 3 invocation; an
     * in-flight Rung 3 continues to use the reference it captured.
     */
    fun setForceFullReset(reset: suspend () -> Unit) {
        forceFullReset = reset
    }

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
     * Per-peer wall-clock timestamp of the most recent **user-data** frame
     * (received or sent). Updated by [notifyFrameReceived] and
     * [notifySendCompleted]; consumed by [isHealthyWithRecentTraffic] for
     * the pre-flight HEALTHY-with-recent-traffic skip.
     *
     * **Deliberately NOT updated on pong arrival** (Task 11 follow-up F,
     * `connection-authority.js:283-297`): pongs are the cadence engine's
     * own bookkeeping and would otherwise paper over the "no real traffic
     * for 5 minutes" case where a probe is precisely what we want.
     *
     * Reads/writes happen on the single-threaded [scope], so no extra
     * synchronization is required (per the threading contract on [scope]).
     */
    private val lastTrafficAt = mutableMapOf<String, Long>()

    /**
     * Per-peer pre-flight coalescing map. Concurrent [ensureSendable] calls
     * for the same peer share the in-flight [Deferred]; the first caller
     * drives the probe + ladder await, others just `await()` the same
     * outcome. Cleared when the Deferred completes.
     *
     * Mirror of `_inflightPreflight: Map<String, Promise>` in
     * `connection-authority.js#ensureSendable`. Prevents a clipboard burst
     * (e.g. 5 files dragged in) from firing 5 redundant peer-pings to the
     * same peer.
     *
     * Mutations are guarded by [preflightMutex] because callers can land
     * from any coroutine context (not just [scope]) — a Mutex is the
     * minimum-overhead serializer for the get-then-set / get-then-remove
     * race that two concurrent [ensureSendable] calls would otherwise hit
     * if mutating off [scope].
     */
    private val inflightPreflight = mutableMapOf<String, Deferred<SendGate>>()
    private val preflightMutex = Mutex()

    /**
     * Recovery ladder owns "I'm trying to recover" sequencing. Non-null
     * while a ladder is in flight; reset to null in [handleLadderSettled].
     *
     * Reads/writes happen on [scope]'s single-thread confinement, so no
     * additional synchronization is needed. Tests probe this field via
     * [VisibleForTesting] to verify single-flight discipline (concurrent
     * peer-FAILED transitions must share the in-flight ladder).
     */
    @VisibleForTesting
    internal var currentLadder: RecoveryLadder? = null
        private set

    /**
     * Companion flag to [currentLadder] tracking whether the in-flight
     * ladder is the thrash-surrender variant (one synthetic rung that
     * returns false synchronously, sending us straight to Rung 4 without
     * incrementing the thrash log). Mirrors Chrome's
     * `RecoveryLadder._isSurrenderLadder` tag.
     *
     * `false` whenever [currentLadder] is null. Reads/writes on [scope]'s
     * single-thread confinement.
     */
    private var currentLadderIsSurrender: Boolean = false

    /**
     * Track of whether the authority is in "shutting down" state. Set in
     * [shutdown] before scope cancellation so any post-cancel observable
     * collector that races the teardown can short-circuit cleanly. Without
     * this guard, a peer-FAILED event landing on the worker thread the
     * exact tick before [scope] cancels would attempt to kick a new ladder
     * after teardown — harmless in isolation, but the leaked
     * [RecoveryLadder] would never settle.
     */
    @Volatile
    private var shuttingDown: Boolean = false

    // ── Task 20 — Rung 4 surrender / backoff / thrash guard ───────────────

    /**
     * Surrender flag (Task 20 — Rung 4). `true` after the ladder has given
     * up and we are waiting on backoff or manual user tap; `false` otherwise.
     * Mirrors Chrome's `_surrenderedToUser.value` Observable.
     *
     * Lives on [scope]'s single-thread confinement; reads from `selfState`
     * subscribers (e.g. UI banner) get a consistent value via the
     * [selfStateWithSurrender] StateFlow exposure (deferred — Task 21 wires
     * the UI). For Task 20 we track it as a private flag and surface only
     * via tests.
     */
    @VisibleForTesting
    internal var surrenderedToUser: Boolean = false
        private set

    /**
     * Timestamps (in [now] coordinates) of recent full Rung-3 failures.
     * A "full Rung-3 failure" is recorded by [recordRung3Failure] exactly
     * when the ladder reached Rung 3, ran its full budget, and `selfState`
     * did not become ONLINE. Entries older than [RUNG_3_THRASH_WINDOW_MS]
     * are pruned at the next read via [thrashGuardActive].
     *
     * Mirrors Chrome's `_rung3FailureLog`. Lives on [scope]'s single-
     * thread confinement.
     */
    private val rung3FailureLog = mutableListOf<Long>()

    /**
     * Auto-retry attempt counter for Rung 4 backoff. Indexes into
     * [BACKOFF_SCHEDULE_MS]. Reset to 0 every time recovery succeeds (or
     * [requestReconnect] fires). Capped at the last index (the spec's
     * 30-min cap rule). Mirrors Chrome's `_backoffAttempt`.
     */
    private var backoffAttempt: Int = 0

    /**
     * Pending Rung-4 auto-retry [Job]. Non-null while a `delay(...)` is
     * armed; cleared when the timer fires, on [requestReconnect] (manual
     * tap bypasses backoff), and on [shutdown].
     *
     * **CRITICAL cancellation order.** [shutdown] MUST cancel this Job
     * BEFORE `scope.cancel()` AND null the field. Otherwise `runTest`'s
     * teardown `advanceUntilIdle` advances virtual time to the still-armed
     * `delay`, [fireBackoffRetry] runs on a (just-cancelled) scope, and
     * the test JVM hangs on never-draining work. Mirrors the prior-attempt
     * gotcha called out in Task 20's CRITICAL notes.
     *
     * `@Volatile` because writes happen on the worker thread (inside
     * [scheduleBackoffRetry]) but reads/cancels from [shutdown] run on the
     * caller's thread. Without the visibility guarantee the field-cancel
     * could miss an armed Job, leaving the explicit pre-cancel ordering
     * above ineffective.
     */
    @Volatile
    private var backoffJob: Job? = null

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
            // Task 18: record real user-data traffic for the recent-traffic
            // pre-flight skip. Snapshotted on the worker thread so reads
            // from `_isHealthyWithRecentTraffic` (also on the worker thread
            // for the single-flight branch) see a consistent value.
            lastTrafficAt[peerId] = now()
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
            // Task 18: same recent-traffic bookkeeping as notifyFrameReceived
            // — both inbound and outbound v2 frames count as proof-of-life
            // for the 30s skip window.
            lastTrafficAt[peerId] = now()
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
            // the cadence engine's nonce map (the Task 18 `ensureSendable`
            // pre-flight awaits tracker promises directly), and recordPong
            // on an unknown nonce is a harmless no-op.
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
     * to [PeerHealth.Failed] from any state. Used by [ensureSendable]
     * after a probe-then-ladder cycle exhausts.
     */
    fun notifyPreFlightFailed(peerId: String) =
        dispatchPeerAsync(peerId, PeerHealthEvent.PreFlightFailed)

    // ── Public actions ────────────────────────────────────────────────────

    /**
     * Send-time pre-flight gate. Mirror of `_runEnsureSendable` in
     * `extension/connection/connection-authority.js` (Chrome Task 9).
     *
     * The algorithm:
     * ```
     * 1. selfState != ONLINE          → SelfOffline
     * 2. peerHealth==HEALTHY AND lastTrafficAt within 30s → Ok (skip probe)
     * 3a. probe with 5s peer-ping
     *      pong → dispatch PongReceived (promotes peer) → Ok
     *      timeout → continue
     * 3b. dispatch PreFlightFailed → drives peer to FAILED, post-hook kicks
     *      ladder; explicit kickLadder follow-through (idempotent — single-
     *      flight guard absorbs re-entry).
     * 3c. await currentLadder?.run(); on Cancelled / Exhausted →
     *      PeerUnreachable; on Success → continue.
     * 3d. re-probe; pong → Ok; otherwise PeerUnreachable.
     * ```
     *
     * **Per-peer coalescing.** Concurrent calls for the same peer share
     * one in-flight [Deferred] via [inflightPreflight]; the first caller
     * drives the probe + ladder await, others just `await()` the same
     * outcome. The self-offline gate (step 1) runs BEFORE the coalescing
     * map is consulted — a self-offline answer is the same for every
     * peer, no benefit to sharing the inflight slot.
     *
     * **Zero frames transmitted on a non-Ok gate.** This is the entire
     * reason for this method existing — the caller (TransferEngine /
     * DeviceHubViewModel) MUST NOT call `beamV2Wiring.transport.sendFile`
     * unless the verdict is [SendGate.Ok]. See spec §"Send-time pre-flight"
     * line 317.
     *
     * Safe to call from any coroutine context. The internal map mutation
     * goes through [preflightMutex]; the probe + ladder await happen on
     * the caller's context (suspending), with reducer dispatches going
     * through the existing [scope] launches.
     *
     * @param peerId Target peer's device ID.
     */
    suspend fun ensureSendable(peerId: String): SendGate {
        // Step 1: self-online gate. Cheap, applies before any per-peer
        // coalescing — a self-offline answer is the same for every peer,
        // no benefit to sharing the inflight slot.
        if (_selfState.value !is SelfState.Online) return SendGate.SelfOffline

        // Coalesce concurrent calls for the same peer. We use scope.async
        // so the worker-thread state mutations inside `runEnsureSendable`
        // (lastTrafficAt read, dispatch hooks) inherit the single-thread
        // confinement; the coalescing map itself is guarded by a Mutex
        // so off-scope callers can serialize get-then-set without racing.
        val deferred = preflightMutex.withLock {
            inflightPreflight[peerId]?.let { return@withLock it }
            // Skeleton-mode: no scope to launch on once shutdown started,
            // and no tracker means we'd just bounce off step 3a anyway.
            // Hand the caller a synchronous PEER_UNREACHABLE to match
            // Chrome's `_preFlightProbe` skeleton-mode short-circuit
            // (`connection-authority.js:560-562`).
            if (shuttingDown) {
                val unreachable = CompletableDeferred<SendGate>().apply {
                    complete(SendGate.PeerUnreachable("PEER_UNREACHABLE"))
                }
                return@withLock unreachable
            }
            val fresh: Deferred<SendGate> = scope.async { runEnsureSendable(peerId) }
            inflightPreflight[peerId] = fresh
            fresh.invokeOnCompletion {
                // Clear only if the entry is still ours — defensive; in
                // practice the Deferred reference identity stays stable.
                scope.launch {
                    preflightMutex.withLock {
                        if (inflightPreflight[peerId] === fresh) {
                            inflightPreflight.remove(peerId)
                        }
                    }
                }
            }
            fresh
        }
        return deferred.await()
    }

    /**
     * Inner pre-flight body — separated so [ensureSendable] can wrap it
     * with the coalescing map without nesting the algorithm.
     *
     * Runs on [scope] (the single-thread confinement) via the
     * `scope.async { ... }` launch in [ensureSendable]. Reads of
     * [_peerHealth] / [lastTrafficAt] are therefore consistent with any
     * concurrent reducer dispatch; the dispatchPeer / kickLadder calls
     * here piggyback on the same worker thread.
     */
    private suspend fun runEnsureSendable(peerId: String): SendGate {
        // Step 2: HEALTHY + recent traffic skip. Worker-thread read of
        // both maps — no race with notifyFrameReceived / notifySendCompleted.
        if (isHealthyWithRecentTraffic(peerId)) {
            return SendGate.Ok
        }

        // Step 3a: probe with a 5s peer-ping. Skeleton-mode (no tracker
        // and/or shutting down) cannot probe; treat as unreachable rather
        // than waving the send through.
        val firstProbe = preFlightProbe(peerId)
        if (firstProbe) return SendGate.Ok

        // Step 3b: probe failed. Mark FAILED (idempotent if already FAILED)
        // and ensure a recovery ladder is running. The reducer's
        // pre-flight-failed event drives any non-OFFLINE state directly to
        // FAILED. The [dispatchPeer] post-hook kicks [kickLadder] only on
        // the OLD→FAILED transition; if the peer was already FAILED we
        // still need a ladder so we explicitly call [kickLadder] after
        // (idempotent — a running ladder is reused).
        dispatchPeer(peerId, PeerHealthEvent.PreFlightFailed)
        kickLadder(triggerPeerId = peerId, reason = "pre-flight-failed")

        // Step 3c: await the in-flight ladder. The ladder owns its own
        // budget timers and resolves with `ok=false` on exhaustion /
        // cancellation. No ladder running (skeleton-mode where kickLadder
        // bailed because shutdown started) is treated as a synchronous
        // failure.
        val ladder = currentLadder ?: return SendGate.PeerUnreachable("PEER_UNREACHABLE")
        val ladderResult = try {
            ladder.run()
        } catch (ce: CancellationException) {
            // Structured-concurrency shutdown — propagate so the caller's
            // scope tears down. Catching CE as a domain outcome would mask
            // parent-cancellation as PEER_UNREACHABLE and leak the
            // launched-from-here `scope.async` chain.
            throw ce
        } catch (e: Exception) {
            // RecoveryLadder.run is documented "never throws", but defend
            // against it anyway.
            Log.w(TAG, "ensureSendable: ladder.run() threw", e)
            return SendGate.PeerUnreachable("PEER_UNREACHABLE")
        }
        if (!ladderResult.ok) return SendGate.PeerUnreachable("PEER_UNREACHABLE")

        // Step 3d: ladder succeeded. Re-probe one more time. The ladder's
        // success path already dispatched RecoverySucceeded which dropped
        // the peer to UNKNOWN, so the HEALTHY-skip branch won't short-
        // circuit; we issue a fresh peer-ping to confirm the send path
        // before the caller commits to encoding frames.
        val retryProbe = preFlightProbe(peerId)
        return if (retryProbe) SendGate.Ok else SendGate.PeerUnreachable("PEER_UNREACHABLE")
    }

    /**
     * Step-2 helper: returns true iff the peer is [PeerHealth.Healthy] AND
     * a recent traffic timestamp falls within [RECENT_TRAFFIC_WINDOW_MS].
     *
     * MUST be called on [scope] (it is — invoked from [runEnsureSendable]
     * which runs via `scope.async`).
     */
    private fun isHealthyWithRecentTraffic(peerId: String): Boolean {
        if (_peerHealth.value[peerId] !== PeerHealth.Healthy) return false
        val last = lastTrafficAt[peerId] ?: return false
        return (now() - last) < RECENT_TRAFFIC_WINDOW_MS
    }

    /**
     * Issue a single peer-ping racing the tracker's resolve against a 5s
     * timer. Returns `true` on a pong landing inside the window, `false`
     * on either the timer expiring first or skeleton-mode (no tracker /
     * shutting down).
     *
     * Implementation note: the cadence-loop [pingTracker] has its own 10s
     * timeoutMs. Reusing it for pre-flight is fine — we ignore the
     * tracker's longer timeout by resolving on whichever lands first
     * (pong via `await()`, or our 5s `withTimeoutOrNull`). A late pong
     * after our timer fires is still safe: the tracker cleans up its own
     * pending entry on `recordPong` / `sweepExpired`.
     *
     * Per Task 11 follow-up F: a successful pre-flight pong is real proof
     * of peer life and SHOULD promote peerHealth through the reducer. We
     * deliberately do NOT register the nonce in [nonceToPeer] (that map
     * is the cadence engine's bookkeeping; mixing pre-flight nonces in
     * would complicate the cadence-engine invariants). Instead, we
     * explicitly dispatch [PeerHealthEvent.PongReceived] directly when
     * the tracker promise resolves inside this function.
     *
     * MUST be called on [scope].
     */
    private suspend fun preFlightProbe(peerId: String): Boolean {
        val tracker = pingTracker ?: return false
        if (shuttingDown) return false

        val (_, deferred) = tracker.sendPing(peerId, now())
        // Race the tracker's deferred against our 5s timer. Note that the
        // virtual-time `delay(...)` inside `withTimeoutOrNull` resolves
        // via the cadence engine's StandardTestDispatcher in tests, so the
        // tracker's wall-clock-based timeout is irrelevant — pre-flight's
        // shorter window always wins or the pong does.
        val result = withTimeoutOrNull(PRE_FLIGHT_PING_TIMEOUT_MS) {
            deferred.await()
        }
        return when (result) {
            is PingResult.Pong -> {
                // Pong landed within our 5s window — promote the peer to
                // HEALTHY through the reducer (Task 11 follow-up F).
                dispatchPeer(peerId, PeerHealthEvent.PongReceived)
                true
            }
            // null = our 5s timer fired first (or the tracker resolved
            // TimedOut on its own 10s deadline; either way, no pong).
            else -> false
        }
    }

    /**
     * Manual reconnect entry point (e.g. UI "Reconnect" tap, lifecycle
     * resume).
     *
     * Per spec §"Discipline rules": "Manual tap always bypasses backoff.
     * `requestReconnect` mid-ladder cancels and restarts at Rung 3."
     *
     * Sequence (mirrors Chrome's `requestReconnect` in
     * `extension/connection/connection-authority.js#requestReconnect`):
     *   1. Cancel any in-flight ladder. The cancellation propagates into
     *      the rung action via [RecoveryLadder.cancel] → [rungScope]'s
     *      cancellation; the launched-from-kickLadder collector observes
     *      [LadderResult.Cancelled] and `handleLadderSettled` returns
     *      without running [recordRung3Failure] / [promoteToRung4].
     *   2. Cancel the Rung-4 backoff timer (manual tap bypasses backoff).
     *   3. Drop the surrender flag.
     *   4. Reset the thrash log (the user has intervened, so the
     *      "two recent Rung-3 failures" signal is no longer relevant).
     *   5. Reset the backoff attempt counter.
     *   6. Build a fresh ladder starting at Rung 3 (skipping Rungs 1+2 —
     *      manual reconnect implies the user has decided the lighter
     *      rungs aren't worth trying).
     *   7. Latch [currentLadder] BEFORE dispatching `RecoveryBegan` so
     *      the post-hook re-entry hits the "ladder owns the floor" guard.
     *   8. Launch the new ladder via [scope.launch].
     *
     * **Cancel-then-launch ordering.** The cancellation of the prior
     * ladder is synchronous from the caller's perspective ([RecoveryLadder.cancel]
     * is non-suspending). The actual settlement of the prior ladder's
     * `run()` happens asynchronously on its own [scope.launch] — but the
     * `currentLadder === ladder` guard in [kickLadder] prevents the
     * settle handler from clobbering our newly-installed ladder slot.
     *
     * Safe to call from any thread — marshals onto [scope] via launch.
     * No-op if shutting down.
     */
    fun requestReconnect() {
        if (shuttingDown) return
        scope.launch {
            // 1. Cancel any in-flight ladder. The launched-from-kickLadder
            // settle handler will see LadderResult.Cancelled and skip the
            // promoteToRung4 path. We snapshot the prior ladder reference
            // BEFORE clearing currentLadder so kickLadder's
            // `if (currentLadder === ladder)` guard correctly distinguishes
            // "the prior ladder cancelled" from "the new ladder is in flight".
            currentLadder?.cancel()
            currentLadder = null
            currentLadderIsSurrender = false

            // 2. Cancel any pending Rung-4 backoff retry. Manual tap is
            // the user saying "don't wait, try now."
            cancelBackoffJob()

            // 3. Drop the surrender flag so the popup banner shows
            // "Reconnecting…" again (yellow), not "Connection failed" (red).
            if (surrenderedToUser) surrenderedToUser = false

            // 4. Reset the thrash log — the user has intervened.
            rung3FailureLog.clear()

            // 5. Reset the backoff attempt counter so the next surrender
            // (if any) starts at the 30s schedule[0] again.
            backoffAttempt = 0

            // 6. Build a fresh ladder starting at Rung 3.
            val ladder = buildRung3OnlyLadder()
            // 7. Latch BEFORE dispatching RecoveryBegan (same ordering
            // rationale as kickLadder).
            currentLadder = ladder
            currentLadderIsSurrender = false
            dispatchSelf(SelfStateEvent.RecoveryBegan)

            Log.i(TAG, "[CA] ladder: kicked reason=manual-reconnect")

            // 8. Launch the new ladder. The settle handler runs through
            // the same handleLadderSettled path as auto-kicked ladders;
            // success lifts to Online, exhaustion goes through Rung 4.
            scope.launch {
                val result = ladder.run()
                val wasSurrender = currentLadderIsSurrender
                if (currentLadder === ladder) {
                    currentLadder = null
                    currentLadderIsSurrender = false
                }
                handleLadderSettled(result, triggerPeerId = null, wasSurrenderLadder = wasSurrender)
            }
        }
    }

    /**
     * Build a single-rung ladder that runs ONLY Rung 3. Used by
     * [requestReconnect] — manual tap always goes straight to a full
     * session reset (Rungs 1 + 2 are useful for "keep the existing
     * transport, just nudge it" scenarios; manual reconnect implies the
     * user has decided the lighter rungs aren't worth trying).
     *
     * Mirrors Chrome's `_buildRung3OnlyLadder`.
     */
    private fun buildRung3OnlyLadder(): RecoveryLadder = RecoveryLadder(
        rungs = listOf(
            RecoveryRung(
                name = "rung3",
                budgetMs = RUNG_3_BUDGET_MS,
                action = { rungScope -> rung3Action(rungScope) },
            ),
        ),
    )

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
        // Set the shutting-down latch BEFORE cancelling anything: the ladder
        // settle handler reads it on the worker thread to decide whether to
        // dispatch RecoverySucceeded etc. on the way out. Without the latch,
        // a Cancelled-result settle racing the scope cancellation could
        // re-enter dispatchSelf on a half-torn-down state machine.
        shuttingDown = true
        signalingClient.removeListener(relayListener)
        // CRITICAL ordering (Task 20): cancel the Rung-4 backoff Job
        // BEFORE [scope.cancel] — without this, runTest's teardown
        // advanceUntilIdle advances virtual time to the still-armed
        // `delay`, [fireBackoffRetry] runs on a (just-cancelled) scope,
        // and the test JVM hangs on never-draining work. Field is nulled
        // explicitly so a post-cancel advanceUntilIdle sees no armed delay.
        cancelBackoffJob()
        // Cancel any in-flight ladder so its budget timers / Flow.first
        // subscriptions release. The ladder's run() resolves with a
        // Cancelled outcome which the settle handler ignores once shutting-
        // Down is true.
        currentLadder?.cancel()
        currentLadder = null
        currentLadderIsSurrender = false
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
        // Cancel any in-flight pre-flight Deferreds so callers awaiting
        // them resolve via CancellationException rather than hanging on a
        // never-completed Deferred. The map is read off-scope (via
        // [preflightMutex]); here we touch it from the [shutdown] caller's
        // thread, which is racy in the strict sense but safe in practice
        // — the worst case is a concurrent ensureSendable observes the
        // pre-clear snapshot and bounces off the `shuttingDown` guard
        // inside the lock instead.
        for (deferred in inflightPreflight.values) deferred.cancel()
        inflightPreflight.clear()
        lastTrafficAt.clear()
        scope.cancel()
    }

    // ── Recovery ladder (Task 17) ─────────────────────────────────────────
    //
    // Mirror of `extension/connection/connection-authority.js` _kickLadder /
    // _buildLadder / _rung1Action / _rung2Action / _handleLadderSettled
    // (commit `dd87ae2`). Tasks 11+ (Rungs 3+4, thrash guard, backoff) are
    // intentionally NOT yet wired; the ladder is a two-rung
    // (re-register + WS reconnect) sequence here. Exhaustion clears
    // `currentLadder` without dispatching `RecoveryGivenUp` — Rung 4
    // surrender lands in the follow-up task.

    /**
     * Start the recovery ladder if none is currently running. Idempotent:
     * concurrent failures (multiple peers FAILED in the same tick, or a
     * `selfState = RECONNECTING` cross while a peer-FAILED ladder is in
     * flight) are absorbed into the existing ladder rather than starting
     * a second.
     *
     * Resets [currentLadder] = null once the ladder resolves (success,
     * exhaustion, or cancellation) so the next failure starts from Rung 1
     * again — matching the spec's discipline rule "A rung that succeeds
     * resets the ladder to idle."
     *
     * MUST be called on [scope] (it is — the dispatchSelf / dispatchPeer
     * post-hooks both run on the worker thread).
     *
     * @param triggerPeerId The peer that crossed into [PeerHealth.Failed],
     *        or `null` for self-RECONNECTING / shutdown / pre-flight kicks.
     * @param reason Short tag for the kick log line; one of
     *        `peer-failed`, `self-reconnecting`.
     */
    private fun kickLadder(triggerPeerId: String?, reason: String) {
        if (shuttingDown) return
        if (currentLadder != null) return // ladder owns the floor

        // Task 20 — thrash guard: if the last RUNG_3_THRASH_THRESHOLD Rung-3
        // failures all landed within RUNG_3_THRASH_WINDOW_MS, skip Rungs
        // 1+2+3 and go straight to Rung 4. The synthetic surrender ladder
        // returns false synchronously, dropping into [handleLadderSettled]
        // → [promoteToRung4]. Tagged via [currentLadderIsSurrender] so the
        // settle handler doesn't double-count this kick toward the thrash
        // log (the failures that triggered it are already counted).
        val thrash = thrashGuardActive()
        val ladder = if (thrash) buildSurrenderLadder() else buildLadder(triggerPeerId)
        // CRITICAL ordering (mirrors Chrome): latch `currentLadder` BEFORE
        // dispatching `RecoveryBegan`. The selfState reducer's RECONNECTING
        // post-hook in [dispatchSelf] re-enters [kickLadder]; latching first
        // makes the re-entry hit the "ladder owns the floor" guard cleanly
        // so we never run two concurrent ladders.
        currentLadder = ladder
        currentLadderIsSurrender = thrash

        // Dispatch RecoveryBegan so the popup banner shows "Reconnecting"
        // immediately on a peer-FAILED kick, not just on a self-RECONNECTING
        // ws-closed transition. Per follow-up A on Chrome's Task 11 review.
        dispatchSelf(SelfStateEvent.RecoveryBegan)

        Log.i(
            TAG,
            "[CA] ladder: kicked reason=$reason triggerPeer=${triggerPeerId ?: "none"}" +
                if (thrash) " thrash=YES" else "",
        )

        scope.launch {
            val result = ladder.run()
            // Snapshot whether this ladder was a surrender ladder BEFORE
            // clearing the slot — handleLadderSettled needs the flag to
            // decide whether to count toward the thrash log.
            val wasSurrender = currentLadderIsSurrender
            // After the ladder settles, if shutdown raced us, the assignment
            // here is harmless (currentLadder is already null) — the guard
            // in handleLadderSettled prevents post-shutdown dispatches.
            if (currentLadder === ladder) {
                currentLadder = null
                currentLadderIsSurrender = false
            }
            handleLadderSettled(result, triggerPeerId, wasSurrender)
        }
    }

    /**
     * Build the two-rung ladder for the given trigger.
     *
     * Tasks 11+ (Rungs 3+4 + thrash + backoff) extend this — for Task 17 we
     * have the re-register-rendezvous and WS-reconnect rungs only. Rung
     * actions close over `this` so they can read the live state and emit
     * via [signalingClient].
     *
     * @param triggerPeerId The peer that crossed into [PeerHealth.Failed],
     *        or `null` for self-RECONNECTING.
     */
    private fun buildLadder(triggerPeerId: String?): RecoveryLadder = RecoveryLadder(
        rungs = listOf(
            RecoveryRung(
                name = "rung1",
                budgetMs = RUNG_1_BUDGET_MS,
                action = { rungScope -> rung1Action(triggerPeerId, rungScope) },
            ),
            RecoveryRung(
                name = "rung2",
                budgetMs = RUNG_2_BUDGET_MS,
                action = { rungScope -> rung2Action(rungScope) },
            ),
            RecoveryRung(
                name = "rung3",
                budgetMs = RUNG_3_BUDGET_MS,
                action = { rungScope -> rung3Action(rungScope) },
            ),
        ),
    )

    /**
     * Rung 1 — re-register-rendezvous + wait for success indicator.
     *
     * Action: dispatch a `register-rendezvous` JSON frame over the existing
     * [signalingClient] (relay may have GC'd our session). Success indicator:
     *
     *  - Peer-trigger (`triggerPeerId != null`): the failed peer becomes
     *    [PeerHealth.Healthy] within [RUNG_1_BUDGET_MS].
     *  - Self-trigger (`triggerPeerId == null`): [selfState] is
     *    [SelfState.Online] AND any peer in [peerHealth] is
     *    [PeerHealth.Healthy] within [RUNG_1_BUDGET_MS]. Per Chrome Task 8
     *    follow-up C: a Rung 1 fired by self-RECONNECTING really should
     *    require self-online, not just "some peer eventually became
     *    HEALTHY" — the latter could read as a success while we're still
     *    stuck CONNECTING.
     *
     * A throwing [signalingClient.send] (e.g. WS already closed) is caught
     * and swallowed: the action falls through to the success-criterion
     * await, which will time out cleanly and advance to Rung 2.
     *
     * @param triggerPeerId The peer that crossed into FAILED, or `null`.
     * @param rungScope The rung's cancellation scope. The
     *        [withTimeoutOrNull] / Flow.first pattern observes its
     *        cancellation cooperatively; an external [RecoveryLadder.cancel]
     *        propagates here as a [kotlinx.coroutines.CancellationException]
     *        out of the suspending wait.
     */
    private suspend fun rung1Action(
        triggerPeerId: String?,
        @Suppress("UNUSED_PARAMETER") rungScope: kotlinx.coroutines.CoroutineScope,
    ): Boolean {
        // Best-effort dispatch. A throwing send shouldn't crash the ladder
        // — it just means Rung 1 cannot recover and we'll time out and
        // advance to Rung 2.
        try {
            val frame = JSONObject().apply {
                put("type", "register-rendezvous")
                // Match the JS shape: a single rendezvousId field carrying
                // own deviceId. The relay accepts both this and the array
                // form used by [SignalingClient.registerRendezvous] for
                // multi-rendezvous scenarios.
                pingTracker?.let { put("rendezvousId", it.ownDeviceId) }
            }
            signalingClient.send(frame)
        } catch (e: Exception) {
            // Swallow — see KDoc.
            Log.d(TAG, "rung1Action: send register-rendezvous failed", e)
        }

        return withTimeoutOrNull(RUNG_1_BUDGET_MS) {
            if (triggerPeerId != null) {
                _peerHealth.first { map -> map[triggerPeerId] === PeerHealth.Healthy }
            } else {
                combine(_selfState, _peerHealth) { s, m ->
                    s === SelfState.Online && m.values.any { it === PeerHealth.Healthy }
                }.first { it }
            }
            true
        } ?: false
    }

    /**
     * Rung 2 — tear down the WebSocket and reopen it.
     *
     * Action: call [signalingClient.disconnect] then [signalingClient.connect]
     * — the production [com.zaptransfer.android.webrtc.SignalingClient]
     * idempotently reopens via its existing reconnect loop, and the auth-
     * complete handler auto-replays the most recent register-rendezvous so
     * the relay's presence module rebinds without a separate dispatch.
     *
     * Success indicator (same composite predicate as Rung 1's self-trigger):
     * [selfState] is [SelfState.Online] AND any paired peer is
     * [PeerHealth.Healthy] within [RUNG_2_BUDGET_MS].
     *
     * A throwing disconnect/connect pair is caught and swallowed — the
     * success-criterion wait still gets the budget to observe success-by-
     * other-path before surrendering.
     *
     * @param rungScope The rung's cancellation scope (consumed by
     *        [withTimeoutOrNull] cooperatively via the suspending Flow ops).
     */
    private suspend fun rung2Action(
        @Suppress("UNUSED_PARAMETER") rungScope: kotlinx.coroutines.CoroutineScope,
    ): Boolean {
        try {
            signalingClient.disconnect()
            signalingClient.connect()
        } catch (e: Exception) {
            Log.d(TAG, "rung2Action: disconnect/connect cycle failed", e)
        }

        return withTimeoutOrNull(RUNG_2_BUDGET_MS) {
            combine(_selfState, _peerHealth) { s, m ->
                s === SelfState.Online && m.values.any { it === PeerHealth.Healthy }
            }.first { it }
            true
        } ?: false
    }

    /**
     * Rung 3 — full session reset.
     *
     * Action: invoke the wired [forceFullReset] hook (which on Android stops
     * the foreground service via Intent, awaits its `onDestroy`, clears v2
     * transport in-memory state, and restarts the service via Intent).
     * Success indicator: [selfState] is [SelfState.Online] AND
     * [serviceLifecycle] reports [ServiceState.Running] within
     * [RUNG_3_BUDGET_MS].
     *
     * **Skeleton-mode** (`forceFullReset == null`): the rung surrenders
     * synchronously. There is nothing to reset and the ladder advances to
     * Rung 4. Mirrors Chrome's "no `forceFullReset` => return false" path.
     *
     * **Cancellation discipline.** The success-criterion await wraps the
     * Flow.first in an explicit [coroutineScope] so external cancellation
     * (via [RecoveryLadder.cancel] propagating into [rungScope], or via
     * [shutdown] cancelling [scope]) tears down the inner Flow collector
     * cleanly — the alternative pattern (raw `withTimeoutOrNull { ...first { it } }`
     * without the inner [coroutineScope]) was the source of the prior
     * attempt's `runTest` teardown hang, where a cancelled-but-not-drained
     * collector kept an armed virtual-time `delay` alive.
     *
     * The pre-suspend `rungScope.isActive` short-circuit avoids invoking
     * the reset hook at all if cancellation has already landed (e.g.
     * `requestReconnect` fired between the rung-2-timeout and rung-3-start
     * tick).
     *
     * @param rungScope The rung's cancellation scope (cooperatively
     *        observed via the inner [coroutineScope] + `isActive` check).
     */
    private suspend fun rung3Action(
        rungScope: kotlinx.coroutines.CoroutineScope,
    ): Boolean {
        // Pre-suspend cancellation check: if the rung's scope is already
        // cancelled (cancel raced our schedule), surrender without
        // tearing down the FG service. Mirrors Chrome's
        // `if (signal.aborted) return false`.
        if (!rungScope.isActive) return false

        val reset = forceFullReset
        if (reset == null) {
            // Skeleton-mode: no reset hook wired. Surrender synchronously
            // so the ladder advances to Rung 4 (or exhausts in Task-20-
            // step-D-isolation, where Rung 4 isn't wired yet).
            //
            // Logged at WARN so a beta APK shipped without the Step-G Hilt
            // wiring (`setForceFullReset` never called) surfaces a
            // detectable signal — without this log a "Reconnect" tap that
            // surrenders within seconds with no actual reset attempt
            // looks identical at the UI level to a stuck relay.
            Log.w(
                TAG,
                "rung3Action: forceFullReset hook not wired — surrendering. " +
                    "This is expected in unit tests but indicates a missing " +
                    "production wiring step in real builds.",
            )
            return false
        }

        // Invoke the reset hook. A throw is swallowed (Chrome parity:
        // `forceFullReset` swallows restart errors internally, and we do
        // belt-and-braces here in case a test injects a throwing reset).
        // The success-criterion wait still gets the budget to observe
        // success-by-other-path before surrendering.
        try {
            reset()
        } catch (ce: CancellationException) {
            // Structured-concurrency cancel must propagate so the caller's
            // scope tears down cleanly. Catching CE as a domain outcome
            // would mask parent-cancellation as Rung-3-failure.
            throw ce
        } catch (e: Exception) {
            Log.d(TAG, "rung3Action: forceFullReset() threw", e)
        }

        // Post-resume cancellation check: a cancel could have landed while
        // the reset hook was suspending. Surrender immediately rather than
        // arming a doomed Flow collector.
        if (!rungScope.isActive) return false

        // Wait for (selfState=Online AND serviceLifecycle=Running) within
        // budget. Wrap the Flow.first in an inner `coroutineScope` so that
        // when the outer `withTimeoutOrNull` cancels (timeout or external),
        // the inner scope cancels structurally and tears down the combine
        // collector — not relying on the timeout's implicit cancellation,
        // which the prior attempt found could leak under runTest teardown.
        return withTimeoutOrNull(RUNG_3_BUDGET_MS) {
            coroutineScope {
                combine(_selfState, serviceLifecycle.state) { self, svc ->
                    self === SelfState.Online && svc === ServiceState.Running
                }.first { it }
                true
            }
        } ?: false
    }

    /**
     * Common settlement handler. Called from [kickLadder]'s `scope.launch`
     * once the ladder resolves.
     *
     * Mirrors `_handleLadderSettled` in
     * `extension/connection/connection-authority.js` (commit `dd87ae2`),
     * **minus the Rung 4 surrender path**: Task 17 does not yet dispatch
     * [SelfStateEvent.RecoveryGivenUp] on exhaustion. The reducer already
     * supports it but no caller fires it until the surrender follow-up
     * task lands. On exhaustion we just clear [currentLadder] — selfState
     * stays [SelfState.Reconnecting]`(false)`.
     *
     * @param result The ladder's outcome.
     * @param triggerPeerId The peer that triggered the kick (for lifting
     *        FAILED → UNKNOWN on success), or `null` if self-triggered.
     */
    private fun handleLadderSettled(
        result: LadderResult,
        triggerPeerId: String?,
        wasSurrenderLadder: Boolean,
    ) {
        if (shuttingDown) return
        when (result) {
            is LadderResult.Success -> {
                // Spec §"Discipline rules": "A rung that succeeds resets the
                // ladder to idle." Reset the thrash counter, the backoff
                // attempt counter, and the surrender flag.
                rung3FailureLog.clear()
                backoffAttempt = 0
                if (surrenderedToUser) surrenderedToUser = false
                cancelBackoffJob()
                // Lift selfState (RECONNECTING -> ONLINE) and the trigger
                // peer (FAILED -> UNKNOWN). The reducers are no-ops if we
                // are already there. dispatchSelf re-enters via the post-
                // hook only on RECONNECTING transitions — RecoverySucceeded
                // moves us OUT of RECONNECTING, so no re-entry.
                dispatchSelf(SelfStateEvent.RecoverySucceeded)
                if (triggerPeerId != null) {
                    dispatchPeer(triggerPeerId, PeerHealthEvent.RecoverySucceeded)
                }
            }
            is LadderResult.Cancelled -> {
                // Cancelled by `requestReconnect` mid-ladder or by
                // [shutdown]. The canceller already owns the recovery state
                // machine from here — do NOT promote to Rung 4 on cancel.
            }
            is LadderResult.Exhausted -> {
                if (wasSurrenderLadder) {
                    // The surrender ladder fired because the thrash guard
                    // was already active. The surrender flag is already
                    // set (was set when the previous ladder exhausted),
                    // and the backoff timer is already armed. Re-running
                    // promoteToRung4 here would re-arm the timer in an
                    // infinite loop (the thrash log doesn't drain in
                    // virtual time because it uses wall-clock `now()`),
                    // so simply stay surrendered until manual reconnect
                    // OR the wall-clock thrash window prunes the log.
                    Log.i(TAG, "[CA] ladder: surrender ladder exhausted, no further retry until requestReconnect")
                    if (!surrenderedToUser) surrenderedToUser = true
                    return
                }
                // Non-surrender ladder reached Rung 3 and Rung 3 did not
                // lift selfState within budget. Record toward the thrash
                // counter and promote to Rung 4.
                recordRung3Failure()
                promoteToRung4()
            }
        }
    }

    // ── Task 20 — Rung 4 surrender / backoff / thrash guard helpers ───────

    /**
     * Build a one-rung "surrender" ladder used when the thrash guard fires.
     * The single rung returns false synchronously, sending us straight
     * through [handleLadderSettled]'s Exhausted path -> [promoteToRung4].
     *
     * Mirrors Chrome's `_buildSurrenderLadder`. Tagged via
     * [currentLadderIsSurrender] (set in [kickLadder]) so the settle
     * handler doesn't double-count it toward [rung3FailureLog].
     */
    private fun buildSurrenderLadder(): RecoveryLadder = RecoveryLadder(
        rungs = listOf(
            RecoveryRung(
                name = "thrash-surrender",
                budgetMs = 0L,
                action = { false },
            ),
        ),
    )

    /**
     * Returns `true` iff the next ladder kick should pre-empt the 3-rung
     * sequence and go straight to surrender. Prunes entries older than
     * [RUNG_3_THRASH_WINDOW_MS] as a side effect.
     *
     * MUST be called on [scope]. Mirrors Chrome's `_thrashGuardActive`.
     */
    private fun thrashGuardActive(): Boolean {
        if (rung3FailureLog.isEmpty()) return false
        val cutoff = now() - RUNG_3_THRASH_WINDOW_MS
        rung3FailureLog.removeAll { it < cutoff }
        return rung3FailureLog.size >= RUNG_3_THRASH_THRESHOLD
    }

    /**
     * Append the current timestamp to [rung3FailureLog]. Called from
     * [handleLadderSettled]'s Exhausted branch when the ladder reached
     * Rung 3 and Rung 3 did not lift selfState to ONLINE within budget.
     *
     * MUST be called on [scope]. Mirrors Chrome's `_recordRung3Failure`.
     */
    private fun recordRung3Failure() {
        rung3FailureLog.add(now())
        Log.i(TAG, "[CA] ladder: rung3 failure recorded (count=${rung3FailureLog.size})")
    }

    /**
     * Rung 4: surrender to the user and schedule the next auto-retry.
     *
     * Per spec §"Rung 4 — Surface to user":
     *   - `selfState` stays in RECONNECTING (the reducer's
     *     [SelfStateEvent.RecoveryGivenUp] handler is a no-op outside
     *     RECONNECTING, so we make sure we're at least in RECONNECTING
     *     first via [SelfStateEvent.RecoveryBegan]).
     *   - The [surrenderedToUser] flag flips to `true` so the popup banner
     *     switches to the red "Connection failed — tap to reconnect" UI.
     *   - [SelfStateEvent.RecoveryGivenUp] is dispatched into the reducer
     *     for any state observers that want to react.
     *   - An exponential-backoff timer is armed for the next auto-attempt.
     *
     * MUST be called on [scope]. Mirrors Chrome's `_promoteToRung4`.
     */
    private fun promoteToRung4() {
        if (shuttingDown) return
        // Make sure we're at least in RECONNECTING so the popup banner
        // stays up. (We could also be in OFFLINE, e.g. if a Stop event
        // raced — in which case the user is no longer paired and the
        // surrender flag is moot. The reducer ignores the dispatch in
        // that case.)
        dispatchSelf(SelfStateEvent.RecoveryBegan)
        dispatchSelf(SelfStateEvent.RecoveryGivenUp)
        if (!surrenderedToUser) surrenderedToUser = true
        Log.i(TAG, "[CA] ladder: surrendered to user (Rung 4)")
        scheduleBackoffRetry()
    }

    /**
     * Arm the next auto-retry timer per [BACKOFF_SCHEDULE_MS]. The
     * [backoffAttempt] index advances after each scheduling so the next
     * retry uses a longer delay (capped at the last entry in the schedule).
     *
     * If a backoff Job is already armed, this is a no-op (idempotent —
     * a second [promoteToRung4] while we're waiting must not stack timers).
     *
     * MUST be called on [scope]. Mirrors Chrome's `_scheduleBackoffRetry`.
     *
     * **Cancellation discipline.** The launched Job participates in
     * [scope]'s structured concurrency, so [scope.cancel] cancels it
     * AS LONG AS [shutdown] cancels [backoffJob] explicitly first AND
     * nulls the field. Without that explicit pre-cancel, `runTest`'s
     * teardown advanceUntilIdle finds the still-armed `delay` and
     * advances time to it, [fireBackoffRetry] runs on a (just-cancelled)
     * scope, and the test JVM hangs on never-draining work.
     */
    private fun scheduleBackoffRetry() {
        if (shuttingDown) return
        if (backoffJob != null) return // already armed
        val idx = minOf(backoffAttempt, BACKOFF_SCHEDULE_MS.size - 1)
        val delayMs = BACKOFF_SCHEDULE_MS[idx]
        backoffAttempt += 1
        Log.i(
            TAG,
            "[CA] ladder: backoff retry scheduled in ${delayMs}ms (attempt #${idx + 1})",
        )
        backoffJob = scope.launch {
            try {
                delay(delayMs)
            } catch (ce: CancellationException) {
                // Structured cancel — no work to do; let the cancel
                // propagate naturally (don't even try to clear the field
                // here, [shutdown] / [requestReconnect] / [cancelBackoffJob]
                // handle that ordering).
                throw ce
            }
            // Clear the field BEFORE firing so an immediate re-arm inside
            // fireBackoffRetry (e.g. another exhausted ladder) sees a
            // null slot to use.
            backoffJob = null
            fireBackoffRetry()
        }
    }

    /**
     * Cancel any pending Rung-4 auto-retry [Job]. Called by
     * [requestReconnect] (manual tap bypasses backoff), the success branch
     * of [handleLadderSettled], and [shutdown].
     *
     * **CRITICAL ordering.** Callers in [shutdown] MUST call this BEFORE
     * `scope.cancel()`. The field is nulled here so a post-cancel
     * advanceUntilIdle does not see an armed delay.
     *
     * MUST be called on [scope] OR from [shutdown]. The field write is
     * a single reference assignment; the [Volatile]-equivalent
     * single-thread confinement of [scope] makes the read-then-cancel
     * race-free for the on-scope path. The [shutdown] path runs on the
     * caller's thread and races with any in-flight scheduleBackoffRetry —
     * the worst case is a benign double-cancel (idempotent on Jobs).
     */
    private fun cancelBackoffJob() {
        backoffJob?.cancel()
        backoffJob = null
    }

    /**
     * Backoff-timer callback: the auto-retry interval has elapsed. Drop
     * the surrender flag (we're trying again) and kick a fresh full
     * ladder. Note we kick a FULL ladder (Rungs 1+2+3), not just Rung 3 —
     * the thrash counter is still in scope and will short-circuit to
     * Rung 4 again if Rungs 1+2 don't quietly recover us.
     *
     * MUST be called on [scope]. Mirrors Chrome's `_fireBackoffRetry`.
     */
    private fun fireBackoffRetry() {
        if (shuttingDown) return
        if (currentLadder != null) return // a manual reconnect raced us
        // Drop the surrender flag — we're actively trying again. The
        // popup banner switches back to the yellow "Reconnecting…" UI.
        if (surrenderedToUser) surrenderedToUser = false
        kickLadder(triggerPeerId = null, reason = "backoff-retry")
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
        // Defend against a `delay(BG_PING_INTERVAL_MS)` that resumes during
        // shutdown — without this, a pingJob could fire one wire frame after
        // shutdown intent (cooperative cancellation handles the suspended
        // resumption cleanly, but `tracker.sendPing` is non-suspending so
        // the actual send call would still go out).
        if (shuttingDown) return
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
     *
     * Post-dispatch hook (Task 17): if the transition crossed any non-
     * Reconnecting state into [SelfState.Reconnecting], kick the recovery
     * ladder with `triggerPeerId = null`. Mirrors the `_dispatchSelf` post-
     * hook in `extension/connection/connection-authority.js` (commit
     * `dd87ae2`). The single-flight guard inside [kickLadder] absorbs the
     * re-entry that occurs when the ladder's own [SelfStateEvent.RecoveryBegan]
     * dispatch lands here a moment later.
     */
    private fun dispatchSelf(event: SelfStateEvent) {
        val current = _selfState.value
        val next = SelfState.reduce(current, event)
        if (next === current) return
        _selfState.value = next
        if (current !is SelfState.Reconnecting && next is SelfState.Reconnecting) {
            kickLadder(triggerPeerId = null, reason = "self-reconnecting")
        }
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
     *
     * Post-dispatch hook (Task 17): if the transition crossed a non-
     * [PeerHealth.Failed] state into [PeerHealth.Failed], kick the recovery
     * ladder with `triggerPeerId = peerId`. Mirrors the `_dispatchPeer`
     * post-hook in `extension/connection/connection-authority.js` (commit
     * `dd87ae2`). Concurrent peers FAILED in the same tick share the in-
     * flight ladder via [kickLadder]'s single-flight guard.
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
        if (before !== PeerHealth.Failed && next === PeerHealth.Failed) {
            kickLadder(triggerPeerId = peerId, reason = "peer-failed")
        }
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
