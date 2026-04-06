package com.zaptransfer.android.webrtc

import android.util.Log
import com.zaptransfer.android.service.NetworkMonitor
import com.zaptransfer.android.service.NetworkState
import com.zaptransfer.android.service.Transport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import javax.inject.Inject

private const val TAG = "IceRestartPolicy"

/**
 * Maximum number of ICE restart attempts for a single peer before giving up and
 * staying on the WebSocket relay permanently for that session.
 */
private const val MAX_RESTART_ATTEMPTS = 3

/**
 * Base delay in milliseconds for the exponential backoff between restart attempts.
 * Delays: 1 s → 2 s → 4 s (capped at 3 attempts).
 */
private const val BASE_BACKOFF_MS = 1_000L

/**
 * Observes [NetworkMonitor.state] and triggers ICE restarts or P2P upgrade attempts
 * in [PeerConnectionManager] when the network transport changes.
 *
 * ## Behaviour on transport change
 *
 *  **Wi-Fi → Cellular**:
 *   - The P2P path (LAN/STUN) may no longer be optimal.
 *   - Triggers [PeerConnectionManager.restartIce] to renegotiate ICE candidates using
 *     the new cellular interface, with up to [MAX_RESTART_ATTEMPTS] retries and
 *     exponential backoff.
 *   - During the restart: traffic bridges through the WebSocket relay so no data is lost.
 *
 *  **Cellular → Wi-Fi**:
 *   - A faster P2P path may now be available.
 *   - Attempts a P2P upgrade by triggering an ICE restart with fresh STUN candidates.
 *   - On success, the data channel takes over from the relay (path upgrade).
 *
 *  **→ Disconnected**:
 *   - No action; [PeerConnectionManager] will retry when connectivity resumes.
 *
 * ## Thread safety
 *  - All mutations run on [scope] (IO dispatcher).
 *  - The [observations] job is cancelled when [stop] is called.
 *
 * @param networkMonitor       Observes system network changes.
 * @param peerConnectionManager  Manages WebRTC [PeerConnection]s; exposes [restartIce].
 */
class IceRestartPolicy @Inject constructor(
    private val networkMonitor: NetworkMonitor,
    private val peerConnectionManager: PeerConnectionManager,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Job driving the network observation loop; cancelled by [stop]. */
    private var observations: Job? = null

    /** Map of peerId → number of ICE restart attempts since the last successful connection. */
    private val restartAttempts = mutableMapOf<String, Int>()

    /**
     * Starts observing network transitions for the given peer.
     *
     * Calling [start] while already observing is a no-op — the existing observation
     * job continues. Call [stop] first to restart with a different [peerId].
     *
     * @param peerId The relay device ID of the remote peer whose connection should be monitored.
     */
    fun start(peerId: String) {
        if (observations?.isActive == true) {
            Log.d(TAG, "Already observing for peer $peerId")
            return
        }
        restartAttempts[peerId] = 0

        observations = scope.launch {
            var previousTransport: Transport? = null

            networkMonitor.state
                .distinctUntilChanged()
                .collect { state ->
                    when (state) {
                        is NetworkState.Connected -> {
                            val current = state.transport
                            val previous = previousTransport

                            if (previous != null && previous != current) {
                                handleTransportChange(peerId, from = previous, to = current)
                            }
                            previousTransport = current
                        }
                        NetworkState.Disconnected -> {
                            Log.d(TAG, "Network disconnected — waiting for recovery")
                            // Do not clear previousTransport so we can still react to the next
                            // connected event as a transition from the last known transport.
                        }
                    }
                }
        }
        Log.d(TAG, "IceRestartPolicy started for peer $peerId")
    }

    /**
     * Stops observing network transitions and resets all retry counters.
     *
     * Call this when the associated peer disconnects or when the transfer session ends.
     */
    fun stop() {
        observations?.cancel()
        observations = null
        restartAttempts.clear()
        Log.d(TAG, "IceRestartPolicy stopped")
    }

    /**
     * Releases the coroutine scope. Must be called when the owning component (service) is
     * destroyed. After [close], this object must not be used.
     */
    fun close() {
        stop()
        scope.cancel()
    }

    // ── Transport change handling ─────────────────────────────────────────────

    /**
     * Dispatches the appropriate action when the transport changes.
     *
     * @param peerId  Remote peer ID.
     * @param from    Previous [Transport].
     * @param to      New [Transport].
     */
    private suspend fun handleTransportChange(peerId: String, from: Transport, to: Transport) {
        Log.i(TAG, "Transport changed: $from → $to (peer=$peerId)")

        when {
            // Wi-Fi lost → cellular: renegotiate ICE on the cellular interface
            from == Transport.WIFI && to == Transport.CELLULAR -> {
                Log.i(TAG, "Wi-Fi → Cellular: triggering ICE restart for peer $peerId")
                attemptIceRestartWithBackoff(peerId)
            }

            // Cellular → Wi-Fi: attempt P2P upgrade via ICE restart
            from == Transport.CELLULAR && to == Transport.WIFI -> {
                Log.i(TAG, "Cellular → Wi-Fi: attempting P2P upgrade for peer $peerId")
                // Reset attempt counter — a new Wi-Fi network gives fresh STUN candidates
                restartAttempts[peerId] = 0
                attemptIceRestartWithBackoff(peerId)
            }

            // Ethernet changes treated the same as Wi-Fi for upgrade attempts
            to == Transport.ETHERNET -> {
                Log.i(TAG, "→ Ethernet: attempting P2P upgrade for peer $peerId")
                restartAttempts[peerId] = 0
                attemptIceRestartWithBackoff(peerId)
            }

            else -> Log.d(TAG, "Transport change $from → $to: no special action")
        }
    }

    /**
     * Attempts an ICE restart for [peerId] with exponential backoff, up to [MAX_RESTART_ATTEMPTS].
     *
     * During each retry interval, the transfer continues bridged through the WebSocket relay
     * (transparent to the [TransferEngine]) so no data is lost while ICE renegotiates.
     *
     * @param peerId Remote peer ID.
     */
    private suspend fun attemptIceRestartWithBackoff(peerId: String) {
        val attempts = restartAttempts[peerId] ?: 0

        if (attempts >= MAX_RESTART_ATTEMPTS) {
            Log.w(
                TAG,
                "Max ICE restart attempts ($MAX_RESTART_ATTEMPTS) reached for peer $peerId — " +
                    "staying on relay"
            )
            return
        }

        // Exponential backoff: 0 ms, 1 s, 2 s (for attempts 0, 1, 2)
        val backoffMs = if (attempts > 0) BASE_BACKOFF_MS * (1L shl (attempts - 1)) else 0L
        if (backoffMs > 0) {
            Log.d(TAG, "ICE restart backoff: ${backoffMs}ms (attempt ${attempts + 1}/$MAX_RESTART_ATTEMPTS)")
            delay(backoffMs)
        }

        restartAttempts[peerId] = attempts + 1

        if (!peerConnectionManager.isConnected(peerId)) {
            Log.d(TAG, "Peer $peerId not connected — skipping ICE restart")
            return
        }

        Log.i(TAG, "Triggering ICE restart for peer $peerId (attempt ${attempts + 1}/$MAX_RESTART_ATTEMPTS)")
        peerConnectionManager.restartIce(peerId)
    }
}
