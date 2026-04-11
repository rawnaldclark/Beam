package com.zaptransfer.android.webrtc

import android.util.Base64
import android.util.Log
import com.zaptransfer.android.crypto.KeyManager
import dagger.hilt.android.scopes.ServiceScoped
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "SignalingClient"

/** Exponential backoff delay sequence per spec §6.8 (ms): 0, 500, 1000, 2000, 4000, 8000, 16000, 30000. */
private val BACKOFF_MS = longArrayOf(0, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000)

/**
 * Retry delay (ms) used for transient network-layer failures that should
 * NOT advance the exponential backoff counter — e.g. DNS unavailable right
 * after an Android background/foreground transition, connection aborts
 * from the OS network stack during a wifi handoff.
 *
 * 500 ms is long enough to let the OS network stack settle but short
 * enough that a recovering device reconnects in under two seconds in
 * the common case.
 */
private const val TRANSIENT_RETRY_DELAY_MS = 500L

/** Interval between heartbeat pings per spec §6.7. */
private const val HEARTBEAT_INTERVAL_MS = 30_000L

/** Relay server URL — matches spec §6.9. */
const val RELAY_URL = "wss://zaptransfer-relay.fly.dev"

// ── Connection state ──────────────────────────────────────────────────────────

/**
 * Represents the lifecycle state of the WebSocket connection to the relay.
 *
 * State transitions:
 *  Disconnected → Connecting → Authenticating → Connected
 *                                              ↘ Error → Connecting (backoff)
 *  Connected → Disconnected → Connecting (backoff)
 */
sealed class ConnectionState {
    /** No active or pending connection. Initial state and state after explicit [SignalingClient.disconnect]. */
    object Disconnected : ConnectionState()

    /** TCP/TLS handshake in progress. The [attempt] counter drives UI feedback. */
    data class Connecting(val attempt: Int) : ConnectionState()

    /** Connected at the socket level; Ed25519 challenge-response underway. */
    object Authenticating : ConnectionState()

    /** Fully authenticated and registered with the relay. Messages may be sent and received. */
    object Connected : ConnectionState()

    /**
     * Terminal error for the current attempt.
     * [message] is suitable for logging; do not display raw error messages to users.
     * The client will transition back to [Connecting] after the backoff delay.
     */
    data class Error(val message: String) : ConnectionState()
}

// ── Incoming message wrapper ──────────────────────────────────────────────────

/**
 * Discriminated union of relay messages delivered to registered listeners.
 *
 * New message types can be added here as the protocol evolves without breaking
 * existing consumers that pattern-match on the sealed class.
 */
sealed class RelayMessage {
    /** A JSON text message from the relay or a remote peer. */
    data class Text(val json: JSONObject) : RelayMessage()

    /**
     * A raw binary frame — typically an encrypted chunk payload or a data relay
     * frame (see wire format §4.9).
     */
    data class Binary(val data: ByteArray) : RelayMessage()
}

// ── Listener interface ────────────────────────────────────────────────────────

/**
 * Callback interface for relay message delivery.
 *
 * Implementations must be thread-safe — callbacks are invoked on OkHttp's
 * WebSocket reader thread, not the main thread.
 */
interface SignalingListener {
    /** Invoked for every decoded JSON text frame received from the relay. */
    fun onMessage(message: RelayMessage)
}

// ── SignalingClient ───────────────────────────────────────────────────────────

/**
 * Manages the authenticated WebSocket connection to the ZapTransfer relay server.
 *
 * Responsibilities:
 *  1. Establish and maintain a WSS connection to [RELAY_URL].
 *  2. Complete the Ed25519 auth handshake (spec §6.5): sign `challenge || timestamp`
 *     and send `{type:"auth", deviceId, publicKey, signature, timestamp}`.
 *  3. Expose [connectionState] as a hot [StateFlow] for UI and service consumers.
 *  4. Reconnect automatically with exponential backoff on any disconnect or error.
 *  5. Send heartbeat pings every 30 seconds to satisfy spec §6.7.
 *  6. Route incoming JSON and binary frames to registered [SignalingListener] instances.
 *
 * Lifecycle:
 *  - Call [connect] to begin. Reconnects are automatic.
 *  - Call [disconnect] to cleanly close (no reconnect after an explicit disconnect).
 *  - Call [close] to release the coroutine scope and OkHttp resources.
 *
 * Thread safety: [send] and [sendBinary] are safe to call from any thread.
 * The underlying [WebSocket] implementation in OkHttp is thread-safe.
 *
 * @param keyManager Provides device Ed25519 keys for auth challenge signing.
 */
@Singleton
class SignalingClient @Inject constructor(
    private val keyManager: KeyManager,
) {

    // ── Internal state ────────────────────────────────────────────────────────

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * OkHttpClient configured with generous timeouts for a persistent WebSocket.
     *
     * `pingInterval` is CRITICAL for half-open detection. Without it, a phone
     * that backgrounds, roams, or sleeps leaves the TCP connection in a state
     * where `send()` silently buffers, no callbacks fire, and the app believes
     * the WebSocket is healthy indefinitely. OkHttp's pingInterval sends a
     * native WebSocket PING frame at the given cadence and fires
     * `WebSocketListener.onFailure` if no PONG arrives within the interval,
     * which drives our reconnect loop.
     *
     * 25s is short enough to detect a dead socket well within the server's
     * 90s silence timeout, and short enough that a user reopening the app
     * after 20s of background gets an immediate half-open detection.
     */
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)       // disable read timeout — WS is long-lived
        .writeTimeout(15, TimeUnit.SECONDS)
        .pingInterval(25, TimeUnit.SECONDS)     // native WS ping/pong keepalive
        .build()

    /** Current live WebSocket handle; null when disconnected or connecting. */
    @Volatile
    private var webSocket: WebSocket? = null

    /**
     * Set by `onFailure` when the last failure was a transient network
     * layer error (DNS unavailable, connection aborted, etc.) rather than
     * a protocol / server issue. The reconnect loop uses this to decide
     * whether to advance the exponential backoff counter — transient
     * network failures immediately after an app backgrounding / foreground
     * transition can burst for several seconds while the OS network stack
     * re-initializes, and exponentially backing off in that window pushes
     * the recovery window out to 15+ seconds.
     */
    @Volatile
    private var lastFailureWasTransient: Boolean = false

    /**
     * Rendezvous IDs most recently provided via [registerRendezvous]. The
     * SignalingClient re-sends a `register-rendezvous` message automatically
     * after every successful auth so the relay always has fresh membership
     * info after reconnects — without requiring the caller (ViewModel) to
     * observe every connectionState transition.
     *
     * This is THE CRITICAL FIX for presence flakiness on cold reopen: the
     * `attemptConnect` loop may reconnect many times within a single
     * singleton lifetime (process cached, VM destroyed and recreated, etc.),
     * and without auto-re-registering we'd be authenticated but invisible
     * to any rendezvous.
     */
    @Volatile
    private var pendingRendezvousIds: List<String>? = null

    /**
     * Reference to the currently-running attemptConnect coroutine, if any.
     * Used to make `connect()` re-entrant: a second `connect()` call while
     * a loop is already active does not spawn a duplicate loop, but does
     * force the current socket to close so the loop cycles and acquires
     * a fresh connection. This is how cold-reopen-from-cached-process is
     * handled — a stale ConnectionState.Connected value is refreshed.
     */
    private var attemptConnectJob: kotlinx.coroutines.Job? = null

    /** Controls whether the reconnect loop should continue. False after [disconnect]. */
    @Volatile
    private var intentionalDisconnect = false

    /** Reconnection attempt index — indexes into [BACKOFF_MS]. */
    private val reconnectAttempt = AtomicInteger(0)

    /** Job reference for the in-flight heartbeat coroutine. */
    private var heartbeatJob: Job? = null

    /** Registered message listeners — notified on every incoming frame. */
    private val listeners = mutableListOf<SignalingListener>()

    // ── Public API ────────────────────────────────────────────────────────────

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)

    /**
     * Hot flow of the current relay connection state.
     * Collectors are notified on every state transition; no initial emission is
     * skipped — the default [ConnectionState.Disconnected] is always the first value.
     */
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    /**
     * Registers a [SignalingListener] that will receive decoded relay messages.
     * Adding the same listener twice has no effect (guarded by [contains] check).
     *
     * @param listener The listener to register. Must be thread-safe.
     */
    fun addListener(listener: SignalingListener) {
        synchronized(listeners) {
            if (!listeners.contains(listener)) listeners.add(listener)
        }
    }

    /**
     * Removes a previously registered [SignalingListener].
     *
     * @param listener The listener to remove.
     */
    fun removeListener(listener: SignalingListener) {
        synchronized(listeners) { listeners.remove(listener) }
    }

    /**
     * Initiates the connection (or reconnection) loop.
     *
     * Safe to call multiple times — if already [ConnectionState.Connected] or
     * [ConnectionState.Connecting] this is a no-op.
     *
     * @param relayUrl Override URL for testing; defaults to the production [RELAY_URL].
     */
    fun connect(relayUrl: String = RELAY_URL) {
        intentionalDisconnect = false

        // Cancel any existing attempt loop and its in-flight socket. This is
        // the CRITICAL path for cold-reopen-from-cached-process and for
        // app-foreground after a network transition: the previous loop may
        // be asleep inside `delay(backoffMs)` for up to 30 seconds (far
        // worse than the user's patience), and `cancel()` on the coroutine
        // unblocks any pending suspend function including `delay()`.
        //
        // We also cancel the WebSocket itself (OkHttp `cancel`, NOT `close`)
        // to force `onFailure` immediately — `close()` sends a graceful
        // close frame that waits for the peer's close ack, which on a
        // half-open socket never arrives.
        attemptConnectJob?.cancel()
        webSocket?.cancel()

        // Reset the backoff counter so the new attempt fires immediately.
        reconnectAttempt.set(0)

        // Launch a fresh loop. The previous job's cancellation will
        // unwind at its next suspension point; the new loop runs
        // independently and will establish a new connection.
        attemptConnectJob = scope.launch { attemptConnect(relayUrl) }
    }

    /**
     * Closes the active WebSocket and prevents automatic reconnection.
     *
     * Calling [connect] after [disconnect] resumes normal operation.
     */
    fun disconnect() {
        intentionalDisconnect = true
        heartbeatJob?.cancel()
        webSocket?.close(1000, "client_disconnect")
        webSocket = null
        _connectionState.value = ConnectionState.Disconnected
    }

    /**
     * Sends a JSON object as a UTF-8 text frame.
     *
     * Silently dropped if the socket is not in [ConnectionState.Connected] state.
     *
     * @param msg JSON payload; must be a valid JSON object.
     * @return true if the message was enqueued; false if the socket is unavailable.
     */
    fun send(msg: JSONObject): Boolean {
        return webSocket?.send(msg.toString()) ?: false
    }

    /**
     * Sends raw bytes as a WebSocket binary frame.
     *
     * Used for encrypted chunk relay — the relay server passes binary frames
     * through opaquely without inspecting the payload (spec §4.8).
     *
     * @param data Raw binary payload.
     * @return true if the message was enqueued; false if the socket is unavailable.
     */
    fun sendBinary(data: ByteArray): Boolean {
        return webSocket?.send(data.toByteString()) ?: false
    }

    /**
     * Registers rendezvous IDs with the relay so it can route messages between
     * paired devices sharing those IDs.
     *
     * @param rendezvousIds List of rendezvous ID strings to register.
     * @return true if the message was enqueued; false if the socket is unavailable.
     */
    fun registerRendezvous(rendezvousIds: List<String>): Boolean {
        // Remember these for automatic replay on future reconnects.
        pendingRendezvousIds = rendezvousIds.toList()
        return sendRegisterRendezvousNow(rendezvousIds)
    }

    /**
     * Internal: emit a `register-rendezvous` message immediately using the
     * given IDs. Used both from the public [registerRendezvous] entry point
     * and from the auth-success path so a reconnect automatically replays
     * the most recent registration.
     */
    private fun sendRegisterRendezvousNow(rendezvousIds: List<String>): Boolean {
        val msg = JSONObject().apply {
            put("type", "register-rendezvous")
            put("rendezvousIds", org.json.JSONArray(rendezvousIds))
        }
        return send(msg)
    }

    /**
     * Cancels all coroutines and closes the OkHttp connection pool.
     * Must be called when the owning component (service / ViewModel) is destroyed.
     */
    fun close() {
        disconnect()
        scope.cancel()
        httpClient.connectionPool.evictAll()
        httpClient.dispatcher.executorService.shutdown()
    }

    // ── Connection loop ───────────────────────────────────────────────────────

    /**
     * Core reconnect loop: opens a new WebSocket, waits for the auth handshake
     * to complete, then blocks until the socket closes. On any failure, waits
     * the appropriate backoff delay and loops.
     *
     * @param relayUrl WSS URL of the relay server.
     */
    private suspend fun attemptConnect(relayUrl: String) {
        while (scope.isActive && !intentionalDisconnect) {
            val attempt = reconnectAttempt.get()
            val backoff = if (attempt < BACKOFF_MS.size) BACKOFF_MS[attempt] else BACKOFF_MS.last()

            if (backoff > 0) {
                Log.d(TAG, "Reconnect backoff ${backoff}ms (attempt $attempt)")
                delay(backoff)
            }

            if (intentionalDisconnect) break

            _connectionState.value = ConnectionState.Connecting(attempt)
            Log.d(TAG, "Connecting to $relayUrl (attempt $attempt)")

            // Reset the transient flag before each attempt so onFailure can
            // freshly classify this iteration's failure (if any).
            lastFailureWasTransient = false

            val request = Request.Builder().url(relayUrl).build()
            val listener = ZapWebSocketListener()

            webSocket = httpClient.newWebSocket(request, listener)

            // Wait until this connection terminates (closed or errored)
            listener.awaitClose()

            if (intentionalDisconnect) break

            // Decide how to advance. Transient network-layer failures
            // (DNS unavailable, connection aborted by OS) keep the attempt
            // counter pinned near zero and use a short fixed retry delay,
            // so a burst of background/foreground DNS failures doesn't
            // push us into 8+ second exponential waits.
            if (lastFailureWasTransient) {
                Log.d(TAG, "Transient failure — fast retry without advancing backoff")
                delay(TRANSIENT_RETRY_DELAY_MS)
            } else {
                reconnectAttempt.compareAndSet(attempt, minOf(attempt + 1, BACKOFF_MS.size - 1))
            }
        }
    }

    // ── Heartbeat ─────────────────────────────────────────────────────────────

    /**
     * Starts a coroutine that sends a ping JSON frame every [HEARTBEAT_INTERVAL_MS].
     * The server interprets absence of pings for >90 seconds as the device going offline
     * (spec §6.7).
     *
     * The previous heartbeat job (if any) is cancelled before starting a new one.
     */
    private fun startHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = scope.launch {
            while (isActive) {
                delay(HEARTBEAT_INTERVAL_MS)
                if (_connectionState.value is ConnectionState.Connected) {
                    val ping = JSONObject().apply { put("type", "ping") }
                    send(ping)
                    Log.v(TAG, "Heartbeat ping sent")
                }
            }
        }
    }

    // ── WebSocket listener ────────────────────────────────────────────────────

    /**
     * OkHttp [WebSocketListener] that handles the relay auth handshake and
     * dispatches messages to registered [SignalingListener]s.
     *
     * The [awaitClose] function allows the outer coroutine loop to suspend until
     * this connection's lifecycle ends.
     */
    private inner class ZapWebSocketListener : WebSocketListener() {

        /** Completion signal used to block [attemptConnect] while the socket is alive. */
        private val closeChannel = kotlinx.coroutines.channels.Channel<Unit>(1)

        /** Suspends the caller until this WebSocket closes (success or error). */
        suspend fun awaitClose() {
            closeChannel.receive()
        }

        // Called when the TCP+TLS handshake succeeds and the HTTP 101 is received
        override fun onOpen(webSocket: WebSocket, response: Response) {
            Log.d(TAG, "WebSocket opened; awaiting auth challenge")
            _connectionState.value = ConnectionState.Authenticating
        }

        /**
         * Called for every UTF-8 text frame.
         *
         * Interprets the first incoming message as the auth challenge from the server.
         * After auth is confirmed, routes all subsequent messages to [listeners].
         */
        override fun onMessage(webSocket: WebSocket, text: String) {
            try {
                val json = JSONObject(text)
                val type = json.optString("type")

                when {
                    // Server issues challenge immediately on connect (spec §6.5)
                    type == "challenge" -> handleAuthChallenge(webSocket, json)

                    // Server confirms successful authentication
                    type == "auth-ok" -> {
                        Log.d(TAG, "Auth confirmed by relay; connection active")
                        _connectionState.value = ConnectionState.Connected
                        reconnectAttempt.set(0)  // reset backoff on successful auth
                        startHeartbeat()

                        // Auto-replay the last register-rendezvous so the
                        // relay's presence module always has fresh membership
                        // info after a reconnect. Without this, the
                        // attemptConnect loop can reconnect silently many
                        // times within a single SignalingClient lifetime
                        // (cached process, recreated ViewModel, transient
                        // network failures) and the device would be
                        // authenticated but invisible to every rendezvous —
                        // which is exactly the "won't come back online
                        // without force-stop" presence flakiness bug.
                        val ids = pendingRendezvousIds
                        if (ids != null && ids.isNotEmpty()) {
                            Log.d(TAG, "Auto-replaying register-rendezvous on reconnect: $ids")
                            sendRegisterRendezvousNow(ids)
                        }
                    }

                    // Pong response to our heartbeat pings — no action needed
                    type == "pong" -> Log.v(TAG, "Heartbeat pong received")

                    // All other messages are dispatched to registered listeners
                    else -> dispatchMessage(RelayMessage.Text(json))
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse text message: ${e.message}")
            }
        }

        /**
         * Called for every binary frame.
         * Binary frames are encrypted relay payloads — passed through opaquely.
         */
        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            dispatchMessage(RelayMessage.Binary(bytes.toByteArray()))
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "WebSocket closing: code=$code reason=$reason")
            webSocket.close(1000, null)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "WebSocket closed: code=$code reason=$reason")
            heartbeatJob?.cancel()
            if (!intentionalDisconnect) {
                _connectionState.value = ConnectionState.Disconnected
            }
            closeChannel.trySend(Unit)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            val msg = t.message ?: "unknown error"
            Log.w(TAG, "WebSocket failure: $msg")
            heartbeatJob?.cancel()

            // Classify the failure. Network-layer errors (DNS unavailable,
            // connection reset, socket timeout) are typically transient —
            // they clear within a few seconds after an Android background/
            // foreground transition and we should NOT let them drive the
            // exponential backoff up to 8+ second waits.
            lastFailureWasTransient = when (t) {
                is java.net.UnknownHostException -> true
                is java.net.ConnectException -> true
                is java.net.SocketTimeoutException -> true
                is java.io.IOException -> msg.contains("connection abort", ignoreCase = true) ||
                    msg.contains("software caused", ignoreCase = true) ||
                    msg.contains("EHOSTUNREACH", ignoreCase = true) ||
                    msg.contains("ENETUNREACH", ignoreCase = true)
                else -> false
            }

            _connectionState.value = ConnectionState.Error(msg)
            closeChannel.trySend(Unit)
        }

        // ── Auth challenge-response (spec §6.5) ───────────────────────────────

        /**
         * Handles the relay's auth challenge by producing an Ed25519 signature over
         * `challengeBytes || timestampBytes` and replying with the device identity.
         *
         * Wire format of the outgoing auth message:
         * ```json
         * {
         *   "type":      "auth",
         *   "deviceId":  "<22-char Base64url device ID>",
         *   "publicKey": "<Base64 Ed25519 public key>",
         *   "signature": "<Base64 Ed25519 signature over challenge||timestamp>",
         *   "timestamp": "<ISO-8601 UTC timestamp>"
         * }
         * ```
         *
         * The server verifies:
         *  1. `SHA256(publicKey)[0:16] == deviceId` (key–ID binding).
         *  2. The Ed25519 signature is valid.
         *  3. The timestamp is within 30 seconds of server time (replay protection).
         *
         * @param webSocket The active socket to reply on.
         * @param json      The `{type:"challenge", challenge:"<hex>"}` JSON object.
         */
        private fun handleAuthChallenge(webSocket: WebSocket, json: JSONObject) {
            try {
                val challengeHex = json.getString("challenge")
                val challengeBytes = hexToBytes(challengeHex)

                val keys = keyManager.getOrCreateKeys()
                val deviceId = keyManager.deriveDeviceId(keys.ed25519Pk)

                // Timestamp is included in the signed payload to prevent replay attacks.
                // Server rejects timestamps more than 30 seconds old (spec §4.2).
                val timestamp = System.currentTimeMillis()
                val timestampBytes = timestamp.toString().toByteArray(Charsets.UTF_8)

                // Sign challenge || timestamp (concatenation, no delimiter)
                val messageToSign = challengeBytes + timestampBytes
                val signature = keyManager.sign(messageToSign)

                val response = JSONObject().apply {
                    put("type", "auth")
                    put("deviceId", deviceId)
                    put("publicKey", Base64.encodeToString(keys.ed25519Pk, Base64.NO_WRAP))
                    put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
                    put("timestamp", timestamp)  // numeric ms since epoch
                }

                webSocket.send(response.toString())
                Log.d(TAG, "Auth challenge response sent for device $deviceId")
            } catch (e: Exception) {
                Log.e(TAG, "Auth challenge handling failed: ${e.message}", e)
                _connectionState.value = ConnectionState.Error("Auth failed: ${e.message}")
                webSocket.close(1008, "auth_failed")
            }
        }
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    /**
     * Delivers a [RelayMessage] to all currently registered listeners.
     * Exceptions in individual listeners are caught and logged to prevent one
     * bad listener from breaking delivery to others.
     */
    private fun dispatchMessage(message: RelayMessage) {
        synchronized(listeners) { listeners.toList() }.forEach { listener ->
            try {
                listener.onMessage(message)
            } catch (e: Exception) {
                Log.e(TAG, "Listener threw on message delivery: ${e.message}", e)
            }
        }
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    /**
     * Converts a hexadecimal string (lowercase or uppercase) to a [ByteArray].
     *
     * @param hex Even-length hex string.
     * @return Decoded bytes.
     * @throws IllegalArgumentException if the string length is odd.
     */
    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length, got ${hex.length}" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
