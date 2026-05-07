package com.zaptransfer.android.connection

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import java.security.SecureRandom
import java.util.Base64
import java.util.LinkedHashMap

/**
 * Outcome of an outbound peer-ping.
 *
 * Mirrors the JS resolved/rejected pair: in JS the promise resolves with
 * `{ok:true, rttMs}` or rejects with `{ok:false, reason:"timeout"}`. On the
 * Kotlin side we keep the [Deferred] always *completing* (never rejecting)
 * with one of these two cases, because:
 *
 *  - [Deferred] cancellation surfaces as `CancellationException` which is
 *    cooperative and not the right signal for "the peer didn't answer in
 *    time"; that's a domain outcome, not coroutine cancellation.
 *  - Modeling the timeout as a successful completion with a [TimedOut]
 *    payload removes the need for every caller to wrap `await()` in
 *    try/catch — the only legitimate exceptions remain real bugs.
 *
 * Both cases carry the [peerId] so a caller can correlate the result with
 * the ping it issued without having to remember it externally.
 */
sealed class PingResult {
    /** Peer ID the ping was issued to (preserved on both outcomes). */
    abstract val peerId: String

    /** A `peer-pong` with the matching nonce was received. */
    data class Pong(override val peerId: String) : PingResult()

    /** No `peer-pong` arrived before the deadline elapsed. */
    data class TimedOut(override val peerId: String) : PingResult()
}

/**
 * Outbound `peer-ping` wire frame, in typed form.
 *
 * The tracker emits one of these per [PeerPingTracker.sendPing] call. The
 * owning `ConnectionAuthority` (Task 15) is responsible for translating it
 * into the wire JSON the relay accepts — currently `org.json.JSONObject`
 * via `SignalingClient.send`. Keeping the tracker free of `org.json` lets
 * pure-JVM unit tests assert on a strongly-typed value rather than fighting
 * Android's stub `org.json` (which returns null from typed accessors when
 * `testOptions.unitTests.isReturnDefaultValues` is true — see
 * `BeamV2VectorsTest` for the gson workaround used elsewhere).
 *
 * Field order matches the JS wire frame in `extension/connection/peer-ping.js`:
 *   `{type:"peer-ping", nonce, targetDeviceId, rendezvousId}`.
 *
 * @property type            Constant `"peer-ping"` literal — reserved for
 *                            future protocol evolution where the tracker
 *                            might emit other related frames.
 * @property nonce           22-character base64url, no padding (16 random bytes).
 * @property targetDeviceId  The peer being pinged (relay's routing key).
 * @property rendezvousId    *This* client's own deviceId — see
 *                            [PeerPingTracker.ownDeviceId] doc for why.
 */
data class PeerPingMessage(
    val type: String = "peer-ping",
    val nonce: String,
    val targetDeviceId: String,
    val rendezvousId: String,
)

/**
 * Tracks outbound `peer-ping` messages and completes their [Deferred]s when
 * pongs arrive or deadlines pass.
 *
 * Kotlin port of `extension/connection/peer-ping.js`. Public surface mirrors
 * the JS one-to-one so the Chrome and Android recovery ladders can re-use
 * test fixtures and spec mappings without per-platform translation.
 *
 * ### Wire-shape routing
 *
 *   - `targetDeviceId` is the peer being pinged.
 *   - `rendezvousId`   is *this* client's own deviceId (injected via
 *                      [ownDeviceId]) — NOT the peer's.
 *
 * The relay's signaling path enforces rendezvous membership for both
 * sender and target; the Chrome <-> Android pair shares the *initiator's*
 * own deviceId as the rendezvous, never the peer's. Getting this backwards
 * silently breaks routing — the constructor's [require] guards exist
 * precisely so an `undefined`/empty `ownDeviceId` fails loudly at
 * construction time rather than producing wire frames the relay rejects.
 *
 * ### Threading
 *
 * This class is **not** thread-safe; its single-threaded mutable state is
 * intentional. The owning `ConnectionAuthority` (Task 15) will confine all
 * calls to a single coroutine context (typically `Dispatchers.Default` via
 * a `Mutex` or single-threaded actor). The unit-test suite drives it on
 * one thread, matching that contract.
 *
 * ### No timers, no I/O
 *
 * This module owns no timers and performs no network I/O. The caller
 * injects [sendJson] and drives the sweep tick by calling [sweepExpired]
 * from a background ticker (the cadence engine in Task 16). This keeps
 * unit tests deterministic — every input is explicit.
 *
 * @property sendMessage   Caller-injected send function. Invoked once per
 *                          [sendPing] call with the typed [PeerPingMessage].
 *                          The owning `ConnectionAuthority` adapts this to
 *                          its underlying transport (`SignalingClient.send`
 *                          for the relay path). Must not throw; exceptions
 *                          propagate to the caller of [sendPing].
 * @property timeoutMs     Milliseconds before a ping is considered timed
 *                          out. Must be positive.
 * @property ownDeviceId   This client's own device ID. Used as the
 *                          `rendezvousId` on outbound peer-ping frames.
 *                          Must be non-empty.
 * @property random        Source of cryptographic randomness for nonces.
 *                          Defaults to a fresh [SecureRandom]; tests may
 *                          inject a stub if determinism is needed (the
 *                          standard suite does not — it relies on the real
 *                          PRNG and asserts the encoded properties).
 *
 * @throws IllegalArgumentException If [ownDeviceId] is empty, [timeoutMs]
 *         is non-positive, or any required collaborator is missing. (Kotlin
 *         idiom for the JS `TypeError` fail-loud guards.)
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 */
class PeerPingTracker(
    private val sendMessage: (PeerPingMessage) -> Unit,
    private val timeoutMs: Long,
    /**
     * This client's own device ID. Exposed (read-only) so the recovery
     * ladder's Rung 1 action can populate the `rendezvousId` field on the
     * register-rendezvous frame without re-deriving it from [KeyManager].
     * Production callers obtain this via the construction path; tests pass
     * a literal.
     */
    val ownDeviceId: String,
    private val random: SecureRandom = SecureRandom(),
) {

    init {
        require(ownDeviceId.isNotEmpty()) {
            "PeerPingTracker: ownDeviceId is required (non-empty string)"
        }
        require(timeoutMs > 0L) {
            "PeerPingTracker: timeoutMs must be positive (got $timeoutMs)"
        }
    }

    /**
     * In-flight ping bookkeeping, keyed by nonce. Iteration order matches
     * insertion order ([LinkedHashMap]) so the [sweepExpired] pass visits
     * pings in send order — strictly cosmetic, but stabilizes log output
     * and any downstream observers that care about FIFO eviction.
     */
    private val pending: LinkedHashMap<String, PendingPing> = LinkedHashMap()

    /**
     * In-flight ping record. Held privately; never escapes the tracker.
     */
    private data class PendingPing(
        val sentAt: Long,
        val deadline: Long,
        val peerId: String,
        val deferred: CompletableDeferred<PingResult>,
    )

    /**
     * Send a `peer-ping` to [peerId] and return the nonce plus a deferred
     * that completes on pong arrival ([PingResult.Pong]) or on the next
     * sweep past the deadline ([PingResult.TimedOut]).
     *
     * The [PeerPingMessage] handed to [sendMessage] has shape:
     * ```
     * PeerPingMessage(
     *   type            = "peer-ping",
     *   nonce           = "<22-char b64url>",
     *   targetDeviceId  = "<peerId>",
     *   rendezvousId    = "<ownDeviceId>",
     * )
     * ```
     * — identical to the JS implementation's wire JSON. The `sentAt`
     * timestamp is held in the tracker's bookkeeping but **not** placed on
     * the wire; the receiver only needs the nonce.
     *
     * @param peerId Device ID to ping (placed on the wire as `targetDeviceId`).
     * @param now    Current time in milliseconds since epoch. Defaults to
     *               [System.currentTimeMillis]; tests inject a fake clock
     *               value to drive deterministic timeout sweeps.
     * @return A pair of (nonce, deferred). The nonce is also embedded in
     *         the wire frame; callers that want to correlate inbound
     *         pongs can match on it. The deferred completes exactly once.
     */
    fun sendPing(
        peerId: String,
        now: Long = System.currentTimeMillis(),
    ): Pair<String, Deferred<PingResult>> {
        val nonce = generateNonce()
        // Defensive guard against a broken random source (e.g. a misconfigured
        // test stub returning a fixed value): clobbering an in-flight entry
        // would silently leak the prior deferred — never completed, never
        // swept once the new entry owns the key. With 128 bits of real
        // entropy a natural collision is astronomically unlikely; this guard
        // exists to surface the seam break, not the birthday bound.
        check(!pending.containsKey(nonce)) {
            "PeerPingTracker: nonce collision — random source may be broken"
        }
        val sentAt = now
        val deadline = sentAt + timeoutMs
        val deferred = CompletableDeferred<PingResult>()
        pending[nonce] = PendingPing(sentAt, deadline, peerId, deferred)

        sendMessage(
            PeerPingMessage(
                nonce = nonce,
                targetDeviceId = peerId,
                rendezvousId = ownDeviceId,
            )
        )

        return nonce to deferred
    }

    /**
     * Record an inbound `peer-pong`. Completes the matching pending
     * deferred with [PingResult.Pong] and removes it from the tracker.
     *
     * Differs from the JS reference in one Kotlin-side affordance: the
     * function returns whether the [nonce] matched a pending ping. The JS
     * version returns void; here a [Boolean] result lets the caller log
     * unrecognized pongs without re-implementing the lookup. An unknown
     * nonce is a no-op — never throws, never has observable side effects.
     *
     * @param nonce The nonce echoed by the peer in its `peer-pong` frame.
     * @param now   Current time in milliseconds (unused for now; reserved
     *              for future RTT bookkeeping if we re-introduce it).
     * @return `true` iff a pending ping with that nonce was found and
     *         completed; `false` if the nonce is unknown.
     */
    @Suppress("UNUSED_PARAMETER")
    fun recordPong(
        nonce: String,
        now: Long = System.currentTimeMillis(),
    ): Boolean {
        // `now` is currently unused — the JS resolves with rttMs, but the
        // Kotlin PingResult.Pong carries only peerId. Kept on the signature
        // so future RTT instrumentation does not break call sites.
        val entry = pending.remove(nonce) ?: return false
        entry.deferred.complete(PingResult.Pong(entry.peerId))
        return true
    }

    /**
     * Sweep the in-flight map for entries whose deadline has passed.
     * Each expired entry is completed with [PingResult.TimedOut] and
     * removed from the tracker.
     *
     * Differs from the JS reference, which returns an array of
     * `{nonce, peerId}` for caller event dispatch. The Kotlin port
     * returns the *count* of swept entries instead — downstream
     * `ConnectionAuthority` listens to each ping's [Deferred] for the
     * per-peer event, so the per-call enumeration is redundant. (Flagged
     * as deviation in Task 13 report; harmless because Tasks 14-17 do
     * not consume the array form.)
     *
     * @param now Current time in milliseconds. Pings whose `deadline <= now`
     *            are swept. The boundary is inclusive on `>=` to match JS:
     *            `if (now >= entry.deadline)`.
     * @return Number of pings swept (0 if none were past their deadline).
     */
    fun sweepExpired(now: Long = System.currentTimeMillis()): Int {
        if (pending.isEmpty()) return 0
        // Two-pass to avoid ConcurrentModificationException on the iterator
        // when we remove entries inside the loop.
        val expiredNonces = mutableListOf<String>()
        for ((nonce, entry) in pending) {
            if (now >= entry.deadline) expiredNonces.add(nonce)
        }
        for (nonce in expiredNonces) {
            val entry = pending.remove(nonce) ?: continue
            entry.deferred.complete(PingResult.TimedOut(entry.peerId))
        }
        return expiredNonces.size
    }

    // ── Internals ──────────────────────────────────────────────────────────

    /**
     * Generate a 16-byte cryptographically random nonce, base64url-encoded
     * without padding. Result is always 22 characters and matches the JS
     * `generateNonce()` byte length, encoding, and padding rules.
     */
    private fun generateNonce(): String {
        val bytes = ByteArray(NONCE_BYTES)
        random.nextBytes(bytes)
        return URL_ENCODER_NO_PAD.encodeToString(bytes)
    }

    private companion object {
        /** Nonce length in bytes — 16, matching JS `peer-ping.js#generateNonce`. */
        const val NONCE_BYTES = 16

        /** Base64 URL-safe encoder without padding (matches JS b64url-no-pad). */
        val URL_ENCODER_NO_PAD: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    }
}
