package com.zaptransfer.android.crypto

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Beam E2E encryption — per-transfer session state machine for Android.
 *
 * Mirrors `extension/crypto/session-registry.js` in shape and semantics so
 * both clients go through identical state transitions. See the spec at
 * `docs/superpowers/specs/2026-04-10-e2e-encryption-design.md` for the
 * full lifecycle.
 *
 * This class is stateless with respect to the wire — callers feed it
 * events (`startInit`, `onInit`, `onAccept`, `destroy`) and it returns the
 * messages to send + the active session object for subsequent encrypt /
 * decrypt calls. No networking, no I/O.
 *
 * Thread-safe: uses ConcurrentHashMap and a coarse lock only for rate-limit
 * counters. Intended to be held as an application-scoped singleton.
 */
class BeamSessionRegistry(
    private val cipher: BeamCipher,
    private val ourStaticSk: ByteArray,
    private val ourStaticPk: ByteArray,
    private val config: Config = Config(),
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val random: SecureRandom = SecureRandom(),
) {

    // -------------------------------------------------------------------------
    // Configuration and constants
    // -------------------------------------------------------------------------

    data class Config(
        val handshakeTimeoutMs: Long = 10_000,
        val activeInactivityMs: Long = 60_000,
        val maxPendingPerPeer: Int = 5,
        val maxGlobalPerSecond: Int = 20,
    )

    enum class State {
        PENDING_INIT,
        AWAITING_ACCEPT,
        ACTIVE,
        COMPLETING,
        DESTROYED,
    }

    enum class Role { INITIATOR, RESPONDER }

    enum class Kind(val wire: String) {
        CLIPBOARD("clipboard"),
        FILE("file");

        companion object {
            fun fromWire(s: String): Kind? = values().firstOrNull { it.wire == s }
        }
    }

    object ErrorCodes {
        const val VERSION: String = "VERSION"
        const val TIMEOUT: String = "TIMEOUT"
        const val RATE_LIMIT: String = "RATE_LIMIT"
        const val DECRYPT_FAIL: String = "DECRYPT_FAIL"
        const val BAD_TRANSCRIPT: String = "BAD_TRANSCRIPT"
        const val INTERNAL: String = "INTERNAL"
        const val DUPLICATE: String = "DUPLICATE"
    }

    /**
     * Canonical user-facing message for every Beam error code. Mirrors
     * `extension/crypto/session-registry.js#ERROR_MESSAGES` so the two
     * platforms surface identical strings.
     */
    object ErrorMessages {
        private val table: Map<String, String> = mapOf(
            ErrorCodes.VERSION        to "Peer is running an incompatible version. Update both devices.",
            ErrorCodes.TIMEOUT        to "Peer didn't respond in time. Make sure the other device is online.",
            ErrorCodes.RATE_LIMIT     to "Too many transfers in progress. Wait a moment and try again.",
            ErrorCodes.DECRYPT_FAIL   to "Decryption failed. The transfer was tampered with or the keys do not match.",
            ErrorCodes.BAD_TRANSCRIPT to "Security check failed. The transfer was rejected.",
            ErrorCodes.INTERNAL       to "Something went wrong. Please try again.",
            ErrorCodes.DUPLICATE      to "Duplicate transfer detected. Wait a moment and try again.",
        )

        fun forCode(code: String?): String =
            table[code] ?: table[ErrorCodes.INTERNAL]!!
    }

    class HandshakeException(val code: String, message: String) : RuntimeException(message)

    // -------------------------------------------------------------------------
    // Session object
    // -------------------------------------------------------------------------

    class Session internal constructor(
        val transferId: ByteArray,
        val transferIdHex: String,
        val peerId: String,
        val peerStaticPk: ByteArray,
        val kind: Kind,
        val role: Role,
        val version: Int,
        val createdAt: Long,
    ) {
        @Volatile var state: State = State.PENDING_INIT
        @Volatile var lastActivity: Long = createdAt

        // Ephemerals — held only during the handshake window, wiped after keys derived.
        var ephSk: ByteArray? = null
        var ephPk: ByteArray? = null

        var salt: ByteArray = ByteArray(0)
        var peerEphPk: ByteArray? = null
        var transcript: ByteArray? = null
        var sessionKey: ByteArray? = null
        var chunkKey: ByteArray? = null
        var metaKey: ByteArray? = null

        // File transfer accounting — populated after metadata envelope is decoded.
        @Volatile var totalChunks: Int = 0
        @Volatile var chunksReceived: Int = 0
    }

    // -------------------------------------------------------------------------
    // Wire message shapes (pure data — no JSON here, callers serialize)
    // -------------------------------------------------------------------------

    data class TransferInitMessage(
        val v: Int,
        val transferId: ByteArray, // 16 bytes
        val kind: Kind,
        val ephPkA: ByteArray,     // 32 bytes
        val salt: ByteArray,       // 32 bytes
    )

    data class TransferAcceptMessage(
        val v: Int,
        val transferId: ByteArray,
        val ephPkB: ByteArray,
    )

    data class InitiateResult(
        val session: Session,
        val wireMessage: TransferInitMessage,
    )

    data class AcceptResult(
        val session: Session,
        val wireMessage: TransferAcceptMessage,
    )

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private val sessions = ConcurrentHashMap<String, Session>()

    // Rolling window of handshake acceptance timestamps for global rate limit.
    private val recentTimestamps = ArrayDeque<Long>()
    private val recentLock = Any()

    private val totalStarted = AtomicLong(0)

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Initiator side: generate an ephemeral keypair, create a pending session,
     * and return the wire message to transmit.
     */
    fun startInit(
        peerId: String,
        peerStaticPk: ByteArray,
        kind: Kind,
    ): InitiateResult {
        require(peerStaticPk.size == 32) { "peerStaticPk must be 32 bytes" }
        enforceRateLimits(peerId)

        val transferId = ByteArray(16).also { random.nextBytes(it) }
        val transferIdHex = toHex(transferId)
        val salt = ByteArray(32).also { random.nextBytes(it) }
        val ephSk = ByteArray(32).also { random.nextBytes(it) }
        val ephPk = cipher.x25519PublicKey(ephSk)

        val now = clock()
        val session = Session(
            transferId = transferId,
            transferIdHex = transferIdHex,
            peerId = peerId,
            peerStaticPk = peerStaticPk,
            kind = kind,
            role = Role.INITIATOR,
            version = BeamCipher.PROTOCOL_VERSION,
            createdAt = now,
        )
        session.ephSk = ephSk
        session.ephPk = ephPk
        session.salt = salt
        session.state = State.AWAITING_ACCEPT

        sessions[transferIdHex] = session
        recordRateLimit(now)
        totalStarted.incrementAndGet()

        return InitiateResult(
            session = session,
            wireMessage = TransferInitMessage(
                v = BeamCipher.PROTOCOL_VERSION,
                transferId = transferId,
                kind = kind,
                ephPkA = ephPk,
                salt = salt,
            ),
        )
    }

    /**
     * Initiator side: peer replied with transfer-accept. Finish the Triple-DH,
     * derive keys, transition to ACTIVE.
     */
    fun onAccept(peerId: String, message: TransferAcceptMessage): Session {
        val transferIdHex = toHex(message.transferId)
        val s = sessions[transferIdHex]
            ?: throw HandshakeException(ErrorCodes.INTERNAL, "no session for transferId")
        if (s.peerId != peerId) {
            throw HandshakeException(ErrorCodes.INTERNAL, "peer mismatch on transfer-accept")
        }
        if (s.state != State.AWAITING_ACCEPT) {
            throw HandshakeException(
                ErrorCodes.INTERNAL,
                "unexpected state ${s.state} for transfer-accept",
            )
        }
        require(message.ephPkB.size == 32) { "ephPkB must be 32 bytes" }

        val ephSk = s.ephSk ?: throw HandshakeException(ErrorCodes.INTERNAL, "ephSk missing")
        val ephPk = s.ephPk ?: throw HandshakeException(ErrorCodes.INTERNAL, "ephPk missing")
        s.peerEphPk = message.ephPkB

        val triple = cipher.computeTripleDHInitiator(
            staticSkA = ourStaticSk,
            ephSkA = ephSk,
            staticPkB = s.peerStaticPk,
            ephPkB = message.ephPkB,
        )

        val transcript = cipher.computeTranscript(
            version = s.version,
            staticPkA = ourStaticPk,
            staticPkB = s.peerStaticPk,
            ephPkA = ephPk,
            ephPkB = message.ephPkB,
            transferId = s.transferId,
        )

        val sessionKey = cipher.deriveSessionKey(triple.ikm, s.salt, transcript)
        val chunkKey = cipher.deriveChunkKey(sessionKey)
        val metaKey = cipher.deriveMetaKey(sessionKey)

        // Wipe ephemerals and ikm; keep the derived keys.
        cipher.wipe(ephSk, triple.dh1, triple.dh2, triple.dh3, triple.ikm)
        s.ephSk = null

        s.transcript = transcript
        s.sessionKey = sessionKey
        s.chunkKey = chunkKey
        s.metaKey = metaKey
        s.state = State.ACTIVE
        s.lastActivity = clock()
        return s
    }

    /**
     * Responder side: peer sent us transfer-init. Generate our ephemeral,
     * derive keys immediately, transition to ACTIVE, return the wire message
     * to reply with.
     */
    fun onInit(
        peerId: String,
        peerStaticPk: ByteArray,
        message: TransferInitMessage,
    ): AcceptResult {
        require(peerStaticPk.size == 32) { "peerStaticPk must be 32 bytes" }
        require(message.ephPkA.size == 32) { "ephPkA must be 32 bytes" }
        require(message.salt.size == 32) { "salt must be 32 bytes" }
        require(message.transferId.size == 16) { "transferId must be 16 bytes" }

        if (message.v != BeamCipher.PROTOCOL_VERSION) {
            throw HandshakeException(ErrorCodes.VERSION, "unsupported version ${message.v}")
        }
        enforceRateLimits(peerId)

        val transferIdHex = toHex(message.transferId)
        if (sessions.containsKey(transferIdHex)) {
            throw HandshakeException(ErrorCodes.DUPLICATE, "duplicate transferId")
        }

        val ephSk = ByteArray(32).also { random.nextBytes(it) }
        val ephPk = cipher.x25519PublicKey(ephSk)

        val triple = cipher.computeTripleDHResponder(
            staticSkB = ourStaticSk,
            ephSkB = ephSk,
            staticPkA = peerStaticPk,
            ephPkA = message.ephPkA,
        )

        // Transcript is always from initiator's perspective (A=peer, B=us).
        val transcript = cipher.computeTranscript(
            version = message.v,
            staticPkA = peerStaticPk,
            staticPkB = ourStaticPk,
            ephPkA = message.ephPkA,
            ephPkB = ephPk,
            transferId = message.transferId,
        )

        val sessionKey = cipher.deriveSessionKey(triple.ikm, message.salt, transcript)
        val chunkKey = cipher.deriveChunkKey(sessionKey)
        val metaKey = cipher.deriveMetaKey(sessionKey)

        cipher.wipe(ephSk, triple.dh1, triple.dh2, triple.dh3, triple.ikm)

        val now = clock()
        val session = Session(
            transferId = message.transferId,
            transferIdHex = transferIdHex,
            peerId = peerId,
            peerStaticPk = peerStaticPk,
            kind = message.kind,
            role = Role.RESPONDER,
            version = message.v,
            createdAt = now,
        )
        session.ephPk = ephPk
        session.salt = message.salt
        session.peerEphPk = message.ephPkA
        session.transcript = transcript
        session.sessionKey = sessionKey
        session.chunkKey = chunkKey
        session.metaKey = metaKey
        session.state = State.ACTIVE
        session.lastActivity = now

        sessions[transferIdHex] = session
        recordRateLimit(now)

        return AcceptResult(
            session = session,
            wireMessage = TransferAcceptMessage(
                v = BeamCipher.PROTOCOL_VERSION,
                transferId = message.transferId,
                ephPkB = ephPk,
            ),
        )
    }

    fun getByTransferId(transferId: ByteArray): Session? =
        sessions[toHex(transferId)]

    fun touch(session: Session) {
        session.lastActivity = clock()
    }

    fun size(): Int = sessions.size

    /**
     * Reap expired handshakes and idle active sessions. Callers should invoke
     * this periodically (e.g. every 2s on a coroutine scope).
     */
    fun sweep() {
        val now = clock()
        val it = sessions.entries.iterator()
        while (it.hasNext()) {
            val (_, s) = it.next()
            val timeout = when (s.state) {
                State.PENDING_INIT, State.AWAITING_ACCEPT -> config.handshakeTimeoutMs
                State.ACTIVE -> config.activeInactivityMs
                else -> continue
            }
            val reference = if (s.state == State.ACTIVE) s.lastActivity else s.createdAt
            if (now - reference > timeout) {
                destroyInternal(s, ErrorCodes.TIMEOUT)
                it.remove()
            }
        }
    }

    fun destroy(transferId: ByteArray, reason: String = ErrorCodes.INTERNAL) {
        val s = sessions.remove(toHex(transferId)) ?: return
        destroyInternal(s, reason)
    }

    private fun destroyInternal(s: Session, reason: String) {
        cipher.wipe(s.sessionKey, s.chunkKey, s.metaKey, s.ephSk)
        s.sessionKey = null
        s.chunkKey = null
        s.metaKey = null
        s.ephSk = null
        s.state = State.DESTROYED
    }

    // -------------------------------------------------------------------------
    // Rate limiting helpers
    // -------------------------------------------------------------------------

    private fun enforceRateLimits(peerId: String) {
        val now = clock()
        synchronized(recentLock) {
            val cutoff = now - 1000
            while (recentTimestamps.isNotEmpty() && recentTimestamps.first() < cutoff) {
                recentTimestamps.removeFirst()
            }
            if (recentTimestamps.size >= config.maxGlobalPerSecond) {
                throw HandshakeException(
                    ErrorCodes.RATE_LIMIT,
                    "global handshake rate limit exceeded",
                )
            }
        }
        val pendingForPeer = sessions.values.count { s ->
            s.peerId == peerId &&
                (s.state == State.PENDING_INIT ||
                    s.state == State.AWAITING_ACCEPT ||
                    s.state == State.ACTIVE)
        }
        if (pendingForPeer >= config.maxPendingPerPeer) {
            throw HandshakeException(
                ErrorCodes.RATE_LIMIT,
                "per-peer pending handshake limit exceeded",
            )
        }
    }

    private fun recordRateLimit(now: Long) {
        synchronized(recentLock) { recentTimestamps.addLast(now) }
    }

    // -------------------------------------------------------------------------
    // Debug / observability
    // -------------------------------------------------------------------------

    fun debugSnapshot(): List<Map<String, Any?>> = sessions.values.map {
        mapOf(
            "id" to it.transferIdHex,
            "state" to it.state.name,
            "role" to it.role.name,
            "kind" to it.kind.wire,
            "peerId" to it.peerId,
            "createdAt" to it.createdAt,
        )
    }

    private fun toHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }
}
