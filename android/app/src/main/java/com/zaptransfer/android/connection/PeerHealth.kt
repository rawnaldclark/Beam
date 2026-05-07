package com.zaptransfer.android.connection

/**
 * Per-peer health state owned by `ConnectionAuthority`.
 *
 * Mirror of `extension/connection/peer-health.js` `PeerHealth`. The JS side
 * keeps these as frozen string constants because JS lacks sum types; on
 * Kotlin we model the same five-element domain as a sealed class so:
 *   1. `when (health)` branches are exhaustive at compile time, and
 *   2. the type system distinguishes `PeerHealth` from arbitrary strings.
 *
 * The Task 14 reducer (`reduce(state, event)`) will be added as a companion
 * function on this class; the value cases here intentionally carry no fields.
 *
 * ### Cases
 *
 *  - [Unknown]  No recent evidence (boot, post-recovery, post-OFFLINE-exit).
 *  - [Healthy]  Strong recent evidence the peer is responsive (peer-pong,
 *               real v2 frame decoded, or send completed).
 *  - [Stale]    One ping has been missed; one more miss promotes to FAILED.
 *  - [Failed]   Send-path is blocked (preflight failed, two pings missed,
 *               or recovery has given up).
 *  - [Offline]  Relay reports the peer's WebSocket is closed.
 *
 * Wire/log payloads use the case's [name] (e.g. `"HEALTHY"`) — chosen to
 * match the JS string constants verbatim so both platforms emit identical
 * diagnostic strings.
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 */
sealed class PeerHealth {

    /** String form used in logs and any wire/UI payloads (matches JS verbatim). */
    abstract val name: String

    /** No recent evidence the peer is reachable. Initial state. */
    object Unknown : PeerHealth() {
        override val name: String = "UNKNOWN"
        override fun toString(): String = name
    }

    /** Strong recent evidence the peer is responsive. */
    object Healthy : PeerHealth() {
        override val name: String = "HEALTHY"
        override fun toString(): String = name
    }

    /** One ping missed; another miss escalates to FAILED. */
    object Stale : PeerHealth() {
        override val name: String = "STALE"
        override fun toString(): String = name
    }

    /** Send-path blocked: preflight failed, pings exhausted, or recovery surrendered. */
    object Failed : PeerHealth() {
        override val name: String = "FAILED"
        override fun toString(): String = name
    }

    /** Relay reports the peer's WebSocket is closed. */
    object Offline : PeerHealth() {
        override val name: String = "OFFLINE"
        override fun toString(): String = name
    }
}
