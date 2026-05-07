package com.zaptransfer.android.connection

/**
 * This client's own connection-to-relay state, owned by `ConnectionAuthority`.
 *
 * Mirror of `extension/connection/self-state.js` `SelfState`. The JS side
 * keeps these as frozen string constants and tracks the "surrendered to user"
 * flag as a separate observable. On Kotlin we model the same domain as a
 * sealed class and fold the surrender flag into the [Reconnecting] case so
 * the state and its modifier travel together — see plan line 474.
 *
 * The Task 14 reducer will be added as a companion function on this class;
 * the value cases here intentionally carry no fields apart from
 * [Reconnecting.surrenderedToUser].
 *
 * ### Cases
 *
 *  - [Offline]      Not currently trying to be connected to the relay
 *                   (cold boot pre-pair, post-stop, post-unpair-all).
 *  - [Connecting]   In-flight WebSocket connect + auth attempt.
 *  - [Online]       WebSocket is open AND auth has completed.
 *  - [Reconnecting] Recovery ladder is engaged. The WS may be closed,
 *                   reopening, or reauthenticating; the ladder owns it.
 *                   When the ladder exhausts its rungs, the same case is
 *                   used with [Reconnecting.surrenderedToUser] = true so
 *                   the UI can surface the "tap to reconnect" affordance.
 *
 * Wire/log payloads use the case's [name] string (e.g. `"RECONNECTING"`),
 * matching the JS string constants verbatim. The [Reconnecting] case omits
 * the surrender flag from [name] to keep log lines stable; callers that
 * need it should read [Reconnecting.surrenderedToUser] directly.
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 */
sealed class SelfState {

    /** String form used in logs and any wire/UI payloads (matches JS verbatim). */
    abstract val name: String

    /** Cold boot pre-pair, post-stop, post-unpair-all — no connect in flight. */
    object Offline : SelfState() {
        override val name: String = "OFFLINE"
        override fun toString(): String = name
    }

    /** WebSocket connect + auth handshake in flight. */
    object Connecting : SelfState() {
        override val name: String = "CONNECTING"
        override fun toString(): String = name
    }

    /** WebSocket is open and auth has completed. */
    object Online : SelfState() {
        override val name: String = "ONLINE"
        override fun toString(): String = name
    }

    /**
     * Recovery ladder is engaged. The [surrenderedToUser] flag is set to
     * `true` when the ladder has exhausted Rungs 1-3 and Rung 4 has handed
     * off to the user — the UI shows the "Connection failed - tap to
     * reconnect" affordance.
     *
     * @property surrenderedToUser True iff the recovery ladder has given up
     *           and the user must tap to retry.
     */
    data class Reconnecting(val surrenderedToUser: Boolean = false) : SelfState() {
        override val name: String = "RECONNECTING"
    }
}
