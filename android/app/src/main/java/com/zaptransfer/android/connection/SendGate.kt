package com.zaptransfer.android.connection

/**
 * Result of `ConnectionAuthority.ensureSendable(deviceId)` — the send-time
 * pre-flight check that gates every outbound v2 frame.
 *
 * Mirrors the JS shape `{ok:true}` / `{ok:false, reason:'SELF_OFFLINE'|'PEER_UNREACHABLE'}`
 * returned by `extension/connection/connection-authority.js#ensureSendable`.
 * Kotlin's sealed class form preserves the same information with exhaustive
 * `when` and zero string-typo risk.
 *
 * ### Cases
 *
 *  - [Ok]               Send is permitted; the caller may encode and ship the
 *                       v2 frame.
 *  - [SelfOffline]      Our own [SelfState] is not [SelfState.Online]; no peer
 *                       is reachable until we reconnect. Caller surfaces a
 *                       "Reconnect" affordance.
 *  - [PeerUnreachable]  We are online but the specific peer cannot be
 *                       reached: pre-flight ping timed out and the recovery
 *                       ladder did not restore the path within budget.
 *                       The carried [PeerUnreachable.reason] string is the
 *                       JS-compatible reason code (currently the literal
 *                       `"PEER_UNREACHABLE"`); future spec revisions may
 *                       add finer-grained reasons here.
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 *       (`§Public surface` shows this exact sealed-class shape).
 */
sealed class SendGate {

    /** Send permitted — ship the frame. */
    object Ok : SendGate()

    /** Our own connection to the relay is not ONLINE; no peer is reachable. */
    object SelfOffline : SendGate()

    /**
     * The specific peer is not reachable right now.
     *
     * @property reason Reason code mirroring the JS `reason` string. Values
     *           currently used: `"PEER_UNREACHABLE"` (per JS `connection-authority.js`).
     */
    data class PeerUnreachable(val reason: String) : SendGate()
}
