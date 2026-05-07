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
 * The Task 14 reducer (`reduce(state, event)`) is implemented on the
 * companion object; the value cases here intentionally carry no fields.
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

    companion object {
        /**
         * Pure reducer: `(currentState, event) -> nextState`.
         *
         * No I/O, no timers, no side effects — this is the math behind the
         * `ConnectionAuthority`'s observable peer-health map. Mirrors
         * `extension/connection/peer-health.js#reducePeerHealth` transition
         * for transition; any divergence here is a bug.
         *
         * No-op transitions return the same `state` instance (object identity)
         * so a downstream `StateFlow` does not re-emit on a non-change.
         *
         * ### Transition table (only non-no-op rows shown)
         *
         *  - [PeerHealthEvent.PongReceived]      : * \ {Offline} -> [Healthy]
         *  - [PeerHealthEvent.FrameReceived]     : * \ {Offline} -> [Healthy]
         *  - [PeerHealthEvent.SendCompleted]     : * \ {Offline} -> [Healthy]
         *  - [PeerHealthEvent.PingMissed]        : [Unknown] -> [Stale],
         *                                           [Healthy] -> [Stale],
         *                                           [Stale]   -> [Failed]
         *  - [PeerHealthEvent.PreFlightFailed]   : *         -> [Failed]
         *                                          (yes, including [Offline] —
         *                                          preflight is concrete failure
         *                                          evidence; matches JS)
         *  - [PeerHealthEvent.RelayPeerOnline]   : [Offline] -> [Unknown]
         *                                          (weaker evidence; NOT [Healthy])
         *  - [PeerHealthEvent.RelayPeerOffline]  : *         -> [Offline]
         *  - [PeerHealthEvent.RecoverySucceeded] : [Failed]  -> [Unknown]
         *  - [PeerHealthEvent.RecoveryGivenUp]   : no-op for every state — the
         *                                          surrender flag lives on
         *                                          [SelfState.Reconnecting], not here.
         *
         * @param state The current peer-health state.
         * @param event The inbound event.
         * @return The next state, or `state` itself if the event is a no-op
         *         from this state. Never null, never throws.
         */
        fun reduce(state: PeerHealth, event: PeerHealthEvent): PeerHealth = when (event) {
            // ─── strong "peer is responsive" signals ────────────────────────
            // Three independent strong signals all promote to HEALTHY from any
            // non-OFFLINE state. While OFFLINE the relay says the peer's WS is
            // closed, so even if a stale-in-flight pong somehow arrives we hold
            // OFFLINE until the relay re-affirms presence (RelayPeerOnline).
            PeerHealthEvent.PongReceived,
            PeerHealthEvent.FrameReceived,
            PeerHealthEvent.SendCompleted -> if (state === Offline) Offline else Healthy

            // ─── PingMissed: one-miss tolerance, then FAILED ────────────────
            PeerHealthEvent.PingMissed -> when (state) {
                Unknown -> Stale
                Healthy -> Stale
                Stale -> Failed
                // Failed stays Failed; Offline stays Offline (offline owns the floor).
                Failed -> state
                Offline -> state
            }

            // ─── PreFlightFailed: hard send-path failure ────────────────────
            // Pre-flight is checked at send time; if it fails we know the send
            // path cannot work right now regardless of prior state, INCLUDING
            // OFFLINE — preflight is concrete failure evidence the relay's
            // peer-online claim was stale. Mirrors JS exactly.
            PeerHealthEvent.PreFlightFailed -> Failed

            // ─── RelayPeerOnline: weaker presence evidence ──────────────────
            // OFFLINE -> UNKNOWN is the only forward transition. Per spec, the
            // relay's "WS open" view does NOT prove the peer's app is
            // responsive — promoting straight to HEALTHY here is the
            // false-positive that produces the "says connected, nothing sends"
            // symptom we are explicitly eliminating. For all non-OFFLINE
            // states we leave the existing state alone (don't upgrade or
            // downgrade on this weaker signal). FAILED in particular is owned
            // by the recovery ladder, not by relay presence events.
            PeerHealthEvent.RelayPeerOnline -> if (state === Offline) Unknown else state

            // ─── RelayPeerOffline: peer's WS is closed ──────────────────────
            PeerHealthEvent.RelayPeerOffline -> Offline

            // ─── RecoverySucceeded: drop to UNKNOWN, await next ping/frame ──
            // Recovery operates on a FAILED peer; succeeding moves us to
            // UNKNOWN so the next strong signal (pong/frame/send) promotes to
            // HEALTHY. Outside of FAILED this event is a no-op.
            PeerHealthEvent.RecoverySucceeded -> if (state === Failed) Unknown else state

            // ─── RecoveryGivenUp: no peer-health change ─────────────────────
            // The surrender flag lives on [SelfState.Reconnecting.surrenderedToUser];
            // peerHealth FAILED is already the right signal for the UI to read,
            // so the reducer is a no-op for this event from every state.
            PeerHealthEvent.RecoveryGivenUp -> state
        }
    }
}

/**
 * Inbound events the [PeerHealth] reducer recognises. Each value is a strict
 * mirror of one of the JS `event.type` discriminator strings in
 * `extension/connection/peer-health.js`.
 *
 * Modelled as `object` cases (no payload) because the JS reducer ignores
 * every non-`type` field on the event. The transport boundary is responsible
 * for translating wire payloads (peer IDs, nonces, etc.) into the right
 * `PeerHealthEvent` value before handing it to [PeerHealth.reduce].
 */
sealed class PeerHealthEvent {
    /** The peer answered our peer-ping. Strong evidence of responsiveness. */
    object PongReceived : PeerHealthEvent()

    /** A real v2 frame was decoded from the peer. Strong evidence. */
    object FrameReceived : PeerHealthEvent()

    /** A frame send to the peer succeeded end-to-end. Strong evidence. */
    object SendCompleted : PeerHealthEvent()

    /** A peer-ping deadline elapsed without a pong. */
    object PingMissed : PeerHealthEvent()

    /** Send-time pre-flight check failed (no peer, channel down, etc.). */
    object PreFlightFailed : PeerHealthEvent()

    /** Relay reports the peer's WebSocket is open. Weaker than a real pong. */
    object RelayPeerOnline : PeerHealthEvent()

    /** Relay reports the peer's WebSocket is closed. */
    object RelayPeerOffline : PeerHealthEvent()

    /** The recovery ladder finished a recovery attempt successfully. */
    object RecoverySucceeded : PeerHealthEvent()

    /** The recovery ladder exhausted its rungs (Rung 4 surrender). */
    object RecoveryGivenUp : PeerHealthEvent()
}
