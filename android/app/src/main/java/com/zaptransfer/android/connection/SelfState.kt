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
 * The Task 14 reducer is implemented on the companion object; the value
 * cases here intentionally carry no fields apart from [Reconnecting.surrenderedToUser].
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

    companion object {
        /**
         * Pure reducer: `(currentState, event) -> nextState`.
         *
         * No I/O, no timers, no side effects — this is the math behind the
         * `ConnectionAuthority`'s observable self-connection state. Mirrors
         * `extension/connection/self-state.js#reduceSelfState` transition for
         * transition; any divergence here is a bug.
         *
         * No-op transitions return the same `state` instance (object identity)
         * so a downstream `StateFlow` does not re-emit on a non-change.
         *
         * ### Transition table (only non-no-op rows shown)
         *
         *  - [SelfStateEvent.StartConnect]      : [Offline] -> [Connecting]
         *  - [SelfStateEvent.AuthComplete]      : [Connecting]      -> [Online]
         *                                         [Reconnecting] -> [Online]
         *                                         (deadlock-fix: WS reauth is
         *                                         the only signal a ladder
         *                                         rung's "Online" success
         *                                         observer can act on — see
         *                                         Chrome commit `bd56305`)
         *  - [SelfStateEvent.WsClosed]          : [Online]      -> [Reconnecting]`(false)`
         *                                         [Connecting]  -> [Reconnecting]`(false)`
         *  - [SelfStateEvent.RecoveryBegan]     : [Connecting]  -> [Reconnecting]`(false)`
         *                                         [Online]      -> [Reconnecting]`(false)`
         *                                         (Offline stays Offline — user
         *                                         explicitly disconnected)
         *  - [SelfStateEvent.RecoverySucceeded] : [Reconnecting] -> [Online]
         *  - [SelfStateEvent.RecoveryGivenUp]   : [Reconnecting]`(false)` -> [Reconnecting]`(true)`
         *                                         [Reconnecting]`(true)`  -> SAME instance
         *                                         (idempotent — no spurious
         *                                         StateFlow notification)
         *  - [SelfStateEvent.Stop]              : *             -> [Offline]
         *
         * @param state The current self-connection state.
         * @param event The inbound event.
         * @return The next state, or `state` itself if the event is a no-op
         *         from this state. Never null, never throws.
         */
        fun reduce(state: SelfState, event: SelfStateEvent): SelfState = when (event) {
            // ─── StartConnect: begin a fresh connect attempt ────────────────
            // Only OFFLINE moves forward. CONNECTING is already trying; ONLINE
            // is already there; RECONNECTING is owned by the recovery ladder.
            // The authority is responsible for dispatching StartConnect at the
            // four entry-trigger moments (first pair, cold boot, manual
            // reconnect, ladder Rung 2/3 begins) — the reducer doesn't
            // distinguish them.
            SelfStateEvent.StartConnect -> if (state === Offline) Connecting else state

            // ─── AuthComplete: relay accepted our auth frame ────────────────
            // Lifts BOTH Connecting -> Online (cold-boot path) AND
            // Reconnecting -> Online (recovery path). The recovery transition
            // is the only signal a ladder rung's "selfState === Online"
            // success observer can act on: without it, Rung 2's
            // `forceWsReconnect` and Rung 3's `forceFullReset` could reopen +
            // reauthenticate the WS but the rung would still time out because
            // nothing else flips selfState back. The ladder's own
            // RecoverySucceeded event is dispatched after a rung resolves; it
            // performs surrender-flag + thrash-counter cleanup but is a
            // state-machine no-op once we're already Online.
            //
            // This is the deadlock fix from Chrome commit bd56305 — load-bearing.
            SelfStateEvent.AuthComplete -> when (state) {
                Connecting -> Online
                is Reconnecting -> Online
                Offline -> state
                Online -> state
            }

            // ─── WsClosed: socket closed unexpectedly ───────────────────────
            // Online -> Reconnecting (we had a working session and lost it).
            // Connecting -> Reconnecting as well: auth never completed, but the
            // recovery ladder still needs to drive us back. Offline is a no-op
            // (no socket exists to close); Reconnecting is a no-op (already
            // engaged — preserves any surrendered-to-user flag).
            SelfStateEvent.WsClosed -> when (state) {
                Online -> Reconnecting(surrenderedToUser = false)
                Connecting -> Reconnecting(surrenderedToUser = false)
                Offline -> state
                is Reconnecting -> state
            }

            // ─── RecoveryBegan: ladder is starting ──────────────────────────
            // Drives every non-Reconnecting state into Reconnecting(false),
            // matching the Chrome reducer (`extension/connection/self-state.js`
            // — `case 'recovery-began'`). Offline is included: a cold-boot
            // ladder kick (e.g. an Android service waking with no prior
            // connect attempt) legitimately drives Offline -> Reconnecting,
            // skipping Connecting entirely.
            //
            // From Reconnecting(true) we transition to a fresh
            // Reconnecting(false): a new ladder kick clears the user-surrender
            // flag so the UI banner returns to amber. From Reconnecting(false)
            // we return the SAME instance — the authority dedupes ladder
            // restarts on its own and a StateFlow re-emit on a non-change is
            // exactly the spurious notification the identity contract avoids.
            SelfStateEvent.RecoveryBegan -> when (state) {
                is Reconnecting ->
                    if (state.surrenderedToUser) Reconnecting(surrenderedToUser = false) else state
                Offline -> Reconnecting(surrenderedToUser = false)
                Connecting -> Reconnecting(surrenderedToUser = false)
                Online -> Reconnecting(surrenderedToUser = false)
            }

            // ─── RecoverySucceeded: ladder restored connectivity ────────────
            // The ladder operates from Reconnecting; succeeding promotes us to
            // Online directly (we don't bounce through Connecting — auth
            // completed inside the ladder). Outside Reconnecting this is a
            // no-op. Surrender flag is dropped on success.
            SelfStateEvent.RecoverySucceeded -> if (state is Reconnecting) Online else state

            // ─── RecoveryGivenUp: Rung 4 surrender ──────────────────────────
            // Reconnecting(false) -> Reconnecting(true): observers see this as
            // a state change, the intended UX signal for "banner goes red".
            // Reconnecting(true)  -> SAME instance: idempotent re-surrender so
            // a StateFlow does not re-emit on a non-change.
            // From any other state -> SAME instance (no-op).
            //
            // Implementation matches the spec's `if (state is Reconnecting &&
            // !state.surrenderedToUser) Reconnecting(true) else state` form.
            SelfStateEvent.RecoveryGivenUp ->
                if (state is Reconnecting && !state.surrenderedToUser) {
                    Reconnecting(surrenderedToUser = true)
                } else {
                    state
                }

            // ─── Stop: hard tear-down ───────────────────────────────────────
            // From any state -> Offline. Used when the user unpairs all
            // devices, the app is shutting down, or any other "stop trying to
            // be connected" signal. From Offline this returns the SAME
            // instance to avoid a no-op StateFlow re-emit.
            SelfStateEvent.Stop -> if (state === Offline) state else Offline
        }
    }
}

/**
 * Inbound events the [SelfState] reducer recognises. Each value is a strict
 * mirror of one of the JS `event.type` discriminator strings in
 * `extension/connection/self-state.js`.
 *
 * Modelled as `object` cases (no payload) because the JS reducer ignores
 * every non-`type` field on the event. The transport boundary is responsible
 * for translating WebSocket lifecycle events, auth-handshake completions,
 * and recovery-ladder rung outcomes into the right `SelfStateEvent` value
 * before handing it to [SelfState.reduce].
 */
sealed class SelfStateEvent {
    /**
     * Begin a fresh connect attempt. The authority dispatches this at four
     * moments (first pair, cold boot, manual reconnect, ladder Rung 2/3
     * begin) — the reducer just sees one event and acts.
     */
    object StartConnect : SelfStateEvent()

    /** The relay accepted our auth frame; we are ONLINE. */
    object AuthComplete : SelfStateEvent()

    /** The WebSocket closed unexpectedly. */
    object WsClosed : SelfStateEvent()

    /**
     * The recovery ladder has started (e.g. peer FAILED + Rung 1 begun, or an
     * external trigger). Drives non-OFFLINE states into RECONNECTING.
     */
    object RecoveryBegan : SelfStateEvent()

    /** The ladder restored connectivity; promote to ONLINE. */
    object RecoverySucceeded : SelfStateEvent()

    /**
     * The ladder exhausted its rungs. We stay in RECONNECTING — the UI shows
     * the surrendered banner; the surrender flag is folded into
     * [SelfState.Reconnecting.surrenderedToUser] (Kotlin) rather than living
     * on a separate authority field (JS).
     */
    object RecoveryGivenUp : SelfStateEvent()

    /**
     * Tear-down (user unpaired all devices, app shutting down). From any
     * state -> OFFLINE.
     */
    object Stop : SelfStateEvent()
}
