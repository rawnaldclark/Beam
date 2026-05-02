/**
 * @file self-state.js
 * @description Pure selfState state machine reducer.
 *
 * Given the current state and an inbound event, returns the next state.
 * No I/O, no timers, no side effects — this is the math behind the
 * `ConnectionAuthority`'s observable self-connection state.
 *
 * The reducer is dimensionless w.r.t. peer ID — there's only one self per
 * process; payload fields beyond `event.type` are intentionally ignored here.
 *
 * States:
 *   - OFFLINE       : not currently trying to be connected to the relay
 *                     (cold boot pre-pair, post-stop, post-unpair-all).
 *   - CONNECTING    : we have an in-flight WS connect + auth attempt.
 *   - ONLINE        : WS is open AND auth has completed.
 *   - RECONNECTING  : recovery ladder is engaged. WS may be closed,
 *                     reopening, or reauthenticating; the ladder owns it.
 *
 * Events:
 *   - start-connect      : begin a fresh connect attempt. The authority
 *                          dispatches this at four moments (first pair, cold
 *                          boot, manual reconnect, ladder Rung 2/3 begin) —
 *                          the reducer just sees one event and acts.
 *   - auth-complete      : the relay accepted our auth frame; we are ONLINE.
 *   - ws-closed          : the WebSocket closed unexpectedly. From ONLINE or
 *                          CONNECTING (auth never completed) -> RECONNECTING.
 *   - recovery-began     : the recovery ladder has started (e.g. peer FAILED
 *                          + Rung 1 begun, or external trigger). Drives any
 *                          non-RECONNECTING state into RECONNECTING.
 *   - recovery-succeeded : the ladder restored connectivity; promote to ONLINE.
 *   - recovery-given-up  : the ladder exhausted its rungs. We stay in
 *                          RECONNECTING — UI shows the surrendered banner;
 *                          the `surrenderedToUser` flag lives on the authority,
 *                          not in the reducer.
 *   - stop               : tear-down (user unpaired all devices, app shutting
 *                          down). From any state -> OFFLINE.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

/**
 * Enumeration of valid selfState states. Values are the string literals
 * (used directly in equality checks and in any wire/log payloads).
 *
 * @readonly
 * @enum {string}
 */
export const SelfState = Object.freeze({
  OFFLINE: 'OFFLINE',
  CONNECTING: 'CONNECTING',
  ONLINE: 'ONLINE',
  RECONNECTING: 'RECONNECTING',
});

/**
 * Pure reducer: (currentState, event) -> nextState.
 *
 * Defensive against unknown event types and null/undefined events: if no
 * transition matches, the input `state` is returned unchanged. The function
 * never throws on a malformed event and never mutates its arguments.
 *
 * @param {string} state  One of the SelfState enum string values.
 * @param {{ type: string }} event  An event object with a `type` discriminator.
 * @returns {string}  The next state (one of SelfState.*).
 */
export function reduceSelfState(state, event) {
  const type = event && event.type;

  switch (type) {
    // ─── start-connect: begin a fresh connect attempt ───────────────────────
    // Only OFFLINE moves forward. CONNECTING is already trying; ONLINE is
    // already there; RECONNECTING is owned by the recovery ladder. The
    // authority is responsible for dispatching start-connect at the four
    // entry-trigger moments (first pair, cold boot, manual reconnect, ladder
    // Rung 2/3 begins) — the reducer doesn't distinguish them.
    case 'start-connect': {
      if (state === SelfState.OFFLINE) return SelfState.CONNECTING;
      return state;
    }

    // ─── auth-complete: relay accepted our auth frame ───────────────────────
    // Only valid lifting CONNECTING to ONLINE. Outside CONNECTING this is a
    // no-op; in particular, RECONNECTING uses recovery-succeeded (not
    // auth-complete) to leave RECONNECTING — the ladder owns that exit.
    case 'auth-complete': {
      if (state === SelfState.CONNECTING) return SelfState.ONLINE;
      return state;
    }

    // ─── ws-closed: socket closed unexpectedly ──────────────────────────────
    // ONLINE -> RECONNECTING (we had a working session and lost it).
    // CONNECTING -> RECONNECTING as well: auth never completed, but the
    // recovery ladder still needs to drive us back. OFFLINE is a no-op (no
    // socket exists to close); RECONNECTING is a no-op (already engaged).
    case 'ws-closed': {
      if (state === SelfState.ONLINE) return SelfState.RECONNECTING;
      if (state === SelfState.CONNECTING) return SelfState.RECONNECTING;
      return state;
    }

    // ─── recovery-began: ladder is starting ─────────────────────────────────
    // Drives every state into RECONNECTING. From RECONNECTING this is a
    // self-transition (no observable change); the authority dedupes ladder
    // restarts on its own — the reducer just reports the steady state.
    case 'recovery-began': {
      return SelfState.RECONNECTING;
    }

    // ─── recovery-succeeded: ladder restored connectivity ───────────────────
    // The ladder operates from RECONNECTING; succeeding promotes us to ONLINE
    // directly (we don't bounce through CONNECTING — auth completed inside the
    // ladder). Outside RECONNECTING this is a no-op.
    case 'recovery-succeeded': {
      if (state === SelfState.RECONNECTING) return SelfState.ONLINE;
      return state;
    }

    // ─── recovery-given-up: ladder exhausted its rungs ──────────────────────
    // Stays in RECONNECTING. The UI shows a surrendered banner; the
    // `surrenderedToUser` boolean lives on the authority, not in this reducer.
    // Spec §"Recovery ladder Rung 4" leaves Rung 4 in RECONNECTING with a flag.
    // Outside RECONNECTING this event is informational and a no-op.
    case 'recovery-given-up': {
      return state;
    }

    // ─── stop: hard tear-down ───────────────────────────────────────────────
    // From any state -> OFFLINE. Used when the user unpairs all devices, the
    // app is shutting down, or any other "stop trying to be connected" signal.
    case 'stop': {
      return SelfState.OFFLINE;
    }

    // ─── unknown / malformed: no-op, do not throw ───────────────────────────
    default:
      return state;
  }
}
