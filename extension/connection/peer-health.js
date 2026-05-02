/**
 * @file peer-health.js
 * @description Pure peer-health state machine reducer.
 *
 * Given the current state and an inbound event, returns the next state.
 * No I/O, no timers, no side effects — this is the math behind the
 * `ConnectionAuthority`'s observable peer-health map.
 *
 * States:
 *   - UNKNOWN  : we have no recent evidence (boot, post-recovery, post-OFFLINE-exit).
 *   - HEALTHY  : strong recent evidence the peer is responsive
 *                (peer-pong received, real v2 frame decoded, or send completed).
 *   - STALE    : one ping has been missed; one more miss will fail us.
 *   - FAILED   : send-path is blocked (preflight failed, two pings missed,
 *                or recovery has given up).
 *   - OFFLINE  : relay reports the peer's WebSocket is closed.
 *
 * Events:
 *   - pong-received       : the peer answered our peer-ping. Strong evidence.
 *   - frame-received      : a real v2 frame was decoded from the peer. Strong evidence.
 *   - send-completed      : a frame send to the peer succeeded end-to-end. Strong evidence.
 *   - ping-missed         : a peer-ping deadline elapsed without a pong.
 *   - pre-flight-failed   : send-time pre-flight check failed (no peer, channel down, etc.).
 *   - relay-peer-online   : the relay tells us the peer's WS is open. *Weaker* evidence —
 *                           the peer's app may not actually be responsive. We exit
 *                           OFFLINE on this event but only as far as UNKNOWN; only
 *                           a real pong/frame can promote us further.
 *   - relay-peer-offline  : the relay tells us the peer's WS is closed.
 *   - recovery-succeeded  : the recovery ladder finished a recovery attempt. We
 *                           drop back to UNKNOWN; the next ping/frame promotes us.
 *   - recovery-given-up   : the recovery ladder exhausted its rungs. State stays
 *                           FAILED (UI surfaces it; user takes manual action).
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

/**
 * Enumeration of valid peer-health states. Values are the string literals
 * (used directly in equality checks and in any wire/log payloads).
 *
 * @readonly
 * @enum {string}
 */
export const PeerHealth = Object.freeze({
  UNKNOWN: 'UNKNOWN',
  HEALTHY: 'HEALTHY',
  STALE: 'STALE',
  FAILED: 'FAILED',
  OFFLINE: 'OFFLINE',
});

/**
 * Pure reducer: (currentState, event) -> nextState.
 *
 * Defensive against unknown event types: if no transition matches, the input
 * `state` is returned unchanged. The function never throws on a malformed
 * event and never mutates its arguments.
 *
 * @param {string} state  One of the PeerHealth enum string values.
 * @param {{ type: string }} event  An event object with a `type` discriminator.
 * @returns {string}  The next state (one of PeerHealth.*).
 */
export function reducePeerHealth(state, event) {
  const type = event && event.type;

  switch (type) {
    // ─── strong "peer is responsive" signals ────────────────────────────────
    // Three independent strong signals all promote to HEALTHY from any non-OFFLINE
    // state. While OFFLINE the relay says the peer's WS is closed, so even if a
    // stale-in-flight pong somehow arrives we hold OFFLINE until the relay
    // re-affirms presence (relay-peer-online).
    case 'pong-received':
    case 'frame-received':
    case 'send-completed': {
      if (state === PeerHealth.OFFLINE) return PeerHealth.OFFLINE;
      return PeerHealth.HEALTHY;
    }

    // ─── ping-missed: one-miss tolerance, then FAILED ───────────────────────
    case 'ping-missed': {
      if (state === PeerHealth.UNKNOWN) return PeerHealth.STALE;
      if (state === PeerHealth.HEALTHY) return PeerHealth.STALE;
      if (state === PeerHealth.STALE) return PeerHealth.FAILED;
      // FAILED stays FAILED; OFFLINE stays OFFLINE (offline owns the floor).
      return state;
    }

    // ─── pre-flight-failed: hard send-path failure ──────────────────────────
    // Pre-flight is checked at send time; if it fails we know the send path
    // cannot work right now regardless of prior state, including OFFLINE.
    case 'pre-flight-failed': {
      return PeerHealth.FAILED;
    }

    // ─── relay-peer-online: weaker presence evidence ────────────────────────
    // OFFLINE -> UNKNOWN is the only forward transition. Per spec, relay's
    // "WS open" view does NOT prove the peer's app is responsive — promoting
    // straight to HEALTHY here is the false-positive that produces the
    // "says connected, nothing sends" symptom we are explicitly eliminating.
    // For all non-OFFLINE states we leave the existing state alone (don't
    // upgrade or downgrade on this weaker signal). FAILED in particular is
    // owned by the recovery ladder, not by relay presence events.
    case 'relay-peer-online': {
      if (state === PeerHealth.OFFLINE) return PeerHealth.UNKNOWN;
      return state;
    }

    // ─── relay-peer-offline: peer's WS is closed ────────────────────────────
    case 'relay-peer-offline': {
      return PeerHealth.OFFLINE;
    }

    // ─── recovery-succeeded: drop to UNKNOWN, await next ping/frame ─────────
    // Recovery operates on a FAILED peer; succeeding moves us to UNKNOWN so
    // the next strong signal (pong/frame/send) promotes to HEALTHY. Outside
    // of FAILED this event is informational and a no-op.
    case 'recovery-succeeded': {
      if (state === PeerHealth.FAILED) return PeerHealth.UNKNOWN;
      return state;
    }

    // ─── recovery-given-up: terminal FAILED ─────────────────────────────────
    // Stays in FAILED (UI surfaces it; user takes manual action). Outside of
    // FAILED this is a no-op.
    case 'recovery-given-up': {
      return state;
    }

    // ─── unknown / malformed: no-op, do not throw ───────────────────────────
    default:
      return state;
  }
}
