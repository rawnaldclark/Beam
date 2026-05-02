/**
 * @file constants.js
 * @description Shared timing constants for the Connection Authority.
 *
 * Centralizing these in one module keeps the cadence engine, recovery ladder,
 * and tests aligned on a single source of truth. The Android side mirrors
 * these in `connection/Constants.kt` (Tasks 13+); changing a number here
 * should be paired with the Kotlin counterpart so the two platforms stay in
 * lock-step.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 *       §"Wire protocol — peer-ping" cadence section.
 */

/**
 * Background peer-ping cadence.
 *
 * Per spec, the authority sends a peer-ping every 120s per online peer. This
 * is the steady-state liveness probe — combined with the 10s timeout below,
 * a fully-failed peer is detected within (120s + 10s) × 2 = 260s, which the
 * spec budgets as "absorbs single-packet loss without flickering UI."
 *
 * The cadence is computed from `lastActivityAt + BG_PING_INTERVAL_MS`, not as
 * a steady tick from peer-add — recent inbound frames or successful sends
 * push the next ping forward (see RECENT_TRAFFIC_WINDOW_MS).
 */
export const BG_PING_INTERVAL_MS = 120_000;

/**
 * Per-ping deadline. If no peer-pong arrives within this window after a
 * peer-ping is sent, the cadence engine dispatches `ping-missed` for the
 * peer and the reducer escalates UNKNOWN/HEALTHY → STALE → FAILED.
 *
 * Forwarded to the PeerPingTracker via the authority's options.
 */
export const PING_TIMEOUT_MS = 10_000;

/**
 * Recent-traffic skip window for `ensureSendable` pre-flight (Task 9).
 *
 * When the send-path calls `ensureSendable`, if `peerHealth === HEALTHY`
 * AND the peer's `lastActivityAt` is within this window, the pre-flight
 * returns `{ok: true}` immediately without issuing a fresh peer-ping —
 * recent inbound/outbound traffic is sufficient proof-of-life for the
 * upcoming send. Spec §"Send-time pre-flight"; plan Task 9 Step 1.
 *
 * NOT consumed by the background cadence engine (Task 7). Cadence
 * unconditionally pushes the next ping out by `BG_PING_INTERVAL_MS` on
 * any activity — this 30s window only governs the send-path skip.
 */
export const RECENT_TRAFFIC_WINDOW_MS = 30_000;

// ─── Recovery ladder budgets (consumed in Task 8+) ──────────────────────────
//
// Per-rung total time budget before the ladder gives up on that rung and
// advances. Defined here so Task 8/11 can wire them without re-deriving
// values from the spec.

/** Rung 1 (in-place reauth) total budget. */
export const RUNG_1_BUDGET_MS = 5_000;
/** Rung 2 (WS reconnect) total budget. */
export const RUNG_2_BUDGET_MS = 15_000;
/** Rung 3 (full transport reset) total budget. */
export const RUNG_3_BUDGET_MS = 30_000;

/**
 * Rung 4 backoff schedule (consumed in Task 11). Each entry is the wait
 * before the next outermost retry attempt, in ms: 30s → 2m → 10m → 30m.
 */
export const BACKOFF_SCHEDULE_MS = [30_000, 120_000, 600_000, 1_800_000];
