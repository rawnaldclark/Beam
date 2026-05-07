package com.zaptransfer.android.connection

/**
 * Shared timing constants for the Connection Authority.
 *
 * Android mirror of `extension/connection/constants.js`. Centralizing these in
 * one file keeps the cadence engine, recovery ladder, and tests aligned on a
 * single source of truth — any change here MUST be paired with the
 * JS counterpart so the two platforms stay lock-step. The spec
 * (`docs/superpowers/specs/2026-05-02-connection-authority-design.md`,
 * §"Wire protocol — peer-ping" cadence section) drives both numbers.
 *
 * Why a top-level file instead of a companion object on a particular class:
 * the cadence engine (Task 16), recovery ladder (Task 17), and ensureSendable
 * pre-flight (Task 18) all consume different subsets of these. Hanging the
 * constants off any one of those classes would either force the others to
 * import that class for unrelated reasons, or require duplicating values —
 * exactly the desync risk we are avoiding.
 */

/**
 * Background peer-ping cadence interval, in milliseconds.
 *
 * Per spec, the authority sends a peer-ping every 120s per online peer once
 * `lastActivityAt + BG_PING_INTERVAL_MS` elapses. Combined with the 10s
 * timeout below, a fully-failed peer is detected within
 * `(120s + 10s) × 2 = 260s`, which the spec budgets as
 * "absorbs single-packet loss without flickering UI".
 *
 * The cadence is computed from `lastActivityAt + BG_PING_INTERVAL_MS`, NOT as
 * a steady tick from peer-add — recent inbound frames or successful sends
 * push the next ping forward (see `RECENT_TRAFFIC_WINDOW_MS`).
 */
const val BG_PING_INTERVAL_MS: Long = 120_000L

/**
 * Per-ping deadline, in milliseconds.
 *
 * If no peer-pong arrives within this window after a peer-ping is sent, the
 * cadence engine dispatches `PingMissed` for the peer and the reducer
 * escalates UNKNOWN/HEALTHY -> STALE -> FAILED on two consecutive misses.
 *
 * Forwarded to the [PeerPingTracker] via the authority's construction path.
 */
const val PING_TIMEOUT_MS: Long = 10_000L

/**
 * Recent-traffic skip window for `ensureSendable` pre-flight, in milliseconds.
 *
 * When the send-path calls `ensureSendable`, if `peerHealth === HEALTHY` AND
 * the peer's `lastActivityAt` is within this window, the pre-flight returns
 * `Ok` immediately without issuing a fresh peer-ping — recent inbound /
 * outbound traffic is sufficient proof-of-life for the upcoming send. Spec
 * §"Send-time pre-flight"; consumed by Task 18.
 *
 * NOT consumed by the background cadence engine (Task 16). Cadence
 * unconditionally pushes the next ping out by `BG_PING_INTERVAL_MS` on any
 * activity — this 30s window only governs the send-path skip.
 */
@Suppress("unused") // Defined now for cross-platform parity; Task 18 wires the consumer.
const val RECENT_TRAFFIC_WINDOW_MS: Long = 30_000L
