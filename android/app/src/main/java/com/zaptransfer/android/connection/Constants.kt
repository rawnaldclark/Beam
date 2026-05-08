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
const val RECENT_TRAFFIC_WINDOW_MS: Long = 30_000L

/**
 * Per-probe deadline for the send-time pre-flight peer-ping, in milliseconds.
 *
 * `ensureSendable` races a 5s timer against the [PeerPingTracker]'s own (10s)
 * timeout. We use the shorter window because pre-flight is on the user's
 * critical send path — a 5s skid before failing over to the recovery ladder
 * is the spec budget; the tracker's longer cadence-engine timeout doesn't
 * apply here. (The tracker's deferred is still safe to await in parallel:
 * whichever lands first wins, and a late tracker resolution after our timer
 * has fired is harmless.)
 *
 * Mirrors `PRE_FLIGHT_PING_TIMEOUT_MS` in `extension/connection/connection-authority.js`.
 * Spec: §"Send-time pre-flight" step 3a.
 */
const val PRE_FLIGHT_PING_TIMEOUT_MS: Long = 5_000L

/**
 * Recovery ladder Rung 1 budget, in milliseconds.
 *
 * Rung 1 ("re-register rendezvous") dispatches a `register-rendezvous` frame
 * over the existing WebSocket and waits up to this budget for the peer to
 * become healthy again (peer-trigger) or for self+any-peer to become healthy
 * (self-trigger). 5s is short enough that a clean `peer-failed` -> `frame-
 * received` round-trip via the relay completes well before timeout, and
 * short enough that an unrecoverable peer doesn't delay Rung 2's WS rebuild.
 *
 * Mirrors `RUNG_1_BUDGET_MS` in `extension/connection/constants.js`.
 */
const val RUNG_1_BUDGET_MS: Long = 5_000L

/**
 * Recovery ladder Rung 2 budget, in milliseconds.
 *
 * Rung 2 ("WebSocket reconnect") tears down the WS via
 * [com.zaptransfer.android.webrtc.SignalingClient.disconnect] +
 * [com.zaptransfer.android.webrtc.SignalingClient.connect] and waits up to
 * this budget for self to return to ONLINE AND any paired peer to become
 * HEALTHY. 15s is the spec budget — long enough to absorb a typical OS-
 * level network handover (wifi <-> mobile) plus the relay's auth round-trip,
 * short enough that an unrecoverable transport doesn't delay surrender.
 *
 * Mirrors `RUNG_2_BUDGET_MS` in `extension/connection/constants.js`.
 */
const val RUNG_2_BUDGET_MS: Long = 15_000L
