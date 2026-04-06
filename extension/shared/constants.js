/**
 * constants.js — Shared configuration constants for the Beam Chrome extension.
 *
 * Centralises every "magic number" and environment-specific URL so that
 * background.js, offscreen documents, and the popup all draw from a single
 * source of truth. Changing a value here propagates everywhere automatically.
 */

// ---------------------------------------------------------------------------
// Relay server URLs
// ---------------------------------------------------------------------------

/** Primary WebSocket relay endpoint. */
export const RELAY_URL = 'wss://zaptransfer-relay.fly.dev';

/** Fallback relay endpoint used when the primary is unreachable. */
export const RELAY_URL_BACKUP = 'wss://relay.zaptransfer.example.com';

// ---------------------------------------------------------------------------
// WebRTC ICE / STUN configuration
// ---------------------------------------------------------------------------

/**
 * STUN servers passed to RTCPeerConnection's `iceServers` option.
 * Using multiple providers improves reliability across networks.
 *
 * @type {RTCIceServer[]}
 */
export const STUN_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun.services.mozilla.com:3478' },
  { urls: 'stun:stun.cloudflare.com:3478' }
];

// ---------------------------------------------------------------------------
// Timing intervals (milliseconds)
// ---------------------------------------------------------------------------

/**
 * How often the service worker sends a keepalive ping to the relay.
 * Must be shorter than the server's idle-disconnect timeout (~30 s on Fly.io).
 */
export const KEEPALIVE_INTERVAL_MS = 25000;

/**
 * How often the offscreen WebRTC heartbeat fires to detect silent peer drops.
 * Slightly longer than KEEPALIVE so the two timers don't fire simultaneously.
 */
export const HEARTBEAT_INTERVAL_MS = 30000;

/**
 * Maximum time to wait for all ICE candidates to be gathered before sending
 * the offer. Prevents indefinite hangs on restrictive networks.
 */
export const ICE_GATHERING_TIMEOUT_MS = 5000;

/**
 * Maximum time to wait for ICE connectivity checks to complete after
 * exchanging offer/answer. Fail-fast to relay fallback if exceeded.
 */
export const ICE_CHECK_TIMEOUT_MS = 8000;

/**
 * How long the receiving side has to accept or reject an incoming transfer
 * before it is automatically cancelled. Shown as a countdown in the UI.
 */
export const ACCEPTANCE_TIMEOUT_MS = 60000;

// ---------------------------------------------------------------------------
// Adaptive chunking
// ---------------------------------------------------------------------------

/**
 * Available chunk sizes in bytes, ordered from smallest to largest.
 * The transfer engine picks a tier based on measured throughput and then
 * adjusts up or down to maximise utilisation without overflowing buffers.
 *
 * @type {number[]}
 */
export const CHUNK_TIERS = [8192, 16384, 32768, 65536, 131072, 262144, 524288];

/**
 * Index into CHUNK_TIERS to use when a transfer begins (64 KB).
 * Conservative start avoids large initial buffer bloat on slow links.
 */
export const DEFAULT_CHUNK_TIER = 3;

// ---------------------------------------------------------------------------
// Sliding-window flow control
// ---------------------------------------------------------------------------

/** Number of in-flight chunks allowed when a transfer starts. */
export const WINDOW_INITIAL = 4;

/** Floor on the congestion window — never drop below this. */
export const WINDOW_MIN = 2;

/**
 * Ceiling for direct (WebRTC DataChannel) transfers.
 * Higher ceiling is safe because DataChannel back-pressure is reliable.
 */
export const WINDOW_MAX_DIRECT = 64;

/**
 * Ceiling for relay (WebSocket) transfers.
 * Lower ceiling because relay bandwidth is shared and has higher latency.
 */
export const WINDOW_MAX_RELAY = 8;

// ---------------------------------------------------------------------------
// History limits
// ---------------------------------------------------------------------------

/** Maximum number of clipboard entries retained in extension storage. */
export const MAX_CLIPBOARD_HISTORY = 20;

/** Maximum number of completed/failed transfers shown in the popup. */
export const MAX_TRANSFER_HISTORY = 10;

// ---------------------------------------------------------------------------
// Reliability / resumption
// ---------------------------------------------------------------------------

/**
 * Persist a resumption checkpoint to storage every N chunks.
 * Lower values give finer resume granularity at the cost of more I/O.
 */
export const CHECKPOINT_INTERVAL_CHUNKS = 10;

// ---------------------------------------------------------------------------
// Back-pressure thresholds (bytes)
// ---------------------------------------------------------------------------

/**
 * Pause sending new chunks when the DataChannel's bufferedAmount exceeds
 * this value. Prevents memory exhaustion on the sender side.
 */
export const BACKPRESSURE_HIGH = 1048576; // 1 MiB

/**
 * Resume sending once bufferedAmount drops back below this value.
 * Hysteresis gap (HIGH - LOW = 512 KiB) avoids rapid pause/resume cycling.
 */
export const BACKPRESSURE_LOW = 524288; // 512 KiB
