/**
 * @file peer-ping.js
 * @description Pure module owning the peer-ping/pong protocol.
 *
 * Responsibilities:
 *   - Generate outbound peer-ping JSON messages with fresh random nonces.
 *   - Track in-flight pings (nonce → {sentAt, deadline, peerId, resolve, reject}).
 *   - Resolve matching pings on pong receipt (recordPong).
 *   - Reject and remove timed-out pings on sweep (sweepExpired).
 *
 * No timers, no WebSocket, no globals beyond crypto.getRandomValues.
 * Caller injects sendJson; caller drives the sweep tick.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/**
 * Encode a Uint8Array to base64url without padding.
 * Pattern mirrors beam-v2-transport.js#b64urlFromBytes.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function b64urlFromBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Generate a cryptographically random 16-byte nonce, b64url-encoded, no padding.
 * Result is always 22 characters.
 * @returns {string}
 */
function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return b64urlFromBytes(bytes);
}

// ---------------------------------------------------------------------------
// PeerPingTracker
// ---------------------------------------------------------------------------

/**
 * Tracks outbound peer-ping messages and resolves/rejects their promises
 * when pongs arrive or deadlines pass.
 *
 * @example
 * const tracker = new PeerPingTracker({ sendJson, timeoutMs: 5000 });
 * const { nonce, promise } = tracker.sendPing(peerId);
 * // ... later, on pong message:
 * tracker.recordPong(nonce);
 * // ... on timer tick:
 * const expired = tracker.sweepExpired(Date.now());
 */
export class PeerPingTracker {
  /**
   * @param {object} opts
   * @param {(msg: object) => void} opts.sendJson   Caller-injected send function.
   * @param {number}               opts.timeoutMs  Milliseconds before a ping times out.
   */
  constructor({ sendJson, timeoutMs }) {
    this._sendJson = sendJson;
    this._timeoutMs = timeoutMs;
    /** @type {Map<string, {sentAt:number, deadline:number, peerId:string, resolve:Function, reject:Function}>} */
    this._pending = new Map();
  }

  /**
   * Send a peer-ping to `peerId` and return the nonce and a promise that
   * settles when the pong arrives or the deadline is swept.
   *
   * @param {string} peerId  The device ID to ping (used as both targetDeviceId and rendezvousId).
   * @param {number} [now]   Optional fake-clock timestamp (defaults to Date.now()).
   * @returns {{ nonce: string, promise: Promise<{ok:true, rttMs:number}> }}
   */
  sendPing(peerId, now = Date.now()) {
    const nonce = generateNonce();
    const sentAt = now;
    const deadline = sentAt + this._timeoutMs;

    let resolve, reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });

    this._pending.set(nonce, { sentAt, deadline, peerId, resolve, reject });

    this._sendJson({
      type: 'peer-ping',
      nonce,
      targetDeviceId: peerId,
      rendezvousId: peerId,
    });

    return { nonce, promise };
  }

  /**
   * Record an incoming pong. Resolves the matching pending ping's promise
   * with `{ok:true, rttMs}`. If the nonce is unknown, this is a no-op.
   *
   * @param {string} nonce  The nonce echoed by the peer.
   * @param {number} [now]  Optional fake-clock timestamp (defaults to Date.now()).
   */
  recordPong(nonce, now = Date.now()) {
    const entry = this._pending.get(nonce);
    if (!entry) return;
    this._pending.delete(nonce);
    entry.resolve({ ok: true, rttMs: now - entry.sentAt });
  }

  /**
   * Sweep the pending map for entries whose deadline has passed.
   * Each expired entry has its promise rejected with `{ok:false, reason:"timeout"}`
   * and is removed from the map.
   *
   * @param {number} [now]  Current time; defaults to Date.now().
   * @returns {Array<{nonce:string, peerId:string}>}  Expired entries, for caller event dispatch.
   */
  sweepExpired(now = Date.now()) {
    const expired = [];
    for (const [nonce, entry] of this._pending) {
      if (now >= entry.deadline) {
        this._pending.delete(nonce);
        entry.reject({ ok: false, reason: 'timeout' });
        expired.push({ nonce, peerId: entry.peerId });
      }
    }
    return expired;
  }
}
