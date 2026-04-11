// Beam E2E encryption — session registry and handshake state machine (Chrome).
//
// Owns the short-lived per-transfer cryptographic state. For each transferId
// we track a Session object through the states:
//
//   PENDING_INIT     — sender generated ephemerals, transfer-init dispatched
//   AWAITING_ACCEPT  — sender waiting for peer's transfer-accept
//   ACTIVE           — keys derived, encrypt/decrypt allowed
//   COMPLETING       — final chunk processed, ready to destroy
//   DESTROYED        — keys wiped, session removed from registry
//
// Timeouts:
//   * PENDING_INIT/AWAITING_ACCEPT → DESTROYED after HANDSHAKE_TIMEOUT_MS
//   * ACTIVE → DESTROYED after ACTIVE_INACTIVITY_MS of no encrypt/decrypt
//
// Rate limits:
//   * MAX_PENDING_PER_PEER active handshakes per peer deviceId
//   * MAX_GLOBAL_PER_SECOND handshakes accepted per rolling second
//
// Persistence (sender side only):
//   Sender's ephSk + salt + peerId are mirrored into chrome.storage.session
//   (memory-backed, not disk) keyed by transferId while state is PENDING_INIT
//   or AWAITING_ACCEPT. This lets us recover the ephemeral across a service-
//   worker restart that can happen any time during the handshake window.
//   The mirror is deleted as soon as we transition to ACTIVE or DESTROYED.
//
// This module is pure state — it does NOT send any messages. Callers wire
// the transitions to the relay WebSocket in background-relay.js.

import {
  PROTOCOL_VERSION,
  computeTripleDHInitiator,
  computeTripleDHResponder,
  computeTranscript,
  deriveSessionKey,
  deriveChunkKey,
  deriveMetaKey,
  generateEphemeral,
  wipe,
  toHex,
  fromHex,
} from './beam-crypto.js';

export const STATE = Object.freeze({
  PENDING_INIT: 'PENDING_INIT',
  AWAITING_ACCEPT: 'AWAITING_ACCEPT',
  ACTIVE: 'ACTIVE',
  COMPLETING: 'COMPLETING',
  DESTROYED: 'DESTROYED',
});

export const ERROR_CODES = Object.freeze({
  VERSION: 'VERSION',
  TIMEOUT: 'TIMEOUT',
  RATE_LIMIT: 'RATE_LIMIT',
  DECRYPT_FAIL: 'DECRYPT_FAIL',
  BAD_TRANSCRIPT: 'BAD_TRANSCRIPT',
  INTERNAL: 'INTERNAL',
  DUPLICATE: 'DUPLICATE',
});

/**
 * Canonical user-facing messages for every Beam error code.
 *
 * Keeping this table colocated with ERROR_CODES makes adding a new code a
 * single-file edit and prevents raw enum strings from ever reaching the UI.
 */
export const ERROR_MESSAGES = Object.freeze({
  VERSION:        'Peer is running an incompatible version. Update both devices.',
  TIMEOUT:        "Peer didn't respond in time. Make sure the other device is online.",
  RATE_LIMIT:     'Too many transfers in progress. Wait a moment and try again.',
  DECRYPT_FAIL:   'Decryption failed. The transfer was tampered with or the keys do not match.',
  BAD_TRANSCRIPT: 'Security check failed. The transfer was rejected.',
  INTERNAL:       'Something went wrong. Please try again.',
  DUPLICATE:      'Duplicate transfer detected. Wait a moment and try again.',
});

/**
 * Look up a user-facing error message for a Beam error code, with a
 * sensible fallback for unknown codes.
 */
export function beamErrorMessage(code) {
  return ERROR_MESSAGES[code] || ERROR_MESSAGES.INTERNAL;
}

// Tuning constants. Exported so tests can override via the factory function.
export const DEFAULTS = Object.freeze({
  HANDSHAKE_TIMEOUT_MS: 10_000,
  ACTIVE_INACTIVITY_MS: 60_000,
  SWEEP_INTERVAL_MS: 2_000,
  MAX_PENDING_PER_PEER: 5,
  MAX_GLOBAL_PER_SECOND: 20,
});

const STORAGE_PREFIX = 'beam:pending-hs:';

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function base64urlFromBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesFromBase64url(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i += 1) out[i] = b.charCodeAt(i);
  return out;
}

// 128-bit random transfer id, 16 raw bytes.
function newTransferId() {
  return randomBytes(16);
}

// ---------------------------------------------------------------------------
// SessionRegistry
// ---------------------------------------------------------------------------

export class SessionRegistry {
  constructor({
    ourStaticSk,
    ourStaticPk,
    options = DEFAULTS,
    now = () => Date.now(),
    storage = null, // { get, set, remove } — defaults to chrome.storage.session
  } = {}) {
    if (!ourStaticSk || ourStaticSk.byteLength !== 32) {
      throw new Error('SessionRegistry requires 32-byte ourStaticSk');
    }
    if (!ourStaticPk || ourStaticPk.byteLength !== 32) {
      throw new Error('SessionRegistry requires 32-byte ourStaticPk');
    }
    this._ourStaticSk = ourStaticSk;
    this._ourStaticPk = ourStaticPk;
    this._opt = { ...DEFAULTS, ...options };
    this._now = now;
    this._storage = storage || defaultSessionStorage();
    /** @type {Map<string, object>} transferIdHex → Session */
    this._sessions = new Map();
    this._recentTimestamps = []; // ring of acceptance times for global rate limit
    this._sweepTimer = null;
  }

  // -------------------------------------------------------------------------
  // Timer / sweep
  // -------------------------------------------------------------------------

  startSweep() {
    if (this._sweepTimer != null) return;
    this._sweepTimer = setInterval(() => this.sweep(), this._opt.SWEEP_INTERVAL_MS);
  }

  stopSweep() {
    if (this._sweepTimer != null) {
      clearInterval(this._sweepTimer);
      this._sweepTimer = null;
    }
  }

  /**
   * Reap expired sessions. Returns a promise that resolves once every
   * triggered destroy — including its async storage cleanup — has
   * completed. Callers in production can fire-and-forget the result
   * (setInterval), while tests should `await` it to observe a fully
   * settled registry.
   */
  sweep() {
    const t = this._now();
    const pending = [];
    for (const [idHex, s] of this._sessions.entries()) {
      let timeoutMs;
      if (s.state === STATE.PENDING_INIT || s.state === STATE.AWAITING_ACCEPT) {
        timeoutMs = this._opt.HANDSHAKE_TIMEOUT_MS;
      } else if (s.state === STATE.ACTIVE) {
        timeoutMs = this._opt.ACTIVE_INACTIVITY_MS;
      } else {
        continue;
      }
      const reference = s.state === STATE.ACTIVE ? s.lastActivity : s.createdAt;
      if (t - reference > timeoutMs) {
        pending.push(this._destroyByHex(idHex, ERROR_CODES.TIMEOUT));
      }
    }
    return Promise.all(pending);
  }

  // -------------------------------------------------------------------------
  // Rate limiting
  // -------------------------------------------------------------------------

  _countPendingForPeer(peerId) {
    let n = 0;
    for (const s of this._sessions.values()) {
      if (
        s.peerId === peerId &&
        (s.state === STATE.PENDING_INIT ||
          s.state === STATE.AWAITING_ACCEPT ||
          s.state === STATE.ACTIVE)
      ) {
        n += 1;
      }
    }
    return n;
  }

  _checkGlobalRate() {
    const t = this._now();
    const cutoff = t - 1000;
    // Trim old entries.
    while (this._recentTimestamps.length > 0 && this._recentTimestamps[0] < cutoff) {
      this._recentTimestamps.shift();
    }
    return this._recentTimestamps.length < this._opt.MAX_GLOBAL_PER_SECOND;
  }

  _recordGlobalRate() {
    this._recentTimestamps.push(this._now());
  }

  // -------------------------------------------------------------------------
  // Sender: startInit — generate ephemerals, mirror to session storage,
  // return the transfer-init payload for the caller to send.
  // -------------------------------------------------------------------------

  async startInit({ peerId, peerStaticPk, kind }) {
    if (!peerId) throw new Error('peerId required');
    if (!peerStaticPk || peerStaticPk.byteLength !== 32) {
      throw new Error('peerStaticPk must be 32 bytes');
    }
    if (kind !== 'clipboard' && kind !== 'file') {
      throw new Error(`kind must be 'clipboard' or 'file', got ${kind}`);
    }
    if (!this._checkGlobalRate()) {
      const err = new Error('global handshake rate limit exceeded');
      err.code = ERROR_CODES.RATE_LIMIT;
      throw err;
    }
    if (this._countPendingForPeer(peerId) >= this._opt.MAX_PENDING_PER_PEER) {
      const err = new Error('per-peer pending handshake limit exceeded');
      err.code = ERROR_CODES.RATE_LIMIT;
      throw err;
    }

    const transferId = newTransferId();
    const transferIdHex = toHex(transferId);
    const salt = randomBytes(32);
    const { sk: ephSk, pk: ephPk } = await generateEphemeral();

    const session = {
      transferId,
      transferIdHex,
      peerId,
      peerStaticPk,
      kind,
      role: 'initiator',
      state: STATE.PENDING_INIT,
      createdAt: this._now(),
      lastActivity: this._now(),
      version: PROTOCOL_VERSION,
      ephSk,
      ephPk,
      salt,
      peerEphPk: null,
      transcript: null,
      sessionKey: null,
      chunkKey: null,
      metaKey: null,
      totalChunks: 0,
    };
    this._sessions.set(transferIdHex, session);
    this._recordGlobalRate();

    // Mirror to chrome.storage.session so the handshake survives SW restarts.
    await this._storage.set(STORAGE_PREFIX + transferIdHex, {
      peerId,
      peerStaticPkHex: toHex(peerStaticPk),
      kind,
      saltHex: toHex(salt),
      ephSkHex: toHex(ephSk),
      ephPkHex: toHex(ephPk),
      createdAt: session.createdAt,
    });

    session.state = STATE.AWAITING_ACCEPT;

    return {
      transferId,
      transferIdHex,
      wireMessage: {
        type: 'transfer-init',
        v: PROTOCOL_VERSION,
        transferId: base64urlFromBytes(transferId),
        kind,
        ephPkA: base64urlFromBytes(ephPk),
        salt: base64urlFromBytes(salt),
      },
    };
  }

  // -------------------------------------------------------------------------
  // Sender: onAccept — peer sent us transfer-accept, finish derivation and
  // transition to ACTIVE. Returns the active session (callers should not
  // read crypto material directly — use encrypt/decrypt wrappers).
  // -------------------------------------------------------------------------

  async onAccept({ peerId, wireMessage, ourStaticPk = this._ourStaticPk }) {
    const transferId = bytesFromBase64url(wireMessage.transferId);
    const transferIdHex = toHex(transferId);
    const s = this._sessions.get(transferIdHex);
    if (!s) {
      const err = new Error('no session for transferId');
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }
    if (s.peerId !== peerId) {
      const err = new Error('peer mismatch on transfer-accept');
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }
    if (s.state !== STATE.AWAITING_ACCEPT) {
      const err = new Error(`unexpected state ${s.state} for transfer-accept`);
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }

    const peerEphPk = bytesFromBase64url(wireMessage.ephPkB);
    if (peerEphPk.byteLength !== 32) {
      const err = new Error('ephPkB must be 32 bytes');
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }
    s.peerEphPk = peerEphPk;

    const { ikm } = await computeTripleDHInitiator({
      staticSkA: this._ourStaticSk,
      ephSkA: s.ephSk,
      staticPkB: s.peerStaticPk,
      ephPkB: peerEphPk,
    });

    const transcript = await computeTranscript({
      version: s.version,
      staticPkA: ourStaticPk,
      staticPkB: s.peerStaticPk,
      ephPkA: s.ephPk,
      ephPkB: peerEphPk,
      transferId: s.transferId,
    });

    const sessionKey = await deriveSessionKey({ ikm, salt: s.salt, transcript });
    const chunkKey = await deriveChunkKey(sessionKey);
    const metaKey = await deriveMetaKey(sessionKey);

    // Best-effort wipe of ephemerals and ikm — not the session key, we still need it.
    await wipe(s.ephSk, ikm);
    s.ephSk = null;

    s.transcript = transcript;
    s.sessionKey = sessionKey;
    s.chunkKey = chunkKey;
    s.metaKey = metaKey;
    s.state = STATE.ACTIVE;
    s.lastActivity = this._now();

    await this._storage.remove(STORAGE_PREFIX + transferIdHex);

    return s;
  }

  // -------------------------------------------------------------------------
  // Receiver: onInit — peer sent us transfer-init, generate our ephemeral,
  // derive keys immediately, transition directly to ACTIVE. Returns:
  //   { session, wireMessage }  — caller sends wireMessage (transfer-accept)
  // -------------------------------------------------------------------------

  async onInit({ peerId, peerStaticPk, wireMessage, ourStaticPk = this._ourStaticPk }) {
    if (!peerId) throw new Error('peerId required');
    if (!peerStaticPk || peerStaticPk.byteLength !== 32) {
      throw new Error('peerStaticPk must be 32 bytes');
    }
    if (wireMessage.v !== PROTOCOL_VERSION) {
      const err = new Error(`unsupported version ${wireMessage.v}`);
      err.code = ERROR_CODES.VERSION;
      throw err;
    }
    if (wireMessage.kind !== 'clipboard' && wireMessage.kind !== 'file') {
      const err = new Error(`invalid kind ${wireMessage.kind}`);
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }
    if (!this._checkGlobalRate()) {
      const err = new Error('global handshake rate limit exceeded');
      err.code = ERROR_CODES.RATE_LIMIT;
      throw err;
    }
    if (this._countPendingForPeer(peerId) >= this._opt.MAX_PENDING_PER_PEER) {
      const err = new Error('per-peer pending handshake limit exceeded');
      err.code = ERROR_CODES.RATE_LIMIT;
      throw err;
    }

    const transferId = bytesFromBase64url(wireMessage.transferId);
    if (transferId.byteLength !== 16) {
      const err = new Error('transferId must be 16 bytes');
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }
    const transferIdHex = toHex(transferId);
    if (this._sessions.has(transferIdHex)) {
      const err = new Error('duplicate transferId');
      err.code = ERROR_CODES.DUPLICATE;
      throw err;
    }

    const peerEphPk = bytesFromBase64url(wireMessage.ephPkA);
    const salt = bytesFromBase64url(wireMessage.salt);
    if (peerEphPk.byteLength !== 32) {
      const err = new Error('ephPkA must be 32 bytes');
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }
    if (salt.byteLength !== 32) {
      const err = new Error('salt must be 32 bytes');
      err.code = ERROR_CODES.INTERNAL;
      throw err;
    }

    const { sk: ephSk, pk: ephPk } = await generateEphemeral();

    const { ikm } = await computeTripleDHResponder({
      staticSkB: this._ourStaticSk,
      ephSkB: ephSk,
      staticPkA: peerStaticPk,
      ephPkA: peerEphPk,
    });

    // Transcript is computed from the initiator's perspective — A is the
    // party that started the handshake, B is us.
    const transcript = await computeTranscript({
      version: wireMessage.v,
      staticPkA: peerStaticPk,
      staticPkB: ourStaticPk,
      ephPkA: peerEphPk,
      ephPkB: ephPk,
      transferId,
    });

    const sessionKey = await deriveSessionKey({ ikm, salt, transcript });
    const chunkKey = await deriveChunkKey(sessionKey);
    const metaKey = await deriveMetaKey(sessionKey);

    await wipe(ephSk, ikm);

    const session = {
      transferId,
      transferIdHex,
      peerId,
      peerStaticPk,
      kind: wireMessage.kind,
      role: 'responder',
      state: STATE.ACTIVE,
      createdAt: this._now(),
      lastActivity: this._now(),
      version: wireMessage.v,
      ephSk: null,
      ephPk,
      salt,
      peerEphPk,
      transcript,
      sessionKey,
      chunkKey,
      metaKey,
      totalChunks: 0,
      chunksReceived: 0,
    };
    this._sessions.set(transferIdHex, session);
    this._recordGlobalRate();

    return {
      session,
      wireMessage: {
        type: 'transfer-accept',
        v: PROTOCOL_VERSION,
        transferId: wireMessage.transferId,
        ephPkB: base64urlFromBytes(ephPk),
      },
    };
  }

  // -------------------------------------------------------------------------
  // Lookups and lifecycle
  // -------------------------------------------------------------------------

  getByTransferId(transferId) {
    const hex = toHex(transferId);
    return this._sessions.get(hex) || null;
  }

  getByTransferIdB64(b64) {
    return this._sessions.get(toHex(bytesFromBase64url(b64))) || null;
  }

  touch(session) {
    if (!session) return;
    session.lastActivity = this._now();
  }

  async destroy(transferId, reason = ERROR_CODES.INTERNAL) {
    if (transferId instanceof Uint8Array) {
      return this._destroyByHex(toHex(transferId), reason);
    }
    return this._destroyByHex(transferId, reason);
  }

  async _destroyByHex(transferIdHex, reason) {
    const s = this._sessions.get(transferIdHex);
    if (!s) return;
    // Synchronous bookkeeping FIRST so callers that check size()/lookups
    // immediately after sweep() see the deletion without awaiting the
    // async wipe + storage removal below. This matters because sweep()
    // is a plain (non-async) method — it fires-and-forgets destroy calls.
    this._sessions.delete(transferIdHex);
    s.state = STATE.DESTROYED;
    s.destroyReason = reason;
    const toWipe = [s.sessionKey, s.chunkKey, s.metaKey, s.ephSk];
    s.sessionKey = null;
    s.chunkKey = null;
    s.metaKey = null;
    s.ephSk = null;
    // Async best-effort cleanup. Failures here are non-fatal because the
    // session is already considered destroyed from the caller's perspective.
    try {
      await wipe(...toWipe);
    } catch (_) {
      /* ignore wipe errors */
    }
    try {
      await this._storage.remove(STORAGE_PREFIX + transferIdHex);
    } catch (_) {
      /* ignore storage errors */
    }
  }

  size() {
    return this._sessions.size;
  }

  /** For tests and debugging only — do not expose crypto material in UI. */
  _debugSnapshot() {
    return Array.from(this._sessions.entries()).map(([id, s]) => ({
      id,
      state: s.state,
      role: s.role,
      kind: s.kind,
      peerId: s.peerId,
      createdAt: s.createdAt,
    }));
  }
}

// ---------------------------------------------------------------------------
// Default session storage wrapper over chrome.storage.session.
// Falls back to a Map when chrome.storage isn't available (tests).
// ---------------------------------------------------------------------------

function defaultSessionStorage() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    return {
      async get(key) {
        const res = await chrome.storage.session.get(key);
        return res[key];
      },
      async set(key, value) {
        await chrome.storage.session.set({ [key]: value });
      },
      async remove(key) {
        await chrome.storage.session.remove(key);
      },
    };
  }
  const m = new Map();
  return {
    async get(key) { return m.get(key); },
    async set(key, value) { m.set(key, value); },
    async remove(key) { m.delete(key); },
  };
}

// ---------------------------------------------------------------------------
// Rehydration of pending handshakes after SW wake.
// Call once at startup with your registry and the peer static key resolver.
// ---------------------------------------------------------------------------

export async function rehydratePendingHandshakes({
  registry,
  peerStaticPkResolver, // (peerId) => Uint8Array | null
  storage = defaultSessionStorage(),
  now = Date.now,
  clock = null, // optional injection for tests
}) {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) {
    return 0;
  }
  const all = await chrome.storage.session.get(null);
  let recovered = 0;
  for (const [key, value] of Object.entries(all)) {
    if (!key.startsWith(STORAGE_PREFIX)) continue;
    const transferIdHex = key.slice(STORAGE_PREFIX.length);
    // Age out anything older than the handshake timeout.
    const age = (clock ? clock() : now()) - (value.createdAt || 0);
    if (age > registry._opt.HANDSHAKE_TIMEOUT_MS) {
      await storage.remove(key);
      continue;
    }
    const peerStaticPk = peerStaticPkResolver(value.peerId);
    if (!peerStaticPk) {
      await storage.remove(key);
      continue;
    }
    const transferId = fromHex(transferIdHex);
    const ephSk = fromHex(value.ephSkHex);
    const ephPk = fromHex(value.ephPkHex);
    const salt = fromHex(value.saltHex);
    registry._sessions.set(transferIdHex, {
      transferId,
      transferIdHex,
      peerId: value.peerId,
      peerStaticPk,
      kind: value.kind,
      role: 'initiator',
      state: STATE.AWAITING_ACCEPT,
      createdAt: value.createdAt,
      lastActivity: value.createdAt,
      version: PROTOCOL_VERSION,
      ephSk,
      ephPk,
      salt,
      peerEphPk: null,
      transcript: null,
      sessionKey: null,
      chunkKey: null,
      metaKey: null,
      totalChunks: 0,
    });
    recovered += 1;
  }
  return recovered;
}
