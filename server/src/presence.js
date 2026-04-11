/**
 * presence.js — Device online/offline tracking with heartbeat and rendezvous.
 *
 * Tracks which devices are connected and which rendezvous IDs they share.
 * When a device registers or unregisters, all peers sharing a rendezvous ID
 * are notified via PEER_ONLINE / PEER_OFFLINE messages through the gateway.
 *
 * Heartbeat model:
 *   - Clients are expected to send a ping every ~30 seconds.
 *   - The gateway calls heartbeat(deviceId) on each incoming message.
 *   - startSilenceChecker() runs a periodic sweep; any device whose lastSeen
 *     exceeds silenceTimeoutMs is unregistered (treated as offline).
 *
 * Rendezvous model:
 *   - Each device may claim one or more rendezvous IDs (e.g. a shared secret
 *     derived from a file hash or pairing code).
 *   - Two devices sharing a rendezvous ID are "peers" and receive mutual
 *     presence notifications.
 *
 * @module presence
 */

import { MSG } from './protocol.js';

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/** Default silence timeout in milliseconds (90 seconds). */
const DEFAULT_SILENCE_TIMEOUT_MS = 90_000;

/** Default sweep interval for the silence checker in milliseconds. */
const DEFAULT_CHECK_INTERVAL_MS = 30_000;

/**
 * Default reconnect grace period in milliseconds.
 *
 * When `unregister(deviceId)` is called (typically from a WebSocket close),
 * the device is not immediately torn down. Instead a timer fires PEER_OFFLINE
 * to peers after this delay. If `register(deviceId)` is called again within
 * the window with the same rendezvous IDs — which is what happens on a
 * normal reconnect — the pending teardown is cancelled and peers never see
 * any offline/online flap.
 *
 * Tuned high enough to absorb a typical reconnect (2s client backoff +
 * handshake round-trip) and low enough that a real disconnect is visible
 * to the user within a human timescale.
 */
const DEFAULT_RECONNECT_GRACE_MS = 3_000;

// ---------------------------------------------------------------------------
// Presence class
// ---------------------------------------------------------------------------

/**
 * Manages device presence and peer-notification for the relay server.
 *
 * @example
 * const presence = new Presence({ gateway });
 * presence.startSilenceChecker();
 *
 * // After a device authenticates:
 * presence.register(deviceId, ['rendezvous-id-1', 'rendezvous-id-2']);
 *
 * // On every inbound message (heartbeat):
 * presence.heartbeat(deviceId);
 *
 * // On disconnect (or called by the silence checker):
 * presence.unregister(deviceId);
 */
export class Presence {
  /**
   * @param {object} opts
   * @param {object}  opts.gateway            - Gateway instance (or compatible mock)
   * @param {number} [opts.silenceTimeoutMs]  - Ms of silence before a device is considered offline
   * @param {number} [opts.checkIntervalMs]   - How often to sweep for stale devices
   */
  constructor({
    gateway,
    silenceTimeoutMs = DEFAULT_SILENCE_TIMEOUT_MS,
    checkIntervalMs = DEFAULT_CHECK_INTERVAL_MS,
    reconnectGraceMs = DEFAULT_RECONNECT_GRACE_MS,
  } = {}) {
    /**
     * The gateway used to send PEER_ONLINE/PEER_OFFLINE messages.
     * @type {object}
     */
    this._gateway = gateway;

    /**
     * Per-device state: deviceId → { rendezvousIds: string[], lastSeen: number }
     * @type {Map<string, { rendezvousIds: string[], lastSeen: number }>}
     */
    this._devices = new Map();

    /**
     * Rendezvous index: rendezvousId → Set<deviceId>
     * @type {Map<string, Set<string>>}
     */
    this._rendezvous = new Map();

    /** Silence timeout configuration in milliseconds. @type {number} */
    this._silenceTimeoutMs = silenceTimeoutMs;

    /** Sweep interval in milliseconds. @type {number} */
    this._checkIntervalMs = checkIntervalMs;

    /** Reconnect grace period in milliseconds. @type {number} */
    this._reconnectGraceMs = reconnectGraceMs;

    /** Handle returned by setInterval, if the silence checker is running. @type {NodeJS.Timeout|null} */
    this._silenceTimer = null;

    /**
     * Pending teardowns keyed by deviceId. Each entry holds the timer that
     * will finalize the offline transition and the snapshot of peers that
     * should be notified when it fires. Cleared on successful reconnect
     * inside the grace window.
     *
     * @type {Map<string, { timer: NodeJS.Timeout, peers: Set<string> }>}
     */
    this._pendingOffline = new Map();

    // Wire into gateway disconnect events so devices are cleaned up when
    // their WebSocket closes (complements the silence checker for immediate cleanup).
    if (gateway && typeof gateway.on === 'function') {
      gateway.on('disconnect', (deviceId) => {
        if (this._devices.has(deviceId)) {
          this.unregister(deviceId);
        }
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Registers a device with the given rendezvous IDs.
   *
   * If the device was previously registered with different rendezvous IDs,
   * the old registrations are removed first: peers that are only on the dropped
   * rendezvous IDs receive PEER_OFFLINE, and peers on the new IDs receive
   * PEER_ONLINE. The registering device receives PEER_ONLINE for all peers
   * already on the new rendezvous IDs.
   *
   * @param {string}   deviceId      - Unique device identifier
   * @param {string[]} rendezvousIds - One or more rendezvous ID strings
   */
  register(deviceId, rendezvousIds) {
    // ─── Reconnect grace cancellation ──────────────────────────────────
    // If this device is mid-teardown, the new register is a reconnect
    // inside the grace window. Cancel the pending PEER_OFFLINE — peers
    // never saw us go offline, so they also don't need a PEER_ONLINE.
    //
    // Only applies when the rendezvous IDs are unchanged. If they differ,
    // we fire the deferred offline immediately and fall through to a
    // clean full registration below.
    const pending = this._pendingOffline.get(deviceId);
    if (pending) {
      const existing = this._devices.get(deviceId);
      const sameIds =
        existing &&
        existing.rendezvousIds.length === rendezvousIds.length &&
        existing.rendezvousIds.every((id) => rendezvousIds.includes(id));

      clearTimeout(pending.timer);
      this._pendingOffline.delete(deviceId);

      if (sameIds && existing) {
        // Smooth reconnect: bump lastSeen and quietly return.
        existing.lastSeen = Date.now();
        return;
      }

      // Rendezvous IDs changed during the grace window — fire the deferred
      // offline now so old peers see us leave cleanly, then fall through
      // to the normal registration path to rebuild state from scratch.
      for (const peerId of pending.peers) {
        this._gateway.send(peerId, { type: MSG.PEER_OFFLINE, deviceId });
      }
      if (existing) {
        this._removeFromRendezvous(deviceId);
        this._devices.delete(deviceId);
      }
    }

    if (this._devices.has(deviceId)) {
      // --- Re-registration: compute peer diff before modifying maps ---

      // Peers on the OLD rendezvous IDs (before removal)
      const oldState = this._devices.get(deviceId);
      const oldPeers = this._collectPeers(deviceId, oldState.rendezvousIds);

      // Remove device from old rendezvous sets (does not delete from _devices yet)
      this._removeFromRendezvous(deviceId);

      // Peers on the NEW rendezvous IDs (before adding device)
      // Note: device is not in the sets yet, so _collectPeers gives us the
      // existing occupants of the new rendezvous IDs.
      const newPeers = this._collectPeers(deviceId, rendezvousIds);

      // Update device state to new rendezvous IDs
      this._devices.set(deviceId, {
        rendezvousIds: [...rendezvousIds],
        lastSeen: Date.now(),
      });

      // Add device to each new rendezvous set
      for (const rvId of rendezvousIds) {
        if (!this._rendezvous.has(rvId)) {
          this._rendezvous.set(rvId, new Set());
        }
        this._rendezvous.get(rvId).add(deviceId);
      }

      // Notify peers that are no longer shared (left behind) — PEER_OFFLINE
      for (const peerId of oldPeers) {
        if (!newPeers.has(peerId)) {
          this._gateway.send(peerId, { type: MSG.PEER_OFFLINE, deviceId });
        }
      }

      // Bidirectional PEER_ONLINE for genuinely new peers
      for (const peerId of newPeers) {
        this._gateway.send(peerId, { type: MSG.PEER_ONLINE, deviceId });
        this._gateway.send(deviceId, { type: MSG.PEER_ONLINE, deviceId: peerId });
      }

      return;
    }

    // --- First-time registration ---

    // Record device state with a fresh lastSeen timestamp
    this._devices.set(deviceId, {
      rendezvousIds: [...rendezvousIds],
      lastSeen: Date.now(),
    });

    // Collect the union of all peers already present on the new rendezvous IDs
    // (before we add the registering device to the sets, so we don't self-notify).
    const existingPeers = this._collectPeers(deviceId, rendezvousIds);

    // Add device to each rendezvous set
    for (const rvId of rendezvousIds) {
      if (!this._rendezvous.has(rvId)) {
        this._rendezvous.set(rvId, new Set());
      }
      this._rendezvous.get(rvId).add(deviceId);
    }

    // Bidirectional notification:
    //   - Notify each existing peer that deviceId is now online
    //   - Notify deviceId about each existing peer that is already online
    for (const peerId of existingPeers) {
      this._gateway.send(peerId, { type: MSG.PEER_ONLINE, deviceId });
      this._gateway.send(deviceId, { type: MSG.PEER_ONLINE, deviceId: peerId });
    }
  }

  /**
   * Unregisters a device, removing it from all rendezvous sets and notifying
   * every peer it was sharing a rendezvous ID with.
   *
   * Safe to call on a device that is not currently registered (no-op).
   *
   * @param {string} deviceId
   */
  unregister(deviceId) {
    if (!this._devices.has(deviceId)) return;

    // If a teardown is already pending, leave it in place — the original
    // unregister already captured the peer snapshot and scheduled the timer.
    if (this._pendingOffline.has(deviceId)) return;

    // Capture the peer snapshot NOW so we notify exactly the peers that
    // were sharing a rendezvous with this device at the moment it left,
    // even if the rendezvous membership changes during the grace window.
    const deviceState = this._devices.get(deviceId);
    const peers = this._collectPeers(deviceId, deviceState.rendezvousIds);

    // graceMs <= 0 disables the deferral entirely (used by tests that
    // require synchronous semantics). Perform the teardown inline.
    if (this._reconnectGraceMs <= 0) {
      this._removeFromRendezvous(deviceId);
      this._devices.delete(deviceId);
      for (const peerId of peers) {
        this._gateway.send(peerId, { type: MSG.PEER_OFFLINE, deviceId });
      }
      return;
    }

    // Defer the actual teardown + notification. The device stays in
    // `_devices` and `_rendezvous` during the grace window so signaling
    // lookups still resolve; callers that need to send to the peer will
    // hit a closed gateway entry and simply get `send()` returning false,
    // which is already the expected behaviour for a flaky peer.
    const timer = setTimeout(
      () => this._finalizeOffline(deviceId, peers),
      this._reconnectGraceMs,
    );
    if (timer.unref) timer.unref();
    this._pendingOffline.set(deviceId, { timer, peers });
  }

  /**
   * Complete a deferred unregister once the grace window expires without
   * the device reconnecting. Removes the device from all maps and fires
   * PEER_OFFLINE to the snapshot of peers captured at unregister time.
   *
   * @param {string} deviceId
   * @param {Set<string>} peers - peer set captured at the moment of unregister
   */
  _finalizeOffline(deviceId, peers) {
    this._pendingOffline.delete(deviceId);
    // If the device was re-registered during the grace window via a
    // different code path that didn't cancel the timer, the device may
    // still be in `_devices`. In that case, do not tear it down — treat
    // this as a no-op.
    if (!this._devices.has(deviceId)) {
      // Already gone via another path; still notify peers since we owe
      // them the offline snapshot we captured.
      for (const peerId of peers) {
        this._gateway.send(peerId, { type: MSG.PEER_OFFLINE, deviceId });
      }
      return;
    }
    this._removeFromRendezvous(deviceId);
    this._devices.delete(deviceId);
    for (const peerId of peers) {
      this._gateway.send(peerId, { type: MSG.PEER_OFFLINE, deviceId });
    }
  }

  /**
   * Updates the lastSeen timestamp for a device (called on every inbound message).
   * No-op if the device is not registered.
   *
   * @param {string} deviceId
   */
  heartbeat(deviceId) {
    const state = this._devices.get(deviceId);
    if (state) {
      state.lastSeen = Date.now();
    }
  }

  /**
   * Returns true if the device is currently registered (online).
   *
   * @param {string} deviceId
   * @returns {boolean}
   */
  isOnline(deviceId) {
    return this._devices.has(deviceId);
  }

  /**
   * Returns the lastSeen timestamp for a device, or undefined if not registered.
   *
   * @param {string} deviceId
   * @returns {number|undefined}
   */
  lastSeen(deviceId) {
    return this._devices.get(deviceId)?.lastSeen;
  }

  /**
   * Returns the Set of device IDs currently registered for a given rendezvous ID.
   * Returns an empty Set for unknown rendezvous IDs (never throws).
   *
   * @param {string} rendezvousId
   * @returns {Set<string>}
   */
  getRendezvousPeers(rendezvousId) {
    return this._rendezvous.get(rendezvousId) ?? new Set();
  }

  /**
   * Starts the periodic silence checker.
   *
   * On each tick, every registered device whose `lastSeen` timestamp is older
   * than `silenceTimeoutMs` is unregistered (triggering PEER_OFFLINE notifications
   * to all of its rendezvous peers).
   *
   * Calling this multiple times is safe — only one timer is active at a time.
   */
  startSilenceChecker() {
    if (this._silenceTimer !== null) return; // already running

    this._silenceTimer = setInterval(() => {
      const cutoff = Date.now() - this._silenceTimeoutMs;
      // Collect stale device IDs before iterating to avoid mutating the map
      // during unregister() calls.
      const stale = [];
      for (const [deviceId, state] of this._devices) {
        if (state.lastSeen < cutoff) {
          stale.push(deviceId);
        }
      }
      for (const deviceId of stale) {
        this.unregister(deviceId);
      }
    }, this._checkIntervalMs);

    // Don't keep the Node.js event loop alive solely for cleanup sweeps
    if (this._silenceTimer.unref) {
      this._silenceTimer.unref();
    }
  }

  /**
   * Stops the silence checker and releases the interval timer.
   * Should be called when the server is shutting down.
   */
  destroy() {
    if (this._silenceTimer !== null) {
      clearInterval(this._silenceTimer);
      this._silenceTimer = null;
    }
    // Cancel any pending teardown timers so the Node.js event loop can
    // exit cleanly on shutdown.
    for (const pending of this._pendingOffline.values()) {
      clearTimeout(pending.timer);
    }
    this._pendingOffline.clear();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Removes `deviceId` from all rendezvous sets it currently belongs to.
   * Cleans up any rendezvous set that becomes empty after removal.
   *
   * Does NOT delete from `_devices` — callers are responsible for that.
   *
   * @param {string} deviceId
   */
  _removeFromRendezvous(deviceId) {
    const state = this._devices.get(deviceId);
    if (!state) return;

    for (const rvId of state.rendezvousIds) {
      const set = this._rendezvous.get(rvId);
      if (set) {
        set.delete(deviceId);
        // Prune empty sets to avoid unbounded map growth
        if (set.size === 0) {
          this._rendezvous.delete(rvId);
        }
      }
    }
  }

  /**
   * Collects the unique set of device IDs sharing any of the given rendezvous IDs
   * with `deviceId`, excluding `deviceId` itself.
   *
   * @param {string}   deviceId       - The registering/unregistering device (excluded from result)
   * @param {string[]} rendezvousIds  - Rendezvous IDs to scan
   * @returns {Set<string>}
   */
  _collectPeers(deviceId, rendezvousIds) {
    const peers = new Set();
    for (const rvId of rendezvousIds) {
      const set = this._rendezvous.get(rvId);
      if (set) {
        for (const peerId of set) {
          if (peerId !== deviceId) {
            peers.add(peerId);
          }
        }
      }
    }
    return peers;
  }
}
