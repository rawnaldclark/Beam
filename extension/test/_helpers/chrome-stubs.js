/**
 * @file chrome-stubs.js
 * @description Minimal in-memory shims for the `chrome.*` extension APIs
 * used by `background-relay.js` and its dependencies. Installed as a global
 * `chrome` so the SW module loads under Node's test runner.
 *
 * Only the surface actually called by the code under test is implemented —
 * if a future test exercises a new API, extend the relevant section here.
 */

class StorageArea {
  constructor() { this._map = new Map(); }

  async get(keys) {
    if (keys === null || keys === undefined) {
      return Object.fromEntries(this._map);
    }
    if (typeof keys === 'string') {
      const out = {};
      if (this._map.has(keys)) out[keys] = this._map.get(keys);
      return out;
    }
    if (Array.isArray(keys)) {
      const out = {};
      for (const k of keys) {
        if (this._map.has(k)) out[k] = this._map.get(k);
      }
      return out;
    }
    // Object form: defaults
    const out = {};
    for (const [k, def] of Object.entries(keys)) {
      out[k] = this._map.has(k) ? this._map.get(k) : def;
    }
    return out;
  }

  async set(items) {
    const changes = {};
    for (const [k, v] of Object.entries(items)) {
      changes[k] = { oldValue: this._map.get(k), newValue: v };
      this._map.set(k, v);
    }
    onChanged._fire(changes, this._areaName);
  }

  async remove(keys) {
    const arr = Array.isArray(keys) ? keys : [keys];
    const changes = {};
    for (const k of arr) {
      if (this._map.has(k)) {
        changes[k] = { oldValue: this._map.get(k), newValue: undefined };
        this._map.delete(k);
      }
    }
    if (Object.keys(changes).length > 0) onChanged._fire(changes, this._areaName);
  }

  _reset() { this._map.clear(); }
}

const onChanged = {
  _listeners: new Set(),
  addListener(fn) { this._listeners.add(fn); },
  removeListener(fn) { this._listeners.delete(fn); },
  _fire(changes, area) {
    for (const fn of this._listeners) {
      try { fn(changes, area); } catch (_) { /* ignore */ }
    }
  },
};

const local   = new StorageArea(); local._areaName = 'local';
const session = new StorageArea(); session._areaName = 'session';

/** Tiny async event surface for chrome.runtime.onMessage / .onConnect. */
function makeEvent() {
  const listeners = new Set();
  return {
    addListener: (fn) => listeners.add(fn),
    removeListener: (fn) => listeners.delete(fn),
    hasListener: (fn) => listeners.has(fn),
    _listeners: listeners,
  };
}

/**
 * In-memory captured runtime messages — tests can read `chrome._runtimeLog`
 * to inspect what the SW tried to send to the popup.
 *
 * @type {Array<object>}
 */
const _runtimeLog = [];

const chromeStub = {
  runtime: {
    onConnect: makeEvent(),
    onMessage: makeEvent(),
    async sendMessage(msg) {
      _runtimeLog.push(msg);
      // Simulate "no receiver" — the SW code paths swallow this case.
      const err = new Error('Could not establish connection. Receiving end does not exist.');
      throw err;
    },
    connect() {
      // Used by offscreen → SW keepalive port. Tests don't exercise this
      // path, but we return a port-like object for safety.
      return {
        name: 'beam-keepalive',
        onMessage:    makeEvent(),
        onDisconnect: makeEvent(),
        postMessage() { /* no-op */ },
        disconnect()  { /* no-op */ },
      };
    },
  },
  storage: {
    local,
    session,
    onChanged,
  },
  notifications: {
    create(_id, _opts) { /* no-op */ },
  },
  downloads: {
    async download(_opts) { return 1; },
  },
  _runtimeLog,
  /** Clears all stub state between tests. */
  _reset() {
    local._reset();
    session._reset();
    _runtimeLog.length = 0;
    onChanged._listeners.clear();
    chromeStub.runtime.onConnect._listeners.clear();
    chromeStub.runtime.onMessage._listeners.clear();
  },
};

/**
 * Install the chrome stub as a global. Call this BEFORE importing any
 * extension module that touches `chrome.*`.
 */
export function installChromeStub() {
  globalThis.chrome = chromeStub;
  return chromeStub;
}

export { chromeStub };
