/**
 * @file peer-health.test.js
 * @description Unit coverage for the pure peer-health reducer.
 *
 * Run:  node --test test/peer-health.test.js
 *
 * The reducer is a pure function: (state, event) => nextState.
 * No timers, no I/O, no side effects.
 *
 * State machine summary:
 *
 *   States: UNKNOWN | HEALTHY | STALE | FAILED | OFFLINE
 *
 *   Forward transitions:
 *     pong-received       : * \ {OFFLINE} -> HEALTHY
 *     frame-received      : * \ {OFFLINE} -> HEALTHY
 *     send-completed      : * \ {OFFLINE} -> HEALTHY
 *     ping-missed         : UNKNOWN -> STALE, HEALTHY -> STALE, STALE -> FAILED
 *     pre-flight-failed   : *        -> FAILED
 *     relay-peer-online   : OFFLINE  -> UNKNOWN  (weaker evidence, NOT HEALTHY)
 *     relay-peer-offline  : *        -> OFFLINE
 *     recovery-succeeded  : FAILED   -> UNKNOWN
 *     recovery-given-up   : FAILED   -> FAILED   (stays; UI surfaces it)
 *
 *   Anything else (event type unknown, or no rule matches): no-op (state unchanged).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { PeerHealth, reducePeerHealth } from '../connection/peer-health.js';

const ALL_STATES = [
  PeerHealth.UNKNOWN,
  PeerHealth.HEALTHY,
  PeerHealth.STALE,
  PeerHealth.FAILED,
  PeerHealth.OFFLINE,
];

// ─── PeerHealth enum sanity ──────────────────────────────────────────────────

describe('PeerHealth enum', () => {
  it('exports the five state constants with their string values', () => {
    assert.equal(PeerHealth.UNKNOWN, 'UNKNOWN');
    assert.equal(PeerHealth.HEALTHY, 'HEALTHY');
    assert.equal(PeerHealth.STALE, 'STALE');
    assert.equal(PeerHealth.FAILED, 'FAILED');
    assert.equal(PeerHealth.OFFLINE, 'OFFLINE');
  });
});

// ─── pong-received ───────────────────────────────────────────────────────────

describe('reducePeerHealth: pong-received', () => {
  const ev = { type: 'pong-received' };

  it('promotes UNKNOWN -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.HEALTHY);
  });
  it('keeps HEALTHY -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.HEALTHY);
  });
  it('promotes STALE -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.HEALTHY);
  });
  it('promotes FAILED -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.HEALTHY);
  });
  it('does NOT escape OFFLINE on pong-received (must wait for relay-peer-online)', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── frame-received ──────────────────────────────────────────────────────────

describe('reducePeerHealth: frame-received', () => {
  const ev = { type: 'frame-received' };

  it('promotes UNKNOWN -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.HEALTHY);
  });
  it('keeps HEALTHY -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.HEALTHY);
  });
  it('promotes STALE -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.HEALTHY);
  });
  it('promotes FAILED -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.HEALTHY);
  });
  it('does NOT escape OFFLINE on frame-received', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── send-completed ──────────────────────────────────────────────────────────

describe('reducePeerHealth: send-completed', () => {
  const ev = { type: 'send-completed' };

  it('promotes UNKNOWN -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.HEALTHY);
  });
  it('keeps HEALTHY -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.HEALTHY);
  });
  it('promotes STALE -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.HEALTHY);
  });
  it('promotes FAILED -> HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.HEALTHY);
  });
  it('does NOT escape OFFLINE on send-completed', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── ping-missed ─────────────────────────────────────────────────────────────

describe('reducePeerHealth: ping-missed', () => {
  const ev = { type: 'ping-missed' };

  it('UNKNOWN -> STALE', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.STALE);
  });
  it('HEALTHY -> STALE', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.STALE);
  });
  it('STALE -> FAILED (one miss tolerated)', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.FAILED);
  });
  it('FAILED stays FAILED on further ping-missed', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.FAILED);
  });
  it('OFFLINE stays OFFLINE on ping-missed (offline owns the floor)', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── pre-flight-failed ───────────────────────────────────────────────────────

describe('reducePeerHealth: pre-flight-failed', () => {
  const ev = { type: 'pre-flight-failed' };

  it('UNKNOWN -> FAILED', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.FAILED);
  });
  it('HEALTHY -> FAILED', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.FAILED);
  });
  it('STALE -> FAILED', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.FAILED);
  });
  it('FAILED stays FAILED', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.FAILED);
  });
  it('OFFLINE -> FAILED (preflight gives concrete failure evidence)', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.FAILED);
  });
});

// ─── relay-peer-online ───────────────────────────────────────────────────────

describe('reducePeerHealth: relay-peer-online', () => {
  const ev = { type: 'relay-peer-online' };

  it('OFFLINE -> UNKNOWN (weaker evidence; NOT promoted to HEALTHY)', () => {
    const next = reducePeerHealth(PeerHealth.OFFLINE, ev);
    assert.equal(next, PeerHealth.UNKNOWN);
    assert.notEqual(next, PeerHealth.HEALTHY,
      'relay says peer WS is open — but that does not prove the app is responsive. ' +
      'Must NOT promote to HEALTHY; only a peer-pong/frame can.');
  });
  it('UNKNOWN stays UNKNOWN (already at the post-OFFLINE floor)', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.UNKNOWN);
  });
  it('HEALTHY stays HEALTHY (do not downgrade on a weaker signal)', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.HEALTHY);
  });
  it('STALE stays STALE (informational; do not move on weaker evidence)', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.STALE);
  });
  it('FAILED stays FAILED (recovery ladder owns the FAILED exit)', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.FAILED);
  });
});

// ─── relay-peer-offline ──────────────────────────────────────────────────────

describe('reducePeerHealth: relay-peer-offline', () => {
  const ev = { type: 'relay-peer-offline' };

  it('UNKNOWN -> OFFLINE', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.OFFLINE);
  });
  it('HEALTHY -> OFFLINE', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.OFFLINE);
  });
  it('STALE -> OFFLINE', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.OFFLINE);
  });
  it('FAILED -> OFFLINE', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.OFFLINE);
  });
  it('OFFLINE stays OFFLINE', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── recovery-succeeded ──────────────────────────────────────────────────────

describe('reducePeerHealth: recovery-succeeded', () => {
  const ev = { type: 'recovery-succeeded' };

  it('FAILED -> UNKNOWN (next ping/frame will promote)', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.UNKNOWN);
  });
  it('UNKNOWN stays UNKNOWN (recovery succeeded outside FAILED is a no-op)', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.UNKNOWN);
  });
  it('HEALTHY stays HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.HEALTHY);
  });
  it('STALE stays STALE', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.STALE);
  });
  it('OFFLINE stays OFFLINE (relay says peer is gone; recovery does not override)', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── recovery-given-up ───────────────────────────────────────────────────────

describe('reducePeerHealth: recovery-given-up', () => {
  const ev = { type: 'recovery-given-up' };

  it('FAILED stays FAILED (UI surfaces this terminal state)', () => {
    assert.equal(reducePeerHealth(PeerHealth.FAILED, ev), PeerHealth.FAILED);
  });
  it('UNKNOWN stays UNKNOWN (no-op outside FAILED)', () => {
    assert.equal(reducePeerHealth(PeerHealth.UNKNOWN, ev), PeerHealth.UNKNOWN);
  });
  it('HEALTHY stays HEALTHY', () => {
    assert.equal(reducePeerHealth(PeerHealth.HEALTHY, ev), PeerHealth.HEALTHY);
  });
  it('STALE stays STALE', () => {
    assert.equal(reducePeerHealth(PeerHealth.STALE, ev), PeerHealth.STALE);
  });
  it('OFFLINE stays OFFLINE', () => {
    assert.equal(reducePeerHealth(PeerHealth.OFFLINE, ev), PeerHealth.OFFLINE);
  });
});

// ─── unknown event type ──────────────────────────────────────────────────────

describe('reducePeerHealth: unknown / malformed events', () => {
  it('an unknown event type leaves state unchanged from every state', () => {
    const ev = { type: 'totally-made-up-event' };
    for (const s of ALL_STATES) {
      assert.equal(reducePeerHealth(s, ev), s, `state ${s} must be unchanged`);
    }
  });

  it('an event without a type is a no-op (defensive, must not throw)', () => {
    for (const s of ALL_STATES) {
      assert.equal(reducePeerHealth(s, {}), s, `state ${s} must be unchanged for {}`);
    }
  });
});

// ─── combined sequences ──────────────────────────────────────────────────────

describe('reducePeerHealth: combined sequences', () => {
  it('HEALTHY -> ping-missed -> STALE -> ping-missed -> FAILED', () => {
    let s = PeerHealth.HEALTHY;
    s = reducePeerHealth(s, { type: 'ping-missed' });
    assert.equal(s, PeerHealth.STALE, 'first miss must move HEALTHY to STALE');
    s = reducePeerHealth(s, { type: 'ping-missed' });
    assert.equal(s, PeerHealth.FAILED, 'second miss must move STALE to FAILED');
  });

  it('OFFLINE -> relay-peer-online -> UNKNOWN -> pong-received -> HEALTHY', () => {
    let s = PeerHealth.OFFLINE;
    s = reducePeerHealth(s, { type: 'relay-peer-online' });
    assert.equal(s, PeerHealth.UNKNOWN, 'relay-peer-online must exit OFFLINE only as far as UNKNOWN');
    s = reducePeerHealth(s, { type: 'pong-received' });
    assert.equal(s, PeerHealth.HEALTHY, 'pong-received must promote UNKNOWN to HEALTHY');
  });

  it('FAILED -> recovery-succeeded -> UNKNOWN -> frame-received -> HEALTHY', () => {
    let s = PeerHealth.FAILED;
    s = reducePeerHealth(s, { type: 'recovery-succeeded' });
    assert.equal(s, PeerHealth.UNKNOWN);
    s = reducePeerHealth(s, { type: 'frame-received' });
    assert.equal(s, PeerHealth.HEALTHY);
  });

  it('HEALTHY -> ping-missed (STALE) -> pong-received (HEALTHY): one miss is recoverable', () => {
    let s = PeerHealth.HEALTHY;
    s = reducePeerHealth(s, { type: 'ping-missed' });
    assert.equal(s, PeerHealth.STALE);
    s = reducePeerHealth(s, { type: 'pong-received' });
    assert.equal(s, PeerHealth.HEALTHY, 'a recovered pong from STALE must restore HEALTHY');
  });

  it('HEALTHY -> relay-peer-offline (OFFLINE) -> relay-peer-online (UNKNOWN), not back to HEALTHY', () => {
    let s = PeerHealth.HEALTHY;
    s = reducePeerHealth(s, { type: 'relay-peer-offline' });
    assert.equal(s, PeerHealth.OFFLINE);
    s = reducePeerHealth(s, { type: 'relay-peer-online' });
    assert.equal(s, PeerHealth.UNKNOWN,
      'after going OFFLINE then back ONLINE we must NOT assume HEALTHY without a pong/frame');
  });

  it('FAILED -> recovery-given-up keeps FAILED indefinitely until an upgrade event arrives', () => {
    let s = PeerHealth.FAILED;
    s = reducePeerHealth(s, { type: 'recovery-given-up' });
    assert.equal(s, PeerHealth.FAILED);
    s = reducePeerHealth(s, { type: 'recovery-given-up' });
    assert.equal(s, PeerHealth.FAILED);
    s = reducePeerHealth(s, { type: 'pong-received' });
    assert.equal(s, PeerHealth.HEALTHY, 'a real pong still rescues us out of FAILED');
  });
});

// ─── purity ──────────────────────────────────────────────────────────────────

describe('reducePeerHealth: purity', () => {
  it('does not mutate the event object', () => {
    const ev = { type: 'ping-missed', extra: 'data' };
    const snapshot = JSON.stringify(ev);
    reducePeerHealth(PeerHealth.HEALTHY, ev);
    assert.equal(JSON.stringify(ev), snapshot);
  });

  it('returns the same primitive state value when the transition is a no-op (identity)', () => {
    // No-op: UNKNOWN with recovery-given-up stays UNKNOWN.
    assert.equal(
      reducePeerHealth(PeerHealth.UNKNOWN, { type: 'recovery-given-up' }),
      PeerHealth.UNKNOWN,
    );
  });
});
