/**
 * @file self-state.test.js
 * @description Unit coverage for the pure selfState reducer.
 *
 * Run:  node --test test/self-state.test.js
 *
 * The reducer is a pure function: (state, event) => nextState.
 * No timers, no I/O, no side effects.
 *
 * State machine summary:
 *
 *   States: OFFLINE | CONNECTING | ONLINE | RECONNECTING
 *
 *   Forward transitions:
 *     start-connect       : OFFLINE                          -> CONNECTING
 *     auth-complete       : CONNECTING                       -> ONLINE
 *     ws-closed           : ONLINE | CONNECTING              -> RECONNECTING
 *     recovery-began      : OFFLINE | CONNECTING | ONLINE    -> RECONNECTING
 *     recovery-succeeded  : RECONNECTING                     -> ONLINE
 *     recovery-given-up   : RECONNECTING                     -> RECONNECTING (stays)
 *     stop                : *                                -> OFFLINE
 *
 *   Anything else (event type unknown, or no rule matches): no-op (state unchanged).
 *
 *   Spec note: the reducer is dimensionless w.r.t. peer ID — there's only one self
 *   per process. The authority decides *when* to dispatch start-connect (first pair,
 *   cold boot, manual reconnect, ladder Rung 2/3); the reducer just sees the event.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { SelfState, reduceSelfState } from '../connection/self-state.js';

const ALL_STATES = [
  SelfState.OFFLINE,
  SelfState.CONNECTING,
  SelfState.ONLINE,
  SelfState.RECONNECTING,
];

// ─── SelfState enum sanity ───────────────────────────────────────────────────

describe('SelfState enum', () => {
  it('exports the four state constants with their string values', () => {
    assert.equal(SelfState.OFFLINE, 'OFFLINE');
    assert.equal(SelfState.CONNECTING, 'CONNECTING');
    assert.equal(SelfState.ONLINE, 'ONLINE');
    assert.equal(SelfState.RECONNECTING, 'RECONNECTING');
  });

  it('is frozen (cannot be mutated at runtime)', () => {
    assert.equal(Object.isFrozen(SelfState), true);
  });
});

// ─── start-connect ───────────────────────────────────────────────────────────

describe('reduceSelfState: start-connect', () => {
  const ev = { type: 'start-connect' };

  it('OFFLINE -> CONNECTING', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.CONNECTING);
  });
  it('CONNECTING stays CONNECTING (already trying)', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.CONNECTING);
  });
  it('ONLINE stays ONLINE (already connected; do not bounce)', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.ONLINE);
  });
  it('RECONNECTING stays RECONNECTING (recovery ladder is in charge)', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.RECONNECTING);
  });
});

// ─── auth-complete ───────────────────────────────────────────────────────────

describe('reduceSelfState: auth-complete', () => {
  const ev = { type: 'auth-complete' };

  it('CONNECTING -> ONLINE', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.ONLINE);
  });
  it('OFFLINE stays OFFLINE (cannot complete auth without connecting first)', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.OFFLINE);
  });
  it('ONLINE stays ONLINE (no-op; already authed)', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.ONLINE);
  });
  it('RECONNECTING stays RECONNECTING (auth-complete during recovery is handled by recovery-succeeded)', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.RECONNECTING);
  });
});

// ─── ws-closed ───────────────────────────────────────────────────────────────

describe('reduceSelfState: ws-closed', () => {
  const ev = { type: 'ws-closed' };

  it('ONLINE -> RECONNECTING', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.RECONNECTING);
  });
  it('CONNECTING -> RECONNECTING (auth never completed; still need recovery)', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.RECONNECTING);
  });
  it('OFFLINE stays OFFLINE (no socket to close)', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.OFFLINE);
  });
  it('RECONNECTING stays RECONNECTING (recovery already engaged)', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.RECONNECTING);
  });
});

// ─── recovery-began ──────────────────────────────────────────────────────────

describe('reduceSelfState: recovery-began', () => {
  const ev = { type: 'recovery-began' };

  it('OFFLINE -> RECONNECTING', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.RECONNECTING);
  });
  it('CONNECTING -> RECONNECTING', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.RECONNECTING);
  });
  it('ONLINE -> RECONNECTING', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.RECONNECTING);
  });
  it('RECONNECTING stays RECONNECTING', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.RECONNECTING);
  });
});

// ─── recovery-succeeded ──────────────────────────────────────────────────────

describe('reduceSelfState: recovery-succeeded', () => {
  const ev = { type: 'recovery-succeeded' };

  it('RECONNECTING -> ONLINE (the ladder restored connectivity)', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.ONLINE);
  });
  it('OFFLINE stays OFFLINE (no-op outside RECONNECTING)', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.OFFLINE);
  });
  it('CONNECTING stays CONNECTING (no-op outside RECONNECTING)', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.CONNECTING);
  });
  it('ONLINE stays ONLINE (no-op outside RECONNECTING)', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.ONLINE);
  });
});

// ─── recovery-given-up ───────────────────────────────────────────────────────

describe('reduceSelfState: recovery-given-up', () => {
  const ev = { type: 'recovery-given-up' };

  it('RECONNECTING stays RECONNECTING (UI surfaces the surrendered banner; flag lives on the authority)', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.RECONNECTING);
  });
  it('OFFLINE stays OFFLINE (no-op outside RECONNECTING)', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.OFFLINE);
  });
  it('CONNECTING stays CONNECTING (no-op outside RECONNECTING)', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.CONNECTING);
  });
  it('ONLINE stays ONLINE (no-op outside RECONNECTING)', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.ONLINE);
  });
});

// ─── stop ────────────────────────────────────────────────────────────────────

describe('reduceSelfState: stop', () => {
  const ev = { type: 'stop' };

  it('OFFLINE stays OFFLINE', () => {
    assert.equal(reduceSelfState(SelfState.OFFLINE, ev), SelfState.OFFLINE);
  });
  it('CONNECTING -> OFFLINE', () => {
    assert.equal(reduceSelfState(SelfState.CONNECTING, ev), SelfState.OFFLINE);
  });
  it('ONLINE -> OFFLINE', () => {
    assert.equal(reduceSelfState(SelfState.ONLINE, ev), SelfState.OFFLINE);
  });
  it('RECONNECTING -> OFFLINE', () => {
    assert.equal(reduceSelfState(SelfState.RECONNECTING, ev), SelfState.OFFLINE);
  });
});

// ─── unknown event type ──────────────────────────────────────────────────────

describe('reduceSelfState: unknown / malformed events', () => {
  it('an unknown event type leaves state unchanged from every state', () => {
    const ev = { type: 'totally-made-up-event' };
    for (const s of ALL_STATES) {
      assert.equal(reduceSelfState(s, ev), s, `state ${s} must be unchanged`);
    }
  });

  it('an event without a type is a no-op (defensive, must not throw)', () => {
    for (const s of ALL_STATES) {
      assert.equal(reduceSelfState(s, {}), s, `state ${s} must be unchanged for {}`);
    }
  });

  it('a null/undefined event is a no-op (defensive, must not throw)', () => {
    for (const s of ALL_STATES) {
      assert.equal(reduceSelfState(s, null), s, `state ${s} must be unchanged for null`);
      assert.equal(reduceSelfState(s, undefined), s, `state ${s} must be unchanged for undefined`);
    }
  });
});

// ─── combined sequences ──────────────────────────────────────────────────────

describe('reduceSelfState: combined sequences', () => {
  it('cold-boot happy path: OFFLINE -> CONNECTING -> ONLINE -> RECONNECTING -> ONLINE', () => {
    let s = SelfState.OFFLINE;
    s = reduceSelfState(s, { type: 'start-connect' });
    assert.equal(s, SelfState.CONNECTING, 'start-connect must promote OFFLINE to CONNECTING');
    s = reduceSelfState(s, { type: 'auth-complete' });
    assert.equal(s, SelfState.ONLINE, 'auth-complete must promote CONNECTING to ONLINE');
    s = reduceSelfState(s, { type: 'ws-closed' });
    assert.equal(s, SelfState.RECONNECTING, 'ws-closed from ONLINE must enter RECONNECTING');
    s = reduceSelfState(s, { type: 'recovery-succeeded' });
    assert.equal(s, SelfState.ONLINE, 'recovery-succeeded must restore ONLINE');
  });

  it('CONNECTING dropped before auth: CONNECTING -> ws-closed -> RECONNECTING -> recovery-succeeded -> ONLINE', () => {
    let s = SelfState.CONNECTING;
    s = reduceSelfState(s, { type: 'ws-closed' });
    assert.equal(s, SelfState.RECONNECTING,
      'a socket close while CONNECTING (auth never completed) must enter RECONNECTING, not OFFLINE');
    s = reduceSelfState(s, { type: 'recovery-succeeded' });
    assert.equal(s, SelfState.ONLINE);
  });

  it('ladder surrenders but stays RECONNECTING: ONLINE -> recovery-began -> RECONNECTING -> recovery-given-up -> RECONNECTING', () => {
    let s = SelfState.ONLINE;
    s = reduceSelfState(s, { type: 'recovery-began' });
    assert.equal(s, SelfState.RECONNECTING);
    s = reduceSelfState(s, { type: 'recovery-given-up' });
    assert.equal(s, SelfState.RECONNECTING,
      'spec §"Recovery ladder Rung 4" leaves Rung 4 in RECONNECTING; surrenderedToUser is a separate flag on the authority');
    // A subsequent given-up event is still a no-op — surrender is sticky in the authority, not the reducer.
    s = reduceSelfState(s, { type: 'recovery-given-up' });
    assert.equal(s, SelfState.RECONNECTING);
  });

  it('user retries after surrender: RECONNECTING -> stop -> OFFLINE -> start-connect -> CONNECTING', () => {
    let s = SelfState.RECONNECTING;
    s = reduceSelfState(s, { type: 'stop' });
    assert.equal(s, SelfState.OFFLINE, 'stop drops to OFFLINE from any state');
    s = reduceSelfState(s, { type: 'start-connect' });
    assert.equal(s, SelfState.CONNECTING, 'manual reconnect after surrender re-enters CONNECTING');
  });

  it('app shutdown from ONLINE: ONLINE -> stop -> OFFLINE', () => {
    let s = SelfState.ONLINE;
    s = reduceSelfState(s, { type: 'stop' });
    assert.equal(s, SelfState.OFFLINE);
  });

  it('repeat start-connect while CONNECTING is idempotent (no bounce)', () => {
    let s = SelfState.OFFLINE;
    s = reduceSelfState(s, { type: 'start-connect' });
    assert.equal(s, SelfState.CONNECTING);
    s = reduceSelfState(s, { type: 'start-connect' });
    assert.equal(s, SelfState.CONNECTING, 'second start-connect must be a no-op');
  });

  it('recovery-began from OFFLINE: cold-boot ladder skips CONNECTING and goes straight to RECONNECTING', () => {
    // Per task spec, recovery-began transitions OFFLINE/CONNECTING/ONLINE -> RECONNECTING.
    let s = SelfState.OFFLINE;
    s = reduceSelfState(s, { type: 'recovery-began' });
    assert.equal(s, SelfState.RECONNECTING);
    s = reduceSelfState(s, { type: 'recovery-succeeded' });
    assert.equal(s, SelfState.ONLINE);
  });
});

// ─── purity ──────────────────────────────────────────────────────────────────

describe('reduceSelfState: purity', () => {
  it('does not mutate the event object', () => {
    const ev = { type: 'start-connect', extra: 'data' };
    const snapshot = JSON.stringify(ev);
    reduceSelfState(SelfState.OFFLINE, ev);
    assert.equal(JSON.stringify(ev), snapshot);
  });

  it('returns the same primitive state value when the transition is a no-op (identity)', () => {
    // No-op: ONLINE with recovery-given-up stays ONLINE.
    assert.equal(
      reduceSelfState(SelfState.ONLINE, { type: 'recovery-given-up' }),
      SelfState.ONLINE,
    );
  });
});
