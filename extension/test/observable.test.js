/**
 * @file observable.test.js
 * @description Unit coverage for the tiny in-house Observable helper.
 *
 * Run:  node --test test/observable.test.js
 *
 * Verifies:
 *   - subscribe(fn) replays the current value immediately.
 *   - next(v) updates `value` and fans out to all subscribers.
 *   - The unsubscribe function returned by subscribe stops further deliveries.
 *   - Multiple subscribers each receive every emission.
 *   - The constructor's initial value is honored.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { Observable } from '../connection/observable.js';

// ─── construction & initial value ────────────────────────────────────────────

describe('Observable: construction', () => {
  it('exposes the initial value via .value', () => {
    const o = new Observable(42);
    assert.equal(o.value, 42);
  });

  it('accepts any type as the initial value (including null, undefined, objects)', () => {
    assert.equal(new Observable(null).value, null);
    assert.equal(new Observable(undefined).value, undefined);
    const obj = { foo: 'bar' };
    assert.equal(new Observable(obj).value, obj);
  });
});

// ─── subscribe replays the current value ─────────────────────────────────────

describe('Observable: subscribe', () => {
  it('calls the subscriber synchronously with the current value on subscribe', () => {
    const o = new Observable('hello');
    const calls = [];
    o.subscribe((v) => calls.push(v));
    assert.deepEqual(calls, ['hello'], 'replay must happen synchronously inside subscribe()');
  });

  it('replays whatever the latest value is, not the initial value', () => {
    const o = new Observable(0);
    o.next(1);
    o.next(2);
    const calls = [];
    o.subscribe((v) => calls.push(v));
    assert.deepEqual(calls, [2], 'late subscriber must receive the latest value, not the initial');
  });
});

// ─── next() updates value and notifies all subscribers ───────────────────────

describe('Observable: next', () => {
  it('updates `value` to the new value', () => {
    const o = new Observable('a');
    o.next('b');
    assert.equal(o.value, 'b');
  });

  it('calls every subscriber with the new value', () => {
    const o = new Observable(0);
    const calls1 = [];
    const calls2 = [];
    o.subscribe((v) => calls1.push(v));
    o.subscribe((v) => calls2.push(v));
    o.next(7);
    // Each subscriber receives: replay (0), then next (7).
    assert.deepEqual(calls1, [0, 7]);
    assert.deepEqual(calls2, [0, 7]);
  });

  it('fires the subscriber once per next() call (naive — no dedupe even if v === value)', () => {
    const o = new Observable(1);
    const calls = [];
    o.subscribe((v) => calls.push(v));
    o.next(1);
    o.next(1);
    // Replay (1), then two next(1) deliveries.
    assert.deepEqual(calls, [1, 1, 1]);
  });
});

// ─── unsubscribe ─────────────────────────────────────────────────────────────

describe('Observable: unsubscribe', () => {
  it('returns a function from subscribe()', () => {
    const o = new Observable(0);
    const unsub = o.subscribe(() => {});
    assert.equal(typeof unsub, 'function');
  });

  it('stops further deliveries after the returned function is called', () => {
    const o = new Observable(0);
    const calls = [];
    const unsub = o.subscribe((v) => calls.push(v));
    o.next(1);
    unsub();
    o.next(2);
    assert.deepEqual(calls, [0, 1], 'no delivery should arrive after unsubscribe');
  });

  it('only removes the unsubscribed subscriber; others keep receiving', () => {
    const o = new Observable(0);
    const a = [];
    const b = [];
    const unsubA = o.subscribe((v) => a.push(v));
    o.subscribe((v) => b.push(v));
    o.next(1);
    unsubA();
    o.next(2);
    assert.deepEqual(a, [0, 1]);
    assert.deepEqual(b, [0, 1, 2]);
  });

  it('calling the unsubscribe function twice is safe (no-op the second time)', () => {
    const o = new Observable(0);
    const unsub = o.subscribe(() => {});
    unsub();
    assert.doesNotThrow(() => unsub());
  });
});
