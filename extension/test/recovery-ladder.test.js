/**
 * @file recovery-ladder.test.js
 * @description Unit coverage for {@link RecoveryLadder} and the
 * `awaitObservableOrTimeout` helper (Task 8).
 *
 * Run:  node --test test/recovery-ladder.test.js
 *
 * The ladder tests use mocked rung actions — the actions are tiny
 * deferred-promise factories that flip `true` / `false` / throw on demand,
 * driven by a {@link FakeClock} so timing is deterministic. The helper tests
 * use a real {@link Observable} from the connection module to verify the
 * subscribe / replay / timeout / abort interleavings.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { RecoveryLadder, awaitObservableOrTimeout } from '../connection/recovery-ladder.js';
import { Observable } from '../connection/observable.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Manual-tick fake clock. Mirrors the one in connection-authority.test.js but
 * stays inline here per Task 8 review note: "extraction would balloon scope."
 */
class FakeClock {
  constructor(startMs = 0) {
    this._now = startMs;
    this._nextId = 1;
    /** @type {Map<number, {dueAt:number, fn:() => void}>} */
    this._timers = new Map();
  }
  now() { return this._now; }
  setTimeout(fn, delay) {
    const id = this._nextId++;
    this._timers.set(id, { dueAt: this._now + Math.max(0, delay), fn });
    return id;
  }
  clearTimeout(id) {
    if (id == null) return;
    this._timers.delete(id);
  }
  tick(ms) {
    const target = this._now + ms;
    while (true) {
      let nextId = null;
      let nextDue = Infinity;
      for (const [id, t] of this._timers) {
        if (t.dueAt <= target && t.dueAt < nextDue) {
          nextDue = t.dueAt;
          nextId = id;
        }
      }
      if (nextId == null) break;
      const t = this._timers.get(nextId);
      this._timers.delete(nextId);
      this._now = t.dueAt;
      t.fn();
    }
    this._now = target;
  }
  get pending() { return this._timers.size; }
}

/**
 * Build a controllable rung. The returned object has:
 *   - `rung`     : the {name, budgetMs, action} object to pass to the ladder.
 *   - `succeed()`: resolve the in-flight call with `true`.
 *   - `timeout()`: resolve the in-flight call with `false`.
 *   - `throw(e)` : reject the in-flight call with `e`.
 *   - `signalSeen` : the AbortSignal handed to the action on its last call.
 *   - `calls`    : number of times the action has been invoked.
 *
 * The action only resolves when one of `succeed/timeout/throw` is called —
 * tests drive timing manually so they can assert on intermediate states
 * (e.g. cancellation while a rung is still pending).
 */
function makeControllableRung(name, budgetMs = 1_000) {
  const ctl = { calls: 0, signalSeen: null };
  let resolveOuter = null;
  let rejectOuter = null;
  ctl.rung = {
    name,
    budgetMs,
    action: ({ signal }) => {
      ctl.calls += 1;
      ctl.signalSeen = signal;
      return new Promise((res, rej) => { resolveOuter = res; rejectOuter = rej; });
    },
  };
  ctl.succeed = () => { if (resolveOuter) resolveOuter(true); };
  ctl.timeout = () => { if (resolveOuter) resolveOuter(false); };
  ctl.throw   = (err) => { if (rejectOuter) rejectOuter(err); };
  return ctl;
}

/** Drain the microtask queue so chained-promise resolutions land. */
const flushMicrotasks = () => new Promise((r) => setImmediate(r));

// ─── constructor ─────────────────────────────────────────────────────────────

describe('RecoveryLadder constructor', () => {
  it('throws TypeError when rungs is missing', () => {
    assert.throws(() => new RecoveryLadder({}), TypeError);
  });

  it('throws TypeError when rungs is empty', () => {
    assert.throws(() => new RecoveryLadder({ rungs: [] }), TypeError);
  });

  it('throws TypeError when a rung is missing name or action', () => {
    assert.throws(
      () => new RecoveryLadder({ rungs: [{ budgetMs: 100 }] }),
      TypeError,
    );
    assert.throws(
      () => new RecoveryLadder({ rungs: [{ name: 'r1', budgetMs: 100 }] }),
      TypeError,
    );
  });
});

// ─── sequencing ──────────────────────────────────────────────────────────────

describe('RecoveryLadder: sequential rung execution', () => {
  it('runs rungs in order, stopping at the first success', async () => {
    const r1 = makeControllableRung('rung1', 5_000);
    const r2 = makeControllableRung('rung2', 15_000);
    const r3 = makeControllableRung('rung3', 30_000);

    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung, r3.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();

    assert.equal(r1.calls, 1, 'rung1 invoked');
    assert.equal(r2.calls, 0, 'rung2 not yet');
    assert.equal(r3.calls, 0, 'rung3 not yet');

    r1.succeed();
    const result = await runPromise;

    assert.deepEqual(result, { ok: true, rung: 'rung1' });
    assert.equal(r2.calls, 0, 'rung2 must not run after rung1 success');
    assert.equal(r3.calls, 0);
  });

  it('advances to rung2 when rung1 returns false', async () => {
    const r1 = makeControllableRung('rung1', 5_000);
    const r2 = makeControllableRung('rung2', 15_000);
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();

    r1.timeout();
    await flushMicrotasks();
    assert.equal(r2.calls, 1, 'rung2 invoked after rung1 returned false');

    r2.succeed();
    const result = await runPromise;
    assert.deepEqual(result, { ok: true, rung: 'rung2' });
  });

  it('reports exhausted when every rung returns false', async () => {
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();
    r1.timeout();
    await flushMicrotasks();
    r2.timeout();

    const result = await runPromise;
    assert.equal(result.ok, false);
    assert.equal(result.exhausted, true);
    assert.equal(result.cancelled, undefined);
  });

  it('treats a thrown action as failure and continues to the next rung', async () => {
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();

    r1.throw(new Error('boom'));
    await flushMicrotasks();
    assert.equal(r2.calls, 1, 'rung2 runs after rung1 threw');

    r2.succeed();
    const result = await runPromise;
    assert.deepEqual(result, { ok: true, rung: 'rung2' });
  });

  it('exhausted result includes lastError when the last rung threw', async () => {
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();
    r1.timeout();
    await flushMicrotasks();
    const err = new Error('rung-3 stub');
    r2.throw(err);

    const result = await runPromise;
    assert.equal(result.ok, false);
    assert.equal(result.exhausted, true);
    assert.equal(result.lastError, err);
  });

  it('models the spec example: rung1 fails, rung2 fails, rung3 throws "TODO Rung 3"', async () => {
    // The plan says rung 3 is a stub that throws — the ladder should surface
    // that error as `lastError` on an exhausted result.
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const r3 = makeControllableRung('rung3');
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung, r3.rung] });
    const runPromise = ladder.run();

    await flushMicrotasks(); r1.timeout();
    await flushMicrotasks(); r2.timeout();
    await flushMicrotasks(); r3.throw(new Error('TODO Rung 3'));

    const result = await runPromise;
    assert.equal(result.ok, false);
    assert.equal(result.exhausted, true);
    assert.equal(result.lastError.message, 'TODO Rung 3');
  });
});

// ─── cancellation ────────────────────────────────────────────────────────────

describe('RecoveryLadder: cancellation', () => {
  it('cancel() mid-rung signals the action and resolves cancelled=true', async () => {
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();
    assert.equal(r1.calls, 1);
    assert.ok(r1.signalSeen, 'action received an AbortSignal');
    assert.equal(r1.signalSeen.aborted, false);

    ladder.cancel();
    assert.equal(r1.signalSeen.aborted, true, 'signal flips on cancel');

    // The well-behaved action observes the signal and resolves false.
    r1.timeout();
    const result = await runPromise;
    assert.deepEqual(result, { ok: false, cancelled: true });
    assert.equal(r2.calls, 0, 'rung2 must not run after cancel');
  });

  it('cancel() before run() short-circuits without invoking any rung', async () => {
    const r1 = makeControllableRung('rung1');
    const ladder = new RecoveryLadder({ rungs: [r1.rung] });
    ladder.cancel();
    const result = await ladder.run();
    assert.deepEqual(result, { ok: false, cancelled: true });
    assert.equal(r1.calls, 0, 'rung must not run after pre-cancel');
  });

  it('cancel() is idempotent', () => {
    const r1 = makeControllableRung('rung1');
    const ladder = new RecoveryLadder({ rungs: [r1.rung] });
    assert.equal(ladder.cancelled, false);
    ladder.cancel();
    assert.equal(ladder.cancelled, true);
    assert.doesNotThrow(() => ladder.cancel());
    assert.equal(ladder.cancelled, true);
  });

  it('cancellation overrides a late "true" from the action', async () => {
    // If the action races and reports success but cancel() landed first,
    // the ladder must report cancelled — Task 11's requestReconnect-mid-
    // ladder semantics rely on this conservative ordering.
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const ladder = new RecoveryLadder({ rungs: [r1.rung, r2.rung] });
    const runPromise = ladder.run();
    await flushMicrotasks();

    ladder.cancel();
    r1.succeed();           // action resolves true after cancel landed.
    const result = await runPromise;

    assert.equal(result.ok, false);
    assert.equal(result.cancelled, true);
    assert.equal(r2.calls, 0);
  });

  it('run() is idempotent: a second call returns the same promise', async () => {
    const r1 = makeControllableRung('rung1');
    const ladder = new RecoveryLadder({ rungs: [r1.rung] });
    const p1 = ladder.run();
    const p2 = ladder.run();
    assert.equal(p1, p2, 'run() must memoize');
    r1.succeed();
    await p1;
  });
});

// ─── transition observer + logging ──────────────────────────────────────────

describe('RecoveryLadder: onTransition observer', () => {
  it('fires start/ok with elapsed time for a successful rung', async () => {
    const clock = new FakeClock(0);
    const r1 = makeControllableRung('rung1', 5_000);
    const transitions = [];
    const ladder = new RecoveryLadder({
      rungs: [r1.rung],
      onTransition: (t) => transitions.push(t),
      timerImpl: clock,
    });
    const runPromise = ladder.run();
    await flushMicrotasks();

    // Advance the virtual clock before the rung settles.
    clock.tick(2_500);
    r1.succeed();
    await runPromise;

    assert.equal(transitions.length, 2);
    assert.equal(transitions[0].rung, 'rung1');
    assert.equal(transitions[0].phase, 'start');
    assert.equal(transitions[1].phase, 'ok');
    assert.equal(transitions[1].elapsedMs, 2_500);
  });

  it('fires start/timeout for a rung returning false', async () => {
    const clock = new FakeClock(0);
    const r1 = makeControllableRung('rung1', 5_000);
    const r2 = makeControllableRung('rung2', 15_000);
    const transitions = [];
    const ladder = new RecoveryLadder({
      rungs: [r1.rung, r2.rung],
      onTransition: (t) => transitions.push(t),
      timerImpl: clock,
    });
    const runPromise = ladder.run();
    await flushMicrotasks();
    clock.tick(5_000);
    r1.timeout();
    await flushMicrotasks();
    clock.tick(15_000);
    r2.timeout();
    await runPromise;

    assert.deepEqual(
      transitions.map((t) => `${t.rung}:${t.phase}:${t.elapsedMs}`),
      ['rung1:start:0', 'rung1:timeout:5000', 'rung2:start:0', 'rung2:timeout:15000'],
    );
  });

  it('fires error transition with the thrown error', async () => {
    const r1 = makeControllableRung('rung1');
    const r2 = makeControllableRung('rung2');
    const transitions = [];
    const ladder = new RecoveryLadder({
      rungs: [r1.rung, r2.rung],
      onTransition: (t) => transitions.push(t),
    });
    const runPromise = ladder.run();
    await flushMicrotasks();
    const err = new Error('rung-3 stub');
    r1.throw(err);
    await flushMicrotasks();
    r2.timeout();
    await runPromise;

    const errEvent = transitions.find((t) => t.phase === 'error');
    assert.ok(errEvent);
    assert.equal(errEvent.rung, 'rung1');
    assert.equal(errEvent.error, err);
  });

  it('a throwing onTransition observer must not break the ladder', async () => {
    const r1 = makeControllableRung('rung1');
    const ladder = new RecoveryLadder({
      rungs: [r1.rung],
      onTransition: () => { throw new Error('observer blew up'); },
    });
    const runPromise = ladder.run();
    await flushMicrotasks();
    r1.succeed();
    const result = await runPromise;
    assert.deepEqual(result, { ok: true, rung: 'rung1' });
  });
});

// ─── awaitObservableOrTimeout helper ─────────────────────────────────────────

describe('awaitObservableOrTimeout', () => {
  it('resolves true synchronously when the predicate matches the replayed value', async () => {
    const clock = new FakeClock(0);
    const obs = new Observable('HEALTHY');
    const result = await awaitObservableOrTimeout(
      obs,
      (v) => v === 'HEALTHY',
      5_000,
      undefined,
      clock,
    );
    assert.equal(result, true);
    assert.equal(clock.pending, 0, 'no leaked budget timer on synchronous match');
  });

  it('resolves true when the observable later emits a matching value', async () => {
    const clock = new FakeClock(0);
    const obs = new Observable('UNKNOWN');
    const p = awaitObservableOrTimeout(
      obs,
      (v) => v === 'HEALTHY',
      5_000,
      undefined,
      clock,
    );
    // Pretend a frame arrived 2s in.
    clock.tick(2_000);
    obs.next('HEALTHY');
    const result = await p;
    assert.equal(result, true);
    assert.equal(clock.pending, 0, 'budget timer cleared on success');
  });

  it('resolves false when the budget elapses with no match', async () => {
    const clock = new FakeClock(0);
    const obs = new Observable('UNKNOWN');
    const p = awaitObservableOrTimeout(
      obs,
      (v) => v === 'HEALTHY',
      5_000,
      undefined,
      clock,
    );
    clock.tick(5_000);
    const result = await p;
    assert.equal(result, false);
    assert.equal(clock.pending, 0, 'no leaked timer on timeout');
  });

  it('resolves false immediately when signal is already aborted', async () => {
    const clock = new FakeClock(0);
    const obs = new Observable('UNKNOWN');
    const ac = new AbortController();
    ac.abort();
    const result = await awaitObservableOrTimeout(
      obs,
      (v) => v === 'HEALTHY',
      5_000,
      ac.signal,
      clock,
    );
    assert.equal(result, false);
    assert.equal(clock.pending, 0, 'no timer armed for already-aborted call');
  });

  it('resolves false and cleans up when signal aborts mid-wait', async () => {
    const clock = new FakeClock(0);
    const obs = new Observable('UNKNOWN');
    const ac = new AbortController();
    const p = awaitObservableOrTimeout(
      obs,
      (v) => v === 'HEALTHY',
      5_000,
      ac.signal,
      clock,
    );
    clock.tick(1_000);
    ac.abort();
    const result = await p;
    assert.equal(result, false);
    assert.equal(clock.pending, 0, 'budget timer cleared on abort');
  });

  it('predicate exceptions are swallowed and treated as no-match', async () => {
    const clock = new FakeClock(0);
    const obs = new Observable('UNKNOWN');
    let throws = true;
    const p = awaitObservableOrTimeout(
      obs,
      (v) => {
        if (throws) { throws = false; throw new Error('boom'); }
        return v === 'HEALTHY';
      },
      5_000,
      undefined,
      clock,
    );
    // First (replay) call threw — should not have settled.
    obs.next('HEALTHY');
    const result = await p;
    assert.equal(result, true);
    assert.equal(clock.pending, 0);
  });
});
