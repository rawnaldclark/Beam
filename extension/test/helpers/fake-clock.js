/**
 * @file fake-clock.js
 * @description Manual-tick virtual clock for deterministic timer tests.
 *
 * Used by `recovery-ladder.test.js`, `connection-authority.test.js`, and
 * Task 11's per-rung tests. Extracted so all three test suites share one
 * implementation rather than three near-identical copies (Task 11 follow-up D
 * in the plan: "extract before this task triples the duplication").
 *
 * Surface:
 *   - `now()`            — returns the current virtual ms timestamp.
 *   - `setTimeout(fn, d)`— schedules `fn` for `now() + max(0, d)`. Returns a
 *                          numeric id.
 *   - `clearTimeout(id)` — cancels a pending timer; safe on unknown ids.
 *   - `tick(ms)`         — advances the virtual clock by `ms`. Fires every
 *                          timer whose deadline has been crossed, in deadline
 *                          order. Timers scheduled inside a callback are
 *                          included in the same `tick()` if they would also
 *                          have fired by the target instant.
 *   - `pending`          — number of currently-armed timers (for shutdown
 *                          assertions: should be 0 after a clean teardown).
 *
 * Intentionally minimal: no setInterval / clearInterval (the authority's
 * cadence engine and the ladder both build their own intervals from
 * setTimeout chains, so a coarser surface stays out of test bug territory).
 */
export class FakeClock {
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

  /** Advance the clock by `ms`, firing every timer whose deadline is now reached. */
  tick(ms) {
    const target = this._now + ms;
    // Loop fires timers in due-at order. New timers scheduled inside a
    // callback are picked up because we re-scan on each iteration.
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

  /** Number of currently-armed timers — for shutdown assertions. */
  get pending() { return this._timers.size; }
}
