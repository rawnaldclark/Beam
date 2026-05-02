/**
 * @file recovery-ladder.js
 * @description Sequential, cancelable promise-chain that runs a list of
 * recovery "rungs" until one succeeds or all fail.
 *
 * Used by {@link ConnectionAuthority} to recover from `peerHealth = FAILED`
 * or `selfState = RECONNECTING`. The ladder owns sequencing, logging, and
 * cancellation; each rung's `action` owns its own success-signal subscription
 * and budget-timer (via the helpers in this module).
 *
 * Contract per rung:
 *   - `name`     : short identifier used in logs (`rung1`, `rung2`, ...).
 *   - `budgetMs` : informational — passed to the action so it knows its
 *                  budget. Logging includes per-rung elapsed time.
 *   - `action`   : `async ({ signal }) => boolean` — resolves `true` if the
 *                  rung recovered, `false` if it timed out / surrendered.
 *                  The provided `signal` is an AbortSignal-like object whose
 *                  `aborted` flag flips and `addEventListener('abort', ...)`
 *                  fires when {@link RecoveryLadder#cancel} is called. Actions
 *                  MUST observe this signal to tear down their subscriptions
 *                  and timers cleanly — otherwise cancellation leaks.
 *
 * Ladder semantics:
 *   - Rungs run strictly sequentially. The first `action` returning `true`
 *     ends the ladder with `{ ok: true, rung: name }`.
 *   - A rung returning `false` (or throwing) advances to the next rung.
 *   - If `cancel()` is called, the in-flight action is signalled and the
 *     ladder resolves with `{ ok: false, cancelled: true }` after the action
 *     settles. No further rungs are attempted.
 *   - If every rung fails, the last rung's outcome is reported as
 *     `{ ok: false, exhausted: true, lastError? }`.
 *
 * Logging:
 *   - `console.log('[CA] ladder: rung=N start')` on entry.
 *   - `console.log('[CA] ladder: rung=N ok t=X.Xs')`  on success.
 *   - `console.log('[CA] ladder: rung=N timeout t=X.Xs')` on action returning false.
 *   - `console.log('[CA] ladder: rung=N error t=X.Xs <message>')` on throw.
 *   - `console.log('[CA] ladder: cancelled')` once cancel-driven exit completes.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 *       §"Recovery ladder".
 */

/**
 * @typedef {object} RecoveryRung
 * @property {string} name
 * @property {number} budgetMs
 * @property {(args: { signal: AbortSignal }) => Promise<boolean>} action
 */

/**
 * @typedef {object} LadderResult
 * @property {boolean} ok
 * @property {string} [rung]        - Name of the rung that succeeded (when ok=true).
 * @property {boolean} [cancelled]  - True when cancel() drove the exit.
 * @property {boolean} [exhausted]  - True when every rung returned false / threw.
 * @property {Error}   [lastError]  - Last action error, if any (when ok=false).
 */

export class RecoveryLadder {
  /**
   * @param {object} opts
   * @param {RecoveryRung[]} opts.rungs
   *   Ordered list of rungs to attempt. Must be non-empty.
   * @param {(transition: { rung: string, phase: 'start'|'ok'|'timeout'|'error', elapsedMs: number, error?: Error }) => void} [opts.onTransition]
   *   Optional observer fired before each console log line — lets tests assert
   *   on transitions without parsing console output.
   * @param {{ now(): number }} [opts.timerImpl]
   *   Injectable clock for timing — only `now()` is used by the ladder itself.
   *   Defaults to `Date.now`. (The action implementations may use the same
   *   clock for their setTimeout/clearTimeout, but that is the action's
   *   responsibility, not the ladder's.)
   */
  constructor({ rungs, onTransition, timerImpl } = {}) {
    if (!Array.isArray(rungs) || rungs.length === 0) {
      throw new TypeError('RecoveryLadder: rungs must be a non-empty array');
    }
    for (const r of rungs) {
      if (!r || typeof r.name !== 'string' || typeof r.action !== 'function') {
        throw new TypeError('RecoveryLadder: each rung needs { name, budgetMs, action }');
      }
    }

    this._rungs = rungs;
    this._onTransition = typeof onTransition === 'function' ? onTransition : null;
    this._now = timerImpl && typeof timerImpl.now === 'function'
      ? () => timerImpl.now()
      : () => Date.now();

    /** Single AbortController shared across all rungs in this ladder. */
    this._abort = new AbortController();
    /** Guards against double-run / post-cancel run. */
    this._started = false;
    /** Cached result so a second `await ladder.run()` returns the same outcome. */
    /** @type {Promise<LadderResult>|null} */
    this._runPromise = null;
  }

  /**
   * Walk every rung in order, returning early on the first success or on
   * cancellation. Idempotent: a second call returns the same promise.
   *
   * @returns {Promise<LadderResult>}
   */
  run() {
    if (this._runPromise) return this._runPromise;
    this._started = true;
    this._runPromise = this._runInternal();
    return this._runPromise;
  }

  /** @returns {Promise<LadderResult>} */
  async _runInternal() {
    /** @type {Error|null} */
    let lastError = null;

    for (const rung of this._rungs) {
      // If cancellation landed between rungs, surrender immediately.
      if (this._abort.signal.aborted) {
        this._log('cancelled');
        return { ok: false, cancelled: true };
      }

      const startedAt = this._now();
      this._emit({ rung: rung.name, phase: 'start', elapsedMs: 0 });
      this._log(`rung=${rung.name} start`);

      let ok = false;
      try {
        ok = await rung.action({ signal: this._abort.signal });
      } catch (err) {
        const elapsedMs = this._now() - startedAt;
        lastError = err instanceof Error ? err : new Error(String(err));
        this._emit({ rung: rung.name, phase: 'error', elapsedMs, error: lastError });
        this._log(`rung=${rung.name} error t=${fmtSeconds(elapsedMs)}s ${lastError.message}`);
        // Treat a thrown action the same as a "false" result: advance to the
        // next rung unless we were cancelled mid-action (signal already set).
        if (this._abort.signal.aborted) {
          this._log('cancelled');
          return { ok: false, cancelled: true, lastError };
        }
        continue; // eslint-disable-line no-continue
      }

      const elapsedMs = this._now() - startedAt;

      // If cancellation landed during a rung that still resolved truthy,
      // honour the cancel (caller asked us to stop) — we do NOT report a
      // success when the user explicitly cancelled. This is conservative but
      // correct: the spec's only cancellation path (`requestReconnect` mid-
      // ladder) wants Rung 3 to run regardless of any in-flight rung's
      // outcome (Task 11).
      if (this._abort.signal.aborted) {
        this._log('cancelled');
        return lastError
          ? { ok: false, cancelled: true, lastError }
          : { ok: false, cancelled: true };
      }

      if (ok) {
        this._emit({ rung: rung.name, phase: 'ok', elapsedMs });
        this._log(`rung=${rung.name} ok t=${fmtSeconds(elapsedMs)}s`);
        return { ok: true, rung: rung.name };
      }

      this._emit({ rung: rung.name, phase: 'timeout', elapsedMs });
      this._log(`rung=${rung.name} timeout t=${fmtSeconds(elapsedMs)}s`);
    }

    // Every rung returned false (or threw) without cancellation.
    return lastError
      ? { ok: false, exhausted: true, lastError }
      : { ok: false, exhausted: true };
  }

  /**
   * Signal every rung action to abort and stop the ladder. Safe to call
   * before, during, or after `run()`. The promise returned by `run()` will
   * resolve with `{ ok: false, cancelled: true }` once the in-flight action
   * has settled in response to the signal. Idempotent.
   */
  cancel() {
    if (this._abort.signal.aborted) return;
    this._abort.abort();
  }

  /** @returns {boolean} True after `cancel()` has been called. */
  get cancelled() { return this._abort.signal.aborted; }

  // ── internal helpers ──────────────────────────────────────────────────────

  _emit(transition) {
    if (!this._onTransition) return;
    try { this._onTransition(transition); } catch { /* observer must not break the ladder */ }
  }

  _log(tail) {
    // eslint-disable-next-line no-console
    console.log(`[CA] ladder: ${tail}`);
  }
}

/**
 * Wait until `predicate(observable.value)` is truthy OR `budgetMs` elapses
 * OR `signal` aborts. Resolves `true` on predicate match, `false` on budget
 * expiry / cancellation. Cleans up both the subscription and the timer on
 * every exit path.
 *
 * Used by the ConnectionAuthority's rung action closures to await peerHealth
 * / selfState transitions without each rung re-implementing the race.
 *
 * @template T
 * @param {{ subscribe(fn:(v:T)=>void): () => void, value: T }} observable
 *   An Observable-like object — see {@link ../connection/observable.js}. The
 *   subscriber is invoked synchronously with the current value once on
 *   subscribe (replay), then on every change. This helper relies on that
 *   replay semantics so a value that is already truthy at call-time wins
 *   without an additional event.
 * @param {(v: T) => boolean} predicate
 *   Called with each emitted value; returning truthy resolves the wait.
 * @param {number} budgetMs
 *   Maximum time to wait, in ms, measured by the injected timer.
 * @param {AbortSignal|undefined} signal
 *   If provided and `aborted`, the wait resolves `false` immediately. If
 *   abort fires later, the wait resolves `false` and cleans up.
 * @param {{ setTimeout(fn:()=>void, ms:number): any, clearTimeout(id:any): void }} timerImpl
 *   Injectable timer surface — typically the same FakeClock the authority is
 *   wired against in tests.
 * @returns {Promise<boolean>}
 */
export function awaitObservableOrTimeout(observable, predicate, budgetMs, signal, timerImpl) {
  return new Promise((resolve) => {
    // Short-circuit: caller already cancelled.
    if (signal && signal.aborted) {
      resolve(false);
      return;
    }

    let settled = false;
    let unsubscribe = null;
    let timerId = null;
    let onAbort = null;

    const cleanup = () => {
      if (unsubscribe) { try { unsubscribe(); } catch { /* swallow */ } unsubscribe = null; }
      if (timerId != null) { try { timerImpl.clearTimeout(timerId); } catch { /* swallow */ } timerId = null; }
      if (signal && onAbort) { try { signal.removeEventListener('abort', onAbort); } catch { /* swallow */ } onAbort = null; }
    };

    const settle = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };

    // Arm the budget timer FIRST so the synchronous-replay subscribe below
    // can pre-empt it cleanly via cleanup() if the predicate is already true.
    timerId = timerImpl.setTimeout(() => settle(false), budgetMs);
    // In Node, setTimeout returns a Timeout object whose `unref()` removes
    // the timer from the event-loop "keep alive" set. We call it so a
    // ladder kicked from a test that doesn't await its resolution won't
    // hold the test process open for the full budget. FakeClock returns a
    // plain number — the typeof guard makes this a no-op there.
    if (timerId && typeof timerId.unref === 'function') timerId.unref();

    if (signal) {
      onAbort = () => settle(false);
      signal.addEventListener('abort', onAbort, { once: true });
    }

    // Subscribe LAST so the replay-on-subscribe semantics get a chance to
    // resolve us before the timer/abort listeners are running unnecessarily.
    // The Observable invokes `fn` synchronously with the current value during
    // subscribe(), so if the predicate is already true we settle here and
    // cleanup() tears the timer + listener back down before this function
    // returns.
    unsubscribe = observable.subscribe((v) => {
      if (settled) return;
      try {
        if (predicate(v)) settle(true);
      } catch {
        // Predicate threw — treat as no-match; budget timer remains armed.
      }
    });
  });
}

function fmtSeconds(ms) {
  return (ms / 1000).toFixed(1);
}
