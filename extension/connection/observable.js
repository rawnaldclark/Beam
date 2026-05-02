/**
 * @file observable.js
 * @description Tiny in-house BehaviorSubject-style observable.
 *
 * Used only by `ConnectionAuthority` to expose `selfState` and `peerHealth`
 * as subscribable values. Replays the current value to each new subscriber on
 * subscribe, then fires every subscriber on each `next(v)` call.
 *
 * Intentionally naive:
 *   - No equality / dedupe: every `next(v)` notifies, even if `v === value`.
 *     The authority does its own change-check before calling `next`, so the
 *     helper stays minimal.
 *   - No completion / error semantics — this is not RxJS.
 *   - Not a public API surface; lives in `extension/connection/` for use by
 *     the authority and its tests only.
 *
 * Spec: docs/superpowers/specs/2026-05-02-connection-authority-design.md
 */

/**
 * A subscribable value that replays the latest value to new subscribers.
 *
 * @template T
 */
export class Observable {
  /**
   * @param {T} initialValue  Starting value; emitted to subscribers on subscribe.
   */
  constructor(initialValue) {
    /** @type {T} */
    this.value = initialValue;
    /** @type {Set<(v: T) => void>} */
    this._subs = new Set();
  }

  /**
   * Subscribe to value changes. The subscriber is invoked synchronously with
   * the current value once on subscribe (replay), then on each `next(v)` call.
   *
   * @param {(v: T) => void} fn  Subscriber callback.
   * @returns {() => void}       Unsubscribe function.
   */
  subscribe(fn) {
    this._subs.add(fn);
    fn(this.value);
    return () => { this._subs.delete(fn); };
  }

  /**
   * Push a new value: updates `value` and notifies every subscriber.
   *
   * @param {T} v
   */
  next(v) {
    this.value = v;
    for (const fn of this._subs) fn(v);
  }
}
