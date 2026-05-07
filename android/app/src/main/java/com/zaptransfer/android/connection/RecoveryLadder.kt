package com.zaptransfer.android.connection

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.supervisorScope
import java.util.concurrent.atomic.AtomicBoolean

private const val TAG = "RecoveryLadder"

/**
 * One step of a [RecoveryLadder].
 *
 * Mirror of the JS `{name, budgetMs, action}` object shape in
 * `extension/connection/recovery-ladder.js`. The action is invoked with a
 * [CoroutineScope] whose cancellation flips when [RecoveryLadder.cancel] is
 * called — actions MUST observe that cancellation (via a `withTimeout` /
 * `select` / cooperative `isActive` check inside their suspending helpers)
 * to tear down their subscriptions and timers cleanly. Otherwise
 * cancellation leaks.
 *
 * @property name Short identifier used in logs (`rung1`, `rung2`, ...).
 * @property budgetMs Informational — the action owns its own timeout via
 *           `kotlinx.coroutines.withTimeoutOrNull(budgetMs) { ... }`. The
 *           ladder logs per-rung elapsed time but does not enforce the
 *           budget itself.
 * @property action `suspend (CoroutineScope) -> Boolean` — returns `true`
 *           if the rung recovered, `false` if it timed out / surrendered.
 *           A thrown action advances to the next rung the same as `false`.
 *           The provided [CoroutineScope] is the rung's cancellation scope:
 *           cancelling it (via [RecoveryLadder.cancel]) propagates through
 *           any structured-concurrency helpers the action launches.
 */
data class RecoveryRung(
    val name: String,
    val budgetMs: Long,
    val action: suspend (CoroutineScope) -> Boolean,
)

/**
 * Result of a [RecoveryLadder.run] invocation.
 *
 * Mirror of the JS `LadderResult` shape `{ok, rung?, cancelled?, exhausted?,
 * lastError?}` from `extension/connection/recovery-ladder.js`. Modelled as a
 * sealed class so `when` branches are exhaustive at compile time.
 *
 *  - [Success]   The named rung recovered. `ok = true`.
 *  - [Cancelled] [RecoveryLadder.cancel] drove the exit. `ok = false`.
 *                `priorRung` is the name of the rung in flight when cancel
 *                landed (or `null` if cancel landed before any rung ran).
 *  - [Exhausted] Every rung returned false / threw. `ok = false`.
 *                `lastError` carries the most recent action throw (or null
 *                if every rung returned false rather than throwing).
 */
sealed class LadderResult {
    abstract val ok: Boolean

    /** A rung's action returned `true`. */
    data class Success(val rung: String) : LadderResult() {
        override val ok = true
    }

    /** [RecoveryLadder.cancel] was invoked during or before the ladder ran. */
    data class Cancelled(val priorRung: String?) : LadderResult() {
        override val ok = false
    }

    /** Every rung returned `false` or threw. */
    data class Exhausted(val lastError: Throwable? = null) : LadderResult() {
        override val ok = false
    }
}

/**
 * Sequential, cancelable runner for an ordered list of [RecoveryRung]s.
 *
 * Mirror of `extension/connection/recovery-ladder.js` (commit `dd87ae2`).
 * Used by [ConnectionAuthority] to recover from `peerHealth = FAILED` or
 * `selfState = RECONNECTING`. The ladder owns sequencing, logging, and
 * cancellation; each rung's [RecoveryRung.action] owns its own success-
 * signal subscription and budget-timer.
 *
 * ### Semantics
 *  - Rungs run strictly sequentially. The first action returning `true`
 *    ends the ladder with [LadderResult.Success].
 *  - An action returning `false` (or throwing) advances to the next rung.
 *  - If [cancel] is called, the in-flight rung's [CoroutineScope] is
 *    cancelled and the ladder resolves with [LadderResult.Cancelled] after
 *    the action settles. No further rungs are attempted.
 *  - If every rung fails without cancellation, the result is
 *    [LadderResult.Exhausted].
 *
 * ### Logging
 * Each phase emits a `[CA] ladder: ...` line so cross-platform diagnostic
 * dumps line up with Chrome's [extension/connection/recovery-ladder.js]:
 *  - `[CA] ladder: rung=N start`        on entry.
 *  - `[CA] ladder: rung=N ok t=X.Xs`    on success.
 *  - `[CA] ladder: rung=N timeout t=X.Xs` on action returning false.
 *  - `[CA] ladder: rung=N error t=X.Xs <message>` on throw.
 *  - `[CA] ladder: cancelled`           on cancel-driven exit.
 *
 * ### Threading
 * [run] is `suspend` and runs entirely on the caller's coroutine context.
 * The expected caller is [ConnectionAuthority]'s single-threaded worker
 * scope (`scope.launch { ladder.run() }`), which inherits the same
 * confinement guarantees as the rest of the authority. [cancel] is safe to
 * call from any thread.
 *
 * Spec: `docs/superpowers/specs/2026-05-02-connection-authority-design.md`
 *       §"Recovery ladder".
 */
class RecoveryLadder(private val rungs: List<RecoveryRung>) {

    init {
        require(rungs.isNotEmpty()) { "RecoveryLadder: rungs must be non-empty" }
    }

    /**
     * Cancellation latch. Flips on [cancel]; checked between rungs and read
     * after each rung settles to decide between [LadderResult.Success] /
     * [LadderResult.Cancelled] when the action and cancel race.
     */
    private val cancelled = AtomicBoolean(false)

    /**
     * Holds the in-flight rung's [Job] so [cancel] can propagate
     * cancellation into its [CoroutineScope]. Cleared between rungs.
     */
    @Volatile
    private var inFlightJob: Job? = null

    /**
     * Cached result for [run] idempotency. The [CompletableDeferred] is
     * completed once the first call to [run] settles, and any subsequent
     * call simply awaits it.
     */
    private val resultLatch = CompletableDeferred<LadderResult>()

    /** Guards against re-entering [runInternal] on a second [run] call. */
    private val started = AtomicBoolean(false)

    /** Wall-clock-equivalent — uses [System.nanoTime] to measure rung elapsed. */
    private fun now(): Long = System.nanoTime() / 1_000_000L

    /**
     * Walk every rung in order, returning early on the first success or on
     * cancellation. Idempotent — a second call awaits the same result.
     *
     * Returns one of [LadderResult.Success] / [LadderResult.Cancelled] /
     * [LadderResult.Exhausted]. Never throws.
     */
    suspend fun run(): LadderResult {
        if (started.compareAndSet(false, true)) {
            // First invocation — actually walk the rungs and settle the
            // shared latch with the outcome.
            val result = runInternal()
            resultLatch.complete(result)
            return result
        }
        // Second / Nth invocation — await the cached outcome.
        return resultLatch.await()
    }

    /**
     * Signal the in-flight rung to abort and stop the ladder.
     *
     * Safe to call before, during, or after [run]. The [run] suspension
     * resolves with [LadderResult.Cancelled] once the in-flight action has
     * settled in response to the cancellation. Idempotent — a second call
     * is a silent no-op.
     */
    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        // Cancel the in-flight rung's coroutine scope. Job.cancel() is a
        // no-op if the rung has already completed; the next-rung guard in
        // runInternal observes the cancelled flag and surrenders before
        // launching the next action.
        inFlightJob?.cancel()
    }

    /** True after [cancel] has been called. */
    val isCancelled: Boolean get() = cancelled.get()

    // ── internals ───────────────────────────────────────────────────────────

    private suspend fun runInternal(): LadderResult {
        var lastError: Throwable? = null
        var priorRung: String? = null

        for (rung in rungs) {
            // Cancellation between rungs: surrender immediately. priorRung
            // carries the most recently-attempted rung's name (or null if
            // cancel landed before any rung ran).
            if (cancelled.get()) {
                Log.i(TAG, "[CA] ladder: cancelled")
                return LadderResult.Cancelled(priorRung)
            }

            priorRung = rung.name
            val startedAt = now()
            Log.i(TAG, "[CA] ladder: rung=${rung.name} start")

            // Run the action inside a `supervisorScope` so we can cancel
            // its child Job via [cancel] without that cancellation
            // propagating up to the caller's scope. We hold a reference to
            // the child [Deferred] so [cancel] can target it cooperatively.
            // The supervisorScope block waits for the child to settle (or
            // for cancellation to drain) before returning.
            //
            // `supervisorScope` (vs `coroutineScope`) is the right choice
            // here because the rung's [Job] failure is a domain outcome,
            // not a parent-cancellation event — we want a thrown action to
            // bubble through `await()` as a normal exception we catch and
            // log, NOT to cancel the ladder's caller.
            val actionResult: ActionOutcome = supervisorScope {
                val deferred: Deferred<Boolean> = async { rung.action(this) }
                inFlightJob = deferred
                try {
                    ActionOutcome.Returned(deferred.await())
                } catch (ce: CancellationException) {
                    // The async call was cancelled — almost always via
                    // [cancel] flipping the latch and calling
                    // `inFlightJob?.cancel()`. The cancelled flag check
                    // below decides Cancelled vs. caller-cancellation
                    // rethrow.
                    ActionOutcome.Cancelled
                } catch (e: Throwable) {
                    ActionOutcome.Threw(e)
                } finally {
                    inFlightJob = null
                }
            }

            val elapsedMs = now() - startedAt

            when (actionResult) {
                is ActionOutcome.Cancelled -> {
                    // The rung observed cancellation. Per spec, this is a
                    // ladder-level cancel result regardless of any value
                    // the action might have computed.
                    Log.i(TAG, "[CA] ladder: cancelled")
                    return LadderResult.Cancelled(priorRung)
                }
                is ActionOutcome.Threw -> {
                    val err = (actionResult as ActionOutcome.Threw).error
                    lastError = err
                    Log.i(
                        TAG,
                        "[CA] ladder: rung=${rung.name} error t=${fmtSeconds(elapsedMs)}s ${err.message}",
                    )
                    // If cancel landed mid-throw, honour it.
                    if (cancelled.get()) {
                        Log.i(TAG, "[CA] ladder: cancelled")
                        return LadderResult.Cancelled(priorRung)
                    }
                    // Otherwise treat throw the same as `false`: advance.
                    continue
                }
                is ActionOutcome.Returned -> {
                    val ok = (actionResult as ActionOutcome.Returned).value
                    // Cancel-during-action ordering: if the user called
                    // cancel() mid-action and the action still resolved
                    // truthy, surrender the success and report cancelled.
                    // This is conservative but correct — the spec's
                    // requestReconnect path (Task 11, later) wants the new
                    // ladder to own the recovery state machine regardless.
                    if (cancelled.get()) {
                        Log.i(TAG, "[CA] ladder: cancelled")
                        return LadderResult.Cancelled(priorRung)
                    }
                    if (ok) {
                        Log.i(TAG, "[CA] ladder: rung=${rung.name} ok t=${fmtSeconds(elapsedMs)}s")
                        return LadderResult.Success(rung.name)
                    }
                    Log.i(TAG, "[CA] ladder: rung=${rung.name} timeout t=${fmtSeconds(elapsedMs)}s")
                    // Continue to the next rung.
                }
            }
        }

        // Every rung ran and surrendered (false or throw) without
        // cancellation — exhausted.
        return LadderResult.Exhausted(lastError)
    }

    /**
     * Tri-state outcome of a single rung's action invocation. We can't fold
     * this into [LadderResult] because the post-action loop branches on the
     * specific case (advance vs surrender vs return) before the ladder
     * settles its overall result.
     */
    private sealed class ActionOutcome {
        /** Action returned a boolean cleanly. */
        data class Returned(val value: Boolean) : ActionOutcome()

        /** Action threw a non-cancellation exception. */
        data class Threw(val error: Throwable) : ActionOutcome()

        /** Action's coroutine was cancelled (via [RecoveryLadder.cancel]). */
        object Cancelled : ActionOutcome()
    }

    private fun fmtSeconds(ms: Long): String {
        // One decimal place, matching the Chrome `(ms / 1000).toFixed(1)` output.
        val tenths = (ms + 50) / 100   // round to nearest tenth-of-a-second
        return "${tenths / 10}.${tenths % 10}"
    }
}
