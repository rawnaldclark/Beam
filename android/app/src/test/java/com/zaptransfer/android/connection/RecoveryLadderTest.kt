package com.zaptransfer.android.connection

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for [RecoveryLadder] — the Kotlin port of
 * `extension/connection/recovery-ladder.js` (commit `dd87ae2`).
 *
 * Mirrors the Chrome JS test matrix in `extension/test/recovery-ladder.test.js`,
 * adapted to Kotlin coroutine idioms:
 *
 *   - `await flushMicrotasks()` -> `runCurrent()` on a [StandardTestDispatcher].
 *   - `clock.tick(N)` -> `testScheduler.advanceTimeBy(N)` for actions whose
 *     suspending bodies use `delay(...)`.
 *   - `r1.succeed() / r1.timeout() / r1.throw(e)` -> a controllable rung
 *     backed by a [CompletableDeferred] the test resolves manually.
 *
 * The cancellation tests verify that an action observing
 * [CoroutineScope.isActive] (or running a `delay(...)` that throws on
 * cancellation) settles correctly when [RecoveryLadder.cancel] flips the
 * ladder's latch and propagates cancellation into the in-flight rung's
 * scope.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RecoveryLadderTest {

    // ── helpers ─────────────────────────────────────────────────────────────

    /**
     * Controllable rung backed by a [CompletableDeferred]. The action
     * suspends on the deferred and observes the [CoroutineScope]'s
     * cancellation via [CompletableDeferred.await] — when the rung's
     * coroutine is cancelled, `await()` throws [kotlinx.coroutines.CancellationException]
     * and the action propagates that as a cancelled outcome.
     *
     * Tests drive the action's resolution by calling [succeed], [timeout],
     * or [throwError]. A test that wants to cover the cancellation path
     * never resolves the deferred — the cancel propagation does the work.
     */
    private class ControllableRung(name: String, budgetMs: Long = 1_000L) {
        private val deferred = CompletableDeferred<Boolean>()
        var calls = 0
            private set
        var lastScope: CoroutineScope? = null
            private set

        val rung: RecoveryRung = RecoveryRung(
            name = name,
            budgetMs = budgetMs,
            action = { scope ->
                calls += 1
                lastScope = scope
                deferred.await()
            },
        )

        fun succeed() {
            deferred.complete(true)
        }

        fun timeout() {
            deferred.complete(false)
        }

        fun throwError(t: Throwable) {
            deferred.completeExceptionally(t)
        }
    }

    // ── constructor ─────────────────────────────────────────────────────────

    @Test(expected = IllegalArgumentException::class)
    fun constructor_rejectsEmptyRungs() {
        RecoveryLadder(rungs = emptyList())
    }

    // ── sequencing ──────────────────────────────────────────────────────────

    @Test
    fun singleRung_returnsSuccess_whenActionReturnsTrue() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))

        val result = async { ladder.run() }
        runCurrent()
        assertEquals("rung1 invoked", 1, r1.calls)

        r1.succeed()
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung1"), outcome)
    }

    @Test
    fun singleRung_returnsExhausted_whenActionReturnsFalse() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))

        val result = async { ladder.run() }
        runCurrent()

        r1.timeout()
        val outcome = result.await()
        assertTrue("expected Exhausted, got $outcome", outcome is LadderResult.Exhausted)
        assertNull((outcome as LadderResult.Exhausted).lastError)
    }

    @Test
    fun twoRungs_advancesToSecond_whenFirstReturnsFalse() = runTest {
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung))

        val result = async { ladder.run() }
        runCurrent()
        assertEquals(1, r1.calls)
        assertEquals(0, r2.calls)

        r1.timeout()
        runCurrent()
        assertEquals("rung2 invoked after rung1 returned false", 1, r2.calls)

        r2.succeed()
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung2"), outcome)
    }

    @Test
    fun twoRungs_returnsExhausted_whenBothReturnFalse() = runTest {
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung))

        val result = async { ladder.run() }
        runCurrent()
        r1.timeout()
        runCurrent()
        r2.timeout()
        val outcome = result.await()
        assertTrue(outcome is LadderResult.Exhausted)
    }

    @Test
    fun twoRungs_advancesPastThrow_andStillReturnsSuccessOnSecondRung() = runTest {
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung))

        val result = async { ladder.run() }
        runCurrent()
        r1.throwError(RuntimeException("boom"))
        runCurrent()
        assertEquals("rung2 runs after rung1 threw", 1, r2.calls)

        r2.succeed()
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung2"), outcome)
    }

    @Test
    fun exhausted_includesLastError_whenFinalRungThrew() = runTest {
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung))

        val result = async { ladder.run() }
        runCurrent()
        r1.timeout()
        runCurrent()
        val err = IllegalStateException("rung-2 stub")
        r2.throwError(err)

        val outcome = result.await()
        assertTrue(outcome is LadderResult.Exhausted)
        // kotlinx [Deferred.await] runs the rethrown exception through
        // [kotlinx.coroutines.internal.recoverStackTrace] which clones the
        // throwable to splice in coroutine boundaries. Compare class +
        // message instead of reference equality.
        val lastError = (outcome as LadderResult.Exhausted).lastError
        assertNotNull(lastError)
        assertEquals(IllegalStateException::class.java, lastError!!::class.java)
        assertEquals("rung-2 stub", lastError.message)
    }

    // ── cancellation ────────────────────────────────────────────────────────

    @Test
    fun cancel_midRung_resolvesCancelled_andDoesNotAdvance() = runTest {
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung))

        val result = async { ladder.run() }
        runCurrent()
        assertEquals(1, r1.calls)

        ladder.cancel()
        // The ladder cancels the in-flight rung's coroutine; its `await()`
        // throws CancellationException which the ladder records as a
        // Cancelled outcome and exits.
        val outcome = result.await()
        assertTrue("expected Cancelled, got $outcome", outcome is LadderResult.Cancelled)
        assertEquals("rung1", (outcome as LadderResult.Cancelled).priorRung)
        assertEquals("rung2 must not run after cancel", 0, r2.calls)
    }

    @Test
    fun cancel_beforeRun_resolvesCancelled_withoutInvokingAnyRung() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))
        ladder.cancel()
        val outcome = ladder.run()
        assertTrue(outcome is LadderResult.Cancelled)
        assertNull((outcome as LadderResult.Cancelled).priorRung)
        assertEquals(0, r1.calls)
    }

    @Test
    fun cancel_isIdempotent() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))
        assertFalse(ladder.isCancelled)
        ladder.cancel()
        assertTrue(ladder.isCancelled)
        // Second cancel must not throw.
        ladder.cancel()
        assertTrue(ladder.isCancelled)
    }

    @Test
    fun cancel_overridesLateSuccess_fromTheAction() = runTest {
        // Even if the action races the cancel and reports `true`, the
        // ladder must report Cancelled — the requestReconnect-mid-ladder
        // semantics of Task 11 rely on this conservative ordering.
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung))

        val result = async { ladder.run() }
        runCurrent()

        ladder.cancel()
        // The action is cancelled before its CompletableDeferred is resolved;
        // succeed() lands on an already-cancelled deferred, which is a
        // silent no-op (CompletableDeferred.complete returns false). The
        // ladder still reports Cancelled.
        r1.succeed()
        val outcome = result.await()
        assertTrue(outcome is LadderResult.Cancelled)
        assertEquals(0, r2.calls)
    }

    @Test
    fun run_isIdempotent_returnsCachedResultOnSecondCall() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))

        val first = async { ladder.run() }
        runCurrent()
        r1.succeed()
        val firstResult = first.await()

        // Second call must return the same result without re-invoking the
        // rung action.
        val secondResult = ladder.run()
        assertEquals(firstResult, secondResult)
        assertEquals("rung action invoked only once across two run() calls", 1, r1.calls)
    }

    // ── budget-via-action timeout ───────────────────────────────────────────
    //
    // The ladder itself does NOT enforce per-rung budgets — the action owns
    // that via [withTimeoutOrNull] internally. These tests use a real delay-
    // based action to verify the integration with [StandardTestDispatcher]
    // virtual time.

    @Test
    fun action_thatTimesOutViaWithTimeoutOrNull_advancesAfterBudget() = runTest {
        // Rung 1 simulates the production rung action: best-effort send,
        // then withTimeoutOrNull on a never-emitting predicate. The rung
        // should resolve `false` after the budget elapses.
        val rung1 = RecoveryRung(
            name = "rung1",
            budgetMs = 5_000L,
            action = {
                kotlinx.coroutines.withTimeoutOrNull(5_000L) {
                    // Never completes — the budget timeout fires.
                    delay(Long.MAX_VALUE)
                    true
                } ?: false
            },
        )
        val r2 = ControllableRung("rung2")
        val ladder = RecoveryLadder(listOf(rung1, r2.rung))

        val result = async { ladder.run() }
        runCurrent()
        // Advance past the budget — withTimeoutOrNull resolves null, action
        // returns false, ladder advances to rung2.
        advanceTimeBy(5_001L)
        runCurrent()
        assertEquals("rung2 invoked after rung1 budget elapsed", 1, r2.calls)

        r2.succeed()
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung2"), outcome)
    }

    @Test
    fun action_returningTrueWithinBudget_resolvesSuccess() = runTest {
        // The "action returns true before budget" path: withTimeoutOrNull
        // wins and we report Success.
        val resolved = CompletableDeferred<Unit>()
        val rung1 = RecoveryRung(
            name = "rung1",
            budgetMs = 5_000L,
            action = {
                kotlinx.coroutines.withTimeoutOrNull(5_000L) {
                    resolved.await()
                    true
                } ?: false
            },
        )
        val ladder = RecoveryLadder(listOf(rung1))

        val result = async { ladder.run() }
        runCurrent()
        // 1s in, the predicate fires.
        advanceTimeBy(1_000L)
        resolved.complete(Unit)
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung1"), outcome)
    }

    // ── ordering / scope plumbing ───────────────────────────────────────────

    @Test
    fun action_receivesACoroutineScope_thatIsActiveBeforeCancel() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))

        val result = async { ladder.run() }
        runCurrent()
        assertNotNull("action received a scope", r1.lastScope)
        assertTrue(
            "scope is active before cancel",
            r1.lastScope!!.coroutineContext[kotlinx.coroutines.Job]!!.isActive,
        )

        r1.succeed()
        result.await()
    }

    @Test
    fun cancel_propagatesIntoTheActionsScope() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))

        val result = async { ladder.run() }
        runCurrent()
        val scope = r1.lastScope!!

        ladder.cancel()
        // After cancel, the rung's scope should no longer be active — the
        // ladder cancelled its child Job.
        runCurrent()
        assertFalse(
            "scope is no longer active after cancel",
            scope.coroutineContext[kotlinx.coroutines.Job]!!.isActive,
        )
        result.await()
    }

    @Test
    fun threeRungs_runsInOrder_stoppingAtFirstSuccess() = runTest {
        val r1 = ControllableRung("rung1")
        val r2 = ControllableRung("rung2")
        val r3 = ControllableRung("rung3")
        val ladder = RecoveryLadder(listOf(r1.rung, r2.rung, r3.rung))

        val result = async { ladder.run() }
        runCurrent()

        r1.timeout()
        runCurrent()
        r2.succeed()
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung2"), outcome)
        assertEquals("rung3 must not run after rung2 succeeded", 0, r3.calls)
    }

    // ── cancel-after-settle ─────────────────────────────────────────────────

    @Test
    fun cancel_afterSettle_isANoOp() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))

        val result = async { ladder.run() }
        runCurrent()
        r1.succeed()
        val outcome = result.await()
        assertEquals(LadderResult.Success(rung = "rung1"), outcome)

        // Post-settle cancel: must not throw, must not flip the result.
        ladder.cancel()
        assertTrue(ladder.isCancelled)
        // Re-running returns the same cached result.
        val again = ladder.run()
        assertEquals(outcome, again)
    }

    // ── parent-coroutine cancellation propagates structural concurrency ────

    @Test
    fun parentScopeCancellation_unwindsTheLadder() = runTest {
        val r1 = ControllableRung("rung1")
        val ladder = RecoveryLadder(listOf(r1.rung))
        val dispatcher = StandardTestDispatcher(testScheduler)
        val parent = CoroutineScope(dispatcher)

        val job = parent.launch {
            ladder.run()
        }
        advanceUntilIdle()
        assertEquals(1, r1.calls)

        // Cancel the parent — the ladder's run() should unwind via
        // CancellationException without leaking.
        parent.cancel()
        advanceUntilIdle()
        assertTrue("launched job is cancelled", job.isCancelled)
    }

}
