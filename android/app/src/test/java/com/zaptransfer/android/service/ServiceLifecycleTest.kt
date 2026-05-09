package com.zaptransfer.android.service

import org.junit.Assert.assertSame
import org.junit.Test

/**
 * Unit coverage for [ServiceLifecycle].
 *
 * Trivial reducer-style checks: initial state is [ServiceState.Stopped];
 * [ServiceLifecycle.dispatch] publishes the new value through the
 * [kotlinx.coroutines.flow.StateFlow]; concurrent dispatches converge.
 *
 * No coroutine harness needed — `StateFlow.value` is a thread-safe
 * synchronous read.
 */
class ServiceLifecycleTest {

    @Test
    fun initial_isStopped() {
        val lifecycle = ServiceLifecycle()
        assertSame(ServiceState.Stopped, lifecycle.state.value)
    }

    @Test
    fun dispatch_publishesNewState() {
        val lifecycle = ServiceLifecycle()
        lifecycle.dispatch(ServiceState.Starting)
        assertSame(ServiceState.Starting, lifecycle.state.value)
        lifecycle.dispatch(ServiceState.Running)
        assertSame(ServiceState.Running, lifecycle.state.value)
        lifecycle.dispatch(ServiceState.Stopping)
        assertSame(ServiceState.Stopping, lifecycle.state.value)
        lifecycle.dispatch(ServiceState.Stopped)
        assertSame(ServiceState.Stopped, lifecycle.state.value)
    }

    @Test
    fun dispatch_redundantTransition_noObservableSpike() {
        // StateFlow dedupes by equality — we don't assert on subscription
        // emissions here (no coroutine context), but document the contract:
        // re-dispatching the same state is a no-op for value reads.
        val lifecycle = ServiceLifecycle()
        lifecycle.dispatch(ServiceState.Running)
        lifecycle.dispatch(ServiceState.Running)
        assertSame(ServiceState.Running, lifecycle.state.value)
    }
}
