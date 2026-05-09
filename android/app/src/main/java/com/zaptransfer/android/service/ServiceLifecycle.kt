package com.zaptransfer.android.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Coarse lifecycle of the [TransferForegroundService] exposed as a hot
 * [StateFlow] so other components (in particular
 * [com.zaptransfer.android.connection.ConnectionAuthority]'s recovery ladder
 * Rung 3) can react to start/stop transitions without taking a hard
 * dependency on the service class itself.
 *
 * ### Why a singleton, not a service-scoped object
 * The recovery ladder's Rung 3 dispatches a `STOP_SERVICE` Intent and then
 * waits for the service's `onDestroy` to land before issuing a fresh
 * `START_SERVICE`. The service singleton is destroyed during that window,
 * so the lifecycle observable cannot live on the service itself —
 * it is a process-scoped Hilt singleton injected into both the service and
 * the authority.
 *
 * ### Threading
 * The [MutableStateFlow] is documented thread-safe. [dispatch] may be called
 * from any thread (the Android service lifecycle runs on the main thread;
 * the authority's worker runs on a single-threaded `Dispatchers.Default`
 * slice). No additional synchronization is required.
 */
@Singleton
class ServiceLifecycle @Inject constructor() {

    private val _state = MutableStateFlow<ServiceState>(ServiceState.Stopped)

    /**
     * Hot [StateFlow] of the current [ServiceState]. Initial value is
     * [ServiceState.Stopped] (no service has been created yet).
     */
    val state: StateFlow<ServiceState> = _state.asStateFlow()

    /**
     * Publish a new lifecycle state. Idempotent — re-dispatching the same
     * state is a no-op as far as [StateFlow] is concerned (it dedupes by
     * equality).
     */
    fun dispatch(next: ServiceState) {
        _state.value = next
    }
}

/**
 * Coarse lifecycle states for [TransferForegroundService].
 *
 * The Rung 3 action consults this flow with the predicate
 * `state === Running` (start success) or `state === Stopped` (stop
 * confirmed). [Starting] and [Stopping] are intermediate states for
 * observability — the ladder action does not gate on them, but UI / debug
 * surfaces can render them.
 */
sealed class ServiceState {
    /** Service has not been started, or was destroyed and not restarted. */
    object Stopped : ServiceState()

    /** `onCreate` has fired; `onStartCommand` may not yet have completed. */
    object Starting : ServiceState()

    /** `onStartCommand` returned `START_STICKY` and the service is alive. */
    object Running : ServiceState()

    /** `onDestroy` has begun (e.g. `stopService` Intent processed). */
    object Stopping : ServiceState()
}
