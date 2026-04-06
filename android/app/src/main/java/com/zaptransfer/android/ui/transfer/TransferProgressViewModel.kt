package com.zaptransfer.android.ui.transfer

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.service.NetworkState
import com.zaptransfer.android.service.NetworkMonitor
import com.zaptransfer.android.service.Transport
import com.zaptransfer.android.service.TransferEngine
import com.zaptransfer.android.service.TransferProgress
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * ViewModel for [TransferProgressScreen].
 *
 * Bridges [TransferEngine.progress] and [NetworkMonitor.state] into simple UI-consumable
 * [StateFlow]s. No business logic lives here — this ViewModel is purely an adapter.
 *
 * @param transferEngine  Observes the live progress map for all active transfers.
 * @param networkMonitor  Provides the current network transport type for the connection chip.
 */
@HiltViewModel
class TransferProgressViewModel @Inject constructor(
    transferEngine: TransferEngine,
    networkMonitor: NetworkMonitor,
) : ViewModel() {

    /**
     * Live map of all active transfer snapshots, keyed by transfer ID.
     *
     * The screen looks up its specific transfer by the [transferId] nav argument.
     * Using the full map rather than filtering inside the ViewModel keeps the flow
     * hot and avoids restarting the upstream on navigation.
     */
    val progress: StateFlow<Map<String, TransferProgress>> = transferEngine.progress

    /**
     * Human-readable connection type label for the connection chip.
     *
     *  - "Local WiFi" when [Transport.WIFI] is active (indicates a P2P path is possible)
     *  - "Wired (Ethernet)" for [Transport.ETHERNET]
     *  - "Cellular" for [Transport.CELLULAR] (relay-only; higher latency expected)
     *  - "Relay" when there is no network (fallback / unresolved transport)
     */
    val connectionLabel: StateFlow<String> = networkMonitor.state
        .map { state ->
            when (state) {
                is NetworkState.Connected -> when (state.transport) {
                    Transport.WIFI -> "Local WiFi"
                    Transport.ETHERNET -> "Wired (Ethernet)"
                    Transport.CELLULAR -> "Cellular"
                }
                NetworkState.Disconnected -> "Relay"
            }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = "Connecting…",
        )
}
