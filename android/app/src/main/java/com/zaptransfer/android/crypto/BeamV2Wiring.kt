package com.zaptransfer.android.crypto

import android.content.Context
import android.content.Intent
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import com.zaptransfer.android.connection.ConnectionAuthority
import com.zaptransfer.android.connection.RUNG_3_STOP_TIMEOUT_MS
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.service.ACTION_STOP_SERVICE
import com.zaptransfer.android.service.ServiceLifecycle
import com.zaptransfer.android.service.ServiceState
import com.zaptransfer.android.service.TransferForegroundService
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Singleton glue between the [BeamV2Transport] state machine and the
 * Android-side dependencies it needs (key store, paired-device store,
 * signaling socket, and delivery callbacks).
 *
 * Construct once at app start (Hilt @Singleton). [TransferEngine] queries
 * [transport] for the active [BeamV2Transport] instance and forwards
 * incoming relay frames into it.
 *
 * Delivery callbacks are wired via [setDelivery] AFTER construction so that
 * [TransferEngine] (which the wiring transitively depends on) avoids a
 * circular DI graph.
 */
@Singleton
class BeamV2Wiring @Inject constructor(
    private val signalingClient: SignalingClient,
    private val deviceRepo: DeviceRepository,
    private val keyManager: KeyManager,
    private val connectionAuthority: ConnectionAuthority,
    @ApplicationContext private val appContext: Context,
    private val serviceLifecycle: ServiceLifecycle,
) {

    interface Delivery {
        suspend fun onClipboardReceived(content: String, fromDeviceId: String)
        suspend fun onFileReceived(args: BeamV2Transport.FileDelivery)
        fun onSendError(transferIdHex: String, code: String) {}
        fun onReceiveError(transferIdHex: String, code: String) {}
    }

    private var delivery: Delivery? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Public so call sites (DeviceHubViewModel, TransferEngine) can drive
     * sendClipboard / sendFile / rotateKAB. Single instance for the app —
     * all v2 state lives behind this reference.
     */
    val transport: BeamV2Transport by lazy { build() }

    init {
        // Step G: install the production [ConnectionAuthority.forceFullReset]
        // hook. This wiring resolves the BeamV2Wiring ↔ ConnectionAuthority
        // Hilt cycle: the authority's @Inject constructor cannot take a
        // BeamV2Wiring (BeamV2Wiring already injects authority), so the
        // hook is bound post-construction here. Until this init runs, the
        // authority is in skeleton mode (Rung 3 surrenders synchronously,
        // logged via Log.w from `rung3Action`).
        connectionAuthority.setForceFullReset(buildForceFullResetHook())

        // The wiring class is the SINGLE place that routes v2 frames into
        // the transport. Other listeners (TransferEngine, DeviceHubViewModel)
        // MUST skip BEA2-prefixed binary frames and beam-v2-* JSON to avoid
        // double delivery.
        signalingClient.addListener(object : SignalingListener {
            override fun onMessage(message: RelayMessage) {
                when (message) {
                    is RelayMessage.Binary -> {
                        val b = message.data
                        if (b.size >= 4 && b[0] == 0x42.toByte() && b[1] == 0x45.toByte() &&
                            b[2] == 0x41.toByte() && b[3] == 0x32.toByte()
                        ) {
                            scope.launch {
                                runCatching { transport.handleIncomingFrame(b) }
                                    .onFailure { Log.e(TAG, "v2 handleIncomingFrame failed: ${it.message}", it) }
                            }
                        }
                    }
                    is RelayMessage.Text -> {
                        val type = message.json.optString("type")
                        if (type.startsWith("beam-v2-")) {
                            scope.launch {
                                runCatching { transport.handleJsonMessage(message.json) }
                                    .onFailure { Log.e(TAG, "v2 handleJsonMessage failed: ${it.message}", it) }
                            }
                        }
                    }
                }
            }
        })
    }

    /**
     * Register the delivery callback. MUST be called from app start
     * (typically by [TransferEngine] in its `init`) before any incoming
     * frame can be processed.
     */
    fun setDelivery(d: Delivery) {
        delivery = d
    }

    /**
     * Drop the cached transport's in-flight bookkeeping (outbox, inbox,
     * pendingRotations) so any state a stale session accumulated does not
     * survive the recovery ladder's Rung 3 ("full session reset"). Mirror
     * of Chrome's `_resetTransportSingleton()` in
     * `extension/crypto/beam-v2-wiring.js`.
     *
     * Called by the [forceFullReset] hook installed in [init] AFTER the
     * service has reached [ServiceState.Stopped] and BEFORE the
     * `startForegroundService` Intent is dispatched — clearing while the
     * old service is still alive could race the next-incoming frame.
     *
     * Safe to call from any thread (delegates to [BeamV2Transport.clearInMemoryState]
     * which uses [java.util.concurrent.ConcurrentHashMap]).
     */
    fun clearInMemoryState() {
        transport.clearInMemoryState()
    }

    /**
     * Build the production Rung-3 "full session reset" hook. Spec §"Rung 3
     * — Full session reset" Android steps mapped onto this lambda:
     *
     *   1. Dispatch [ACTION_STOP_SERVICE] Intent → service.onDestroy →
     *      [ServiceLifecycle] dispatches [ServiceState.Stopped].
     *   2. Await [ServiceState.Stopped] within [RUNG_3_STOP_TIMEOUT_MS]
     *      (10s). On timeout: surrender — the lambda returns without
     *      clearing state or restarting; `rung3Action`'s outer
     *      `RUNG_3_BUDGET_MS` (30s) timer fires, the rung returns false,
     *      ladder advances to Rung 4.
     *   3. Clear in-memory transport state.
     *   6. Dispatch a fresh `startForegroundService` Intent → service
     *      onCreate → [ServiceLifecycle] dispatches [ServiceState.Running].
     *
     * Steps 4-5 (reload paired devices from Room, re-init crypto from
     * KeyManager) happen automatically as the new service instance comes
     * up — neither is a side-effect this hook drives.
     *
     * The lambda's parent scope is the rung's `CoroutineScope` provided
     * by [com.zaptransfer.android.connection.RecoveryLadder] —
     * cancellation propagates here as a [kotlinx.coroutines.CancellationException]
     * out of [withTimeoutOrNull] / [kotlinx.coroutines.flow.Flow.first]
     * cooperatively.
     */
    private fun buildForceFullResetHook(): suspend () -> Unit = ::forceFullReset

    /**
     * Body of the [ConnectionAuthority.forceFullReset] hook. See
     * [buildForceFullResetHook] for spec mapping.
     */
    private suspend fun forceFullReset() {
        if (serviceLifecycle.state.value !== ServiceState.Stopped) {
            // Step 1: dispatch ACTION_STOP_SERVICE Intent.
            val stopIntent = Intent(appContext, TransferForegroundService::class.java).apply {
                action = ACTION_STOP_SERVICE
            }
            try {
                appContext.startService(stopIntent)
            } catch (e: IllegalStateException) {
                // Background-start exception on API 26+ when the app is
                // backgrounded. Fall through to the await — if the
                // service happens to be already stopping (e.g. the OS
                // killed it for resources), the lifecycle flow will
                // surface `Stopped` and we proceed.
                Log.w(TAG, "forceFullReset: stopService failed; continuing to await", e)
            }

            // Step 2: await Stopped within RUNG_3_STOP_TIMEOUT_MS.
            val stopped = withTimeoutOrNull(RUNG_3_STOP_TIMEOUT_MS) {
                serviceLifecycle.state.first { it === ServiceState.Stopped }
                true
            }
            if (stopped == null) {
                Log.w(
                    TAG,
                    "forceFullReset: service did not reach STOPPED within " +
                        "${RUNG_3_STOP_TIMEOUT_MS}ms; surrendering Rung 3",
                )
                return
            }
        }

        // Step 3: clear in-memory transport state.
        clearInMemoryState()

        // Step 6: dispatch a fresh startForegroundService Intent. The new
        // service instance's onCreate will dispatch Starting then Running;
        // `rung3Action`'s outer combine awaits Running.
        val startIntent = Intent(appContext, TransferForegroundService::class.java)
        try {
            ContextCompat.startForegroundService(appContext, startIntent)
        } catch (e: IllegalStateException) {
            Log.w(TAG, "forceFullReset: startForegroundService failed", e)
            // Do not throw — let `rung3Action` surrender via its outer
            // budget timer rather than escalate this lambda's failure.
        }
    }

    private fun build(): BeamV2Transport {
        return BeamV2Transport(
            sendJson = { msg ->
                signalingClient.send(msg)
            },
            sendBinary = { bytes ->
                signalingClient.sendBinary(bytes)
            },
            hooks = object : BeamV2Transport.Hooks {
                override suspend fun getPeer(deviceId: String): BeamV2Transport.PairedPeer? {
                    val entity = deviceRepo.getDevice(deviceId) ?: return null
                    return toPairedPeer(entity)
                }
                override suspend fun listPeers(): List<BeamV2Transport.PairedPeer> {
                    val entities = deviceRepo.listDevices()
                    return entities.mapNotNull { toPairedPeer(it) }
                }
                override suspend fun storeKABRing(deviceId: String, ring: BeamV2Transport.KABRing) {
                    val json = serializeRing(ring)
                    deviceRepo.updateKABRing(deviceId, json)
                }
                override suspend fun onClipboardReceived(content: String, fromDeviceId: String) {
                    // A successful inbound v2 clipboard frame is strong proof
                    // of life — promote the peer to HEALTHY in the authority.
                    connectionAuthority.notifyFrameReceived(fromDeviceId)
                    delivery?.onClipboardReceived(content, fromDeviceId)
                        ?: Log.w(TAG, "onClipboardReceived: no delivery wired")
                }
                override suspend fun onFileReceived(args: BeamV2Transport.FileDelivery) {
                    // A successful inbound v2 file frame is strong proof of
                    // life — promote the peer to HEALTHY in the authority.
                    connectionAuthority.notifyFrameReceived(args.fromDeviceId)
                    delivery?.onFileReceived(args)
                        ?: Log.w(TAG, "onFileReceived: no delivery wired")
                }
                override fun onSendError(transferIdHex: String, code: String) {
                    delivery?.onSendError(transferIdHex, code)
                }
                override fun onReceiveError(transferIdHex: String, code: String) {
                    delivery?.onReceiveError(transferIdHex, code)
                }
                override fun ourDeviceId(): String? {
                    return runCatching {
                        val keys = keyManager.getOrCreateKeys()
                        keyManager.deriveDeviceId(keys.ed25519Pk)
                    }.getOrNull()
                }
            },
            scope = scope,
        )
    }

    /**
     * Convert a [com.zaptransfer.android.data.db.entity.PairedDeviceEntity]
     * into the transport's [BeamV2Transport.PairedPeer] shape, decoding the
     * JSON-serialised K_AB ring.
     */
    private fun toPairedPeer(
        entity: com.zaptransfer.android.data.db.entity.PairedDeviceEntity,
    ): BeamV2Transport.PairedPeer? {
        val ring = parseRing(entity.kABRingJson) ?: return null
        val ourKeys = keyManager.getOrCreateKeys()
        return BeamV2Transport.PairedPeer(
            deviceId  = entity.deviceId,
            ourSk     = ourKeys.x25519Sk,
            peerPk    = entity.x25519PublicKey,
            ourEdPk   = ourKeys.ed25519Pk,
            peerEdPk  = entity.ed25519PublicKey,
            kABRing   = ring,
        )
    }

    private fun parseRing(json: String): BeamV2Transport.KABRing? {
        if (json.isBlank()) return null
        return try {
            val obj = JSONObject(json)
            val keysObj = obj.getJSONObject("keys")
            val keys = mutableMapOf<Int, BeamV2Transport.KABEntry>()
            for (k in keysObj.keys()) {
                val gen = k.toIntOrNull() ?: continue
                val entry = keysObj.getJSONObject(k)
                val kABHex = entry.getString("kAB")
                val kAB = ByteArray(kABHex.length / 2)
                for (i in kAB.indices) {
                    kAB[i] = ((Character.digit(kABHex[i * 2], 16) shl 4) or
                              Character.digit(kABHex[i * 2 + 1], 16)).toByte()
                }
                val expiresAt = if (entry.has("expiresAt")) entry.optLong("expiresAt").takeIf { it > 0 } else null
                keys[gen] = BeamV2Transport.KABEntry(
                    kAB = kAB,
                    expiresAt = expiresAt,
                    rotateNonce = if (entry.has("rotateNonce")) Base64.decode(entry.getString("rotateNonce"), Base64.NO_WRAP) else null,
                    createdAt = entry.optLong("createdAt", System.currentTimeMillis()),
                )
            }
            BeamV2Transport.KABRing(
                currentGeneration = obj.getInt("currentGeneration"),
                keys = keys,
            )
        } catch (e: Exception) {
            Log.e(TAG, "parseRing failed: ${e.message}", e)
            null
        }
    }

    private fun serializeRing(ring: BeamV2Transport.KABRing): String {
        val keysObj = JSONObject()
        for ((gen, entry) in ring.keys) {
            val o = JSONObject().apply {
                put("kAB", entry.kAB.joinToString("") { "%02x".format(it) })
                put("createdAt", entry.createdAt)
                if (entry.expiresAt != null) put("expiresAt", entry.expiresAt)
                if (entry.rotateNonce != null) {
                    put("rotateNonce", Base64.encodeToString(entry.rotateNonce, Base64.NO_WRAP))
                }
            }
            keysObj.put(gen.toString(), o)
        }
        return JSONObject().apply {
            put("currentGeneration", ring.currentGeneration)
            put("keys", keysObj)
        }.toString()
    }

    companion object {
        private const val TAG = "BeamV2Wiring"
    }
}
