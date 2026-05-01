package com.zaptransfer.android.crypto

import android.util.Base64
import android.util.Log
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
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
                    delivery?.onClipboardReceived(content, fromDeviceId)
                        ?: Log.w(TAG, "onClipboardReceived: no delivery wired")
                }
                override suspend fun onFileReceived(args: BeamV2Transport.FileDelivery) {
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
