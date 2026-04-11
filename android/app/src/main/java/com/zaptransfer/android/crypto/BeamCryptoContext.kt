package com.zaptransfer.android.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.zaptransfer.android.data.db.dao.PairedDeviceDao
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Beam E2E encryption — application-scoped crypto context for Android.
 *
 * Mirrors `extension/crypto/beam-crypto-context.js` in purpose:
 * lazily assembles the [BeamCipher] + [BeamSessionRegistry] for the
 * active device identity and provides peer static key lookups against
 * the paired-devices table.
 *
 * The registry lives for the lifetime of the app process. It is NOT
 * rebuilt when the paired devices change because peer public keys are
 * resolved on demand at handshake time via [peerStaticPk].
 */
@Singleton
class BeamCryptoContext @Inject constructor(
    private val keyManager: KeyManager,
    private val pairedDeviceDao: PairedDeviceDao,
) {
    private val sodium = LazySodiumAndroid(SodiumAndroid())

    /**
     * Long-lived cipher for primitive operations. Thread-safe: all methods
     * are pure functions over their inputs.
     */
    val cipher: BeamCipher = BeamCipher(sodium)

    /**
     * Session registry — holds per-transfer state through the Triple-DH
     * handshake and for the active encrypted transfer. Singleton so that
     * every ViewModel, foreground service, or worker sees the same state.
     */
    val registry: BeamSessionRegistry by lazy {
        val keys = keyManager.getOrCreateKeys()
        BeamSessionRegistry(
            cipher = cipher,
            ourStaticSk = keys.x25519Sk,
            ourStaticPk = keys.x25519Pk,
        )
    }

    /**
     * Our Ed25519-derived deviceId, matching whatever the signaling layer
     * uses for this device.
     */
    val ourDeviceId: String by lazy {
        val keys = keyManager.getOrCreateKeys()
        keyManager.deriveDeviceId(keys.ed25519Pk)
    }

    /** Our raw 32-byte X25519 public key — needed as the "B" arg in handshake transcript hashes. */
    val ourStaticPk: ByteArray by lazy { keyManager.getOrCreateKeys().x25519Pk }

    /**
     * Look up the peer's static X25519 public key by device ID. Returns
     * null if the device is not in the paired roster. Suspends briefly on
     * the Room query.
     */
    suspend fun peerStaticPk(deviceId: String): ByteArray? {
        val entity = pairedDeviceDao.getByIdOnce(deviceId) ?: return null
        return entity.x25519PublicKey
    }
}
