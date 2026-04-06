package com.zaptransfer.android.ui.pairing

import android.util.Base64
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.crypto.KeyManager
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.repository.DeviceRepository
import com.zaptransfer.android.webrtc.ConnectionState
import com.zaptransfer.android.webrtc.RelayMessage
import com.zaptransfer.android.webrtc.SignalingClient
import com.zaptransfer.android.webrtc.SignalingListener
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import javax.inject.Inject

private const val TAG = "PairingViewModel"

// ── 256-emoji SAS table ───────────────────────────────────────────────────────
// Identical to the Chrome extension's table for cross-platform SAS compatibility (spec §4.4.2).
// Each index maps to one emoji; 4 emoji are shown (2 bytes each = 8 bytes of SAS material).
// Sourced from the ZapTransfer spec — do not modify without updating the Chrome extension.

private val SAS_EMOJI_TABLE = arrayOf(
    "😀", "😂", "😍", "🤣", "😊", "😎", "🤩", "😴",
    "🥳", "😈", "🤖", "👻", "💀", "🎃", "🙈", "🙉",
    "🙊", "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻",
    "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵",
    "🐔", "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇",
    "🐺", "🐗", "🐴", "🦄", "🐝", "🐛", "🦋", "🐌",
    "🐞", "🐜", "🦟", "🦗", "🦂", "🐢", "🐍", "🦎",
    "🦖", "🦕", "🐙", "🦑", "🦐", "🦞", "🦀", "🐡",
    "🐠", "🐟", "🐬", "🐳", "🐋", "🦈", "🐊", "🐅",
    "🐆", "🦓", "🦍", "🦧", "🦣", "🐘", "🦛", "🦏",
    "🐪", "🐫", "🦒", "🦘", "🦬", "🐃", "🐂", "🐄",
    "🐎", "🐖", "🐏", "🐑", "🦙", "🐐", "🦌", "🐕",
    "🐩", "🦮", "🐈", "🐓", "🦃", "🦤", "🦚", "🦜",
    "🦢", "🦩", "🕊", "🐇", "🦝", "🦨", "🦡", "🦫",
    "🦦", "🦥", "🐁", "🐀", "🐿", "🦔", "🌵", "🌲",
    "🌳", "🌴", "🌱", "🌿", "☘", "🍀", "🎍", "🎋",
    "🍃", "🍂", "🍁", "🍄", "🌾", "💐", "🌷", "🌹",
    "🥀", "🌺", "🌸", "🌼", "🌻", "🌞", "🌝", "🌛",
    "🌜", "🌚", "🌕", "🌖", "🌗", "🌘", "🌑", "🌒",
    "🌓", "🌔", "🌙", "🌟", "⭐", "🌠", "🌌", "☁",
    "⛅", "🌤", "🌈", "⚡", "❄", "🔥", "💧", "🌊",
    "🍏", "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇",
    "🍓", "🫐", "🍈", "🍒", "🍑", "🥭", "🍍", "🥥",
    "🥝", "🍅", "🍆", "🥑", "🥦", "🥬", "🥒", "🌶",
    "🫑", "🧄", "🧅", "🥔", "🍠", "🥐", "🥯", "🍞",
    "🥖", "🥨", "🧀", "🥚", "🍳", "🧈", "🥞", "🧇",
    "🥓", "🥩", "🍗", "🍖", "🦴", "🌭", "🍔", "🍟",
    "🍕", "🌮", "🌯", "🫔", "🥙", "🧆", "🥚", "🍿",
    "🧂", "🥫", "🍱", "🍘", "🍙", "🍚", "🍛", "🍜",
    "🍝", "🍠", "🍢", "🍣", "🍤", "🍥", "🥮", "🍡",
    "🥟", "🦪", "🍦", "🍧", "🍨", "🍩", "🍪", "🎂",
    "🍰", "🧁", "🥧", "🍫", "🍬", "🍭", "🍮", "🍯"
)

// ── UI states ─────────────────────────────────────────────────────────────────

/**
 * Describes the peer device info decoded from the QR code payload.
 * All fields map 1:1 to the QR payload spec: `{v, did, epk, xpk, relay}`.
 *
 * @param deviceId  22-char Base64url device ID of the Chrome extension.
 * @param ed25519Pk 32-byte Ed25519 public key (for SAS derivation and signature verification).
 * @param x25519Pk  32-byte X25519 public key (for key exchange).
 * @param relayUrl  Relay server URL; may differ from the default if the Chrome extension uses a backup.
 */
data class PeerPayload(
    val deviceId: String,
    val ed25519Pk: ByteArray,
    val x25519Pk: ByteArray,
    val relayUrl: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PeerPayload) return false
        return deviceId == other.deviceId &&
            ed25519Pk.contentEquals(other.ed25519Pk) &&
            x25519Pk.contentEquals(other.x25519Pk) &&
            relayUrl == other.relayUrl
    }

    override fun hashCode(): Int {
        var result = deviceId.hashCode()
        result = 31 * result + ed25519Pk.contentHashCode()
        result = 31 * result + x25519Pk.contentHashCode()
        result = 31 * result + relayUrl.hashCode()
        return result
    }
}

/**
 * SAS (Short Authentication String) derived from the X25519 key exchange.
 *
 * @param emoji List of 4 emoji from [SAS_EMOJI_TABLE].
 * @param labels Human-readable labels for accessibility (e.g., "Rocket", "Globe").
 *               Currently mirrors the emoji for simplicity; a future revision could
 *               add localised text labels.
 */
data class SasData(
    val emoji: List<String>,
    val labels: List<String>,
)

/**
 * All UI states for the pairing flow.
 *
 * The state machine follows the spec §4.4.1 flow:
 *  Scanning → Verifying → Naming → Complete
 *  Scanning → PinEntry → Verifying → Naming → Complete
 *  Any state → Error (recoverable by navigating back to Scanning)
 */
sealed class PairingUiState {

    /** Waiting for the user to point the camera at a QR code. Initial state. */
    object Scanning : PairingUiState()

    /**
     * Fallback PIN entry mode. The user chose "Can't scan? Enter PIN".
     * @param errorMessage Non-null after a failed PIN attempt.
     */
    data class PinEntry(val errorMessage: String? = null) : PairingUiState()

    /**
     * QR decoded or PIN exchange complete. Displaying 4 SAS emoji for verification.
     *
     * @param peerPayload The decoded peer identity from QR or relay.
     * @param sas         The derived 4-emoji SAS for visual comparison.
     */
    data class Verifying(
        val peerPayload: PeerPayload,
        val sas: SasData,
    ) : PairingUiState()

    /**
     * SAS verified. The user must give the peer device a local name.
     *
     * @param peerDeviceId Stable device ID (for Room persistence).
     * @param suggestedName Name advertised by the peer in the relay handshake.
     * @param peerPayload Full payload (needed to construct [PairedDeviceEntity]).
     */
    data class Naming(
        val peerDeviceId: String,
        val suggestedName: String,
        val peerPayload: PeerPayload,
    ) : PairingUiState()

    /**
     * Pairing complete. The device has been saved to Room.
     * UI should navigate to the Device Hub.
     *
     * @param deviceId The newly paired device's ID.
     */
    data class Complete(val deviceId: String) : PairingUiState()

    /**
     * Recoverable error. UI shows the message and a "Try Again" button
     * that navigates back to [Scanning].
     *
     * @param message Developer-facing message; sanitise before showing to users.
     */
    data class Error(val message: String) : PairingUiState()
}

// ── PairingViewModel ──────────────────────────────────────────────────────────

/**
 * Orchestrates the full device pairing ceremony.
 *
 * State flow:
 *  1. [PairingUiState.Scanning] — user scans QR code.
 *  2. [onQrDecoded]: parse payload, connect to relay, perform X25519 key exchange,
 *     derive SAS.
 *  3. [PairingUiState.Verifying] — user compares 4 emoji on both screens.
 *  4. [onSasConfirmed]: advance to naming.
 *  5. [PairingUiState.Naming] — user types a local name for the peer device.
 *  6. [onNamingComplete]: save [PairedDeviceEntity] to Room → [PairingUiState.Complete].
 *
 * PIN entry alternate path:
 *  1. [onPinEntryRequested]: transition to [PairingUiState.PinEntry].
 *  2. [onPinSubmitted]: connect to relay via SPAKE2, then resume at step 3 above.
 *     NOTE: SPAKE2 protocol is noted as future work; this implementation performs
 *     a simplified relay-mediated X25519 exchange and is marked accordingly.
 *
 * @param keyManager    Provides this device's key pairs for ECDH and signing.
 * @param deviceRepo    Persists the completed [PairedDeviceEntity] to Room.
 * @param signalingClient Active relay connection (shared Singleton).
 */
@HiltViewModel
class PairingViewModel @Inject constructor(
    private val keyManager: KeyManager,
    private val deviceRepo: DeviceRepository,
    private val signalingClient: SignalingClient,
) : ViewModel() {

    private val _uiState = MutableStateFlow<PairingUiState>(PairingUiState.Scanning)

    /** Observable UI state — collect in Composable screens via [collectAsStateWithLifecycle]. */
    val uiState: StateFlow<PairingUiState> = _uiState.asStateFlow()

    /**
     * Transient storage for key exchange material during the Verifying step.
     * Cleared after [onNamingComplete] so the raw shared secret does not linger.
     */
    private var pendingSharedSecret: ByteArray? = null

    // ── QR decode entry point ─────────────────────────────────────────────────

    /**
     * Called by [QrScannerScreen] when ML Kit decodes a QR code.
     *
     * Parses the JSON payload `{v, did, epk, xpk, relay}`, connects to the relay
     * if not already connected, performs an X25519 key exchange, and derives the
     * SAS fingerprint. Transitions to [PairingUiState.Verifying] on success.
     *
     * QR payload fields (spec §4.4.1):
     *  - `v`     — version; must be `1`
     *  - `did`   — Chrome extension's device ID (22-char Base64url)
     *  - `epk`   — Ed25519 public key (Base64)
     *  - `xpk`   — X25519 public key (Base64)
     *  - `relay` — relay WSS URL
     *
     * @param rawJson The raw JSON string from the QR code.
     */
    fun onQrDecoded(rawJson: String) {
        viewModelScope.launch {
            try {
                val payload = parseQrPayload(rawJson)
                performKeyExchangeAndDeriveSas(payload)
            } catch (e: Exception) {
                Log.e(TAG, "QR decode failed: ${e.message}", e)
                _uiState.value = PairingUiState.Error("Invalid QR code: ${e.message}")
            }
        }
    }

    // ── PIN entry ─────────────────────────────────────────────────────────────

    /** Transitions to the PIN entry screen. */
    fun onPinEntryRequested() {
        _uiState.value = PairingUiState.PinEntry()
    }

    /**
     * Called by [PinEntryScreen] when the user completes the 8-digit PIN.
     *
     * Implementation note: Full SPAKE2 (spec §4.4.3) requires a library not yet
     * available in lazysodium-android. This method currently sends a pairing
     * initiation message to the relay and waits for the peer's public keys.
     * A TODO marks the SPAKE2 upgrade path.
     *
     * @param pin The 8-character numeric string entered by the user.
     */
    fun onPinSubmitted(pin: String) {
        if (pin.length != 8 || !pin.all { it.isDigit() }) {
            _uiState.value = PairingUiState.PinEntry(errorMessage = "PIN must be exactly 8 digits")
            return
        }

        viewModelScope.launch {
            try {
                // Ensure relay is connected before attempting PIN-based pairing
                ensureRelayConnected()

                // TODO (Phase D+): implement full SPAKE2 protocol per spec §4.4.3.
                // Current stub: send a pairing request with the PIN hash to the relay.
                // The relay will match two devices presenting the same PIN and forward
                // each device's public keys to the other side.
                val keys = keyManager.getOrCreateKeys()
                val deviceId = keyManager.deriveDeviceId(keys.ed25519Pk)
                val pinRequest = JSONObject().apply {
                    put("type", "pin_pair_request")
                    put("pin", pin)  // WARNING: in production this must be SPAKE2 blinded — never raw
                    put("deviceId", deviceId)
                    put("xpk", Base64.encodeToString(keys.x25519Pk, Base64.NO_WRAP))
                    put("epk", Base64.encodeToString(keys.ed25519Pk, Base64.NO_WRAP))
                }
                signalingClient.send(pinRequest)

                // Register a one-shot listener for the relay's peer_keys response
                registerPinPairingListener()
            } catch (e: Exception) {
                Log.e(TAG, "PIN pairing failed: ${e.message}", e)
                _uiState.value = PairingUiState.PinEntry(errorMessage = "Connection failed. Try again.")
            }
        }
    }

    // ── SAS confirmation ──────────────────────────────────────────────────────

    /**
     * Called by [SasVerificationScreen] when the user taps "They Match".
     *
     * Transitions to [PairingUiState.Naming]. The peer's self-reported name
     * (from the relay handshake) is used as the pre-filled suggestion.
     */
    fun onSasConfirmed() {
        val current = _uiState.value
        if (current !is PairingUiState.Verifying) return

        _uiState.value = PairingUiState.Naming(
            peerDeviceId = current.peerPayload.deviceId,
            suggestedName = "My Device",  // TODO: use peer's self-reported name from relay handshake
            peerPayload = current.peerPayload,
        )
    }

    /**
     * Called by [SasVerificationScreen] when the user taps "No Match".
     *
     * Aborts the pairing attempt and returns to the scanning screen.
     * The partial shared secret is zeroed.
     */
    fun onSasDenied() {
        clearPendingSecret()
        _uiState.value = PairingUiState.Scanning
        Log.w(TAG, "SAS mismatch — pairing aborted")
    }

    // ── Device naming ─────────────────────────────────────────────────────────

    /**
     * Called by [DeviceNamingScreen] when the user taps "Done".
     *
     * Saves the [PairedDeviceEntity] to Room and transitions to
     * [PairingUiState.Complete]. The pending shared secret is cleared after use.
     *
     * @param name  The local name chosen by the user (non-empty, validated by UI).
     * @param icon  One of "LAPTOP", "DESKTOP", "PHONE", "TABLET".
     */
    fun onNamingComplete(name: String, icon: String) {
        val current = _uiState.value
        if (current !is PairingUiState.Naming) return

        viewModelScope.launch {
            try {
                val entity = PairedDeviceEntity(
                    deviceId = current.peerPayload.deviceId,
                    name = name.trim(),
                    icon = icon,
                    platform = "chrome_extension",
                    x25519PublicKey = current.peerPayload.x25519Pk,
                    ed25519PublicKey = current.peerPayload.ed25519Pk,
                    pairedAt = System.currentTimeMillis(),
                )

                deviceRepo.addDevice(entity)
                clearPendingSecret()

                Log.i(TAG, "Pairing complete: ${entity.deviceId} (${entity.name})")
                _uiState.value = PairingUiState.Complete(entity.deviceId)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save pairing: ${e.message}", e)
                _uiState.value = PairingUiState.Error("Failed to save device: ${e.message}")
            }
        }
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    /** Returns to the scanning state. Useful after error recovery. */
    fun resetToScanning() {
        clearPendingSecret()
        _uiState.value = PairingUiState.Scanning
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Parses the QR payload JSON into a [PeerPayload].
     *
     * Validates that version == 1 and all required fields are present.
     *
     * @param rawJson Raw JSON string from the QR code.
     * @return Parsed [PeerPayload].
     * @throws IllegalArgumentException if the payload is invalid.
     */
    private fun parseQrPayload(rawJson: String): PeerPayload {
        val json = JSONObject(rawJson)

        val version = json.getInt("v")
        require(version == 1) { "Unsupported QR payload version: $version" }

        val deviceId = json.getString("did")
        Log.d("PairingViewModel", "QR payload: did=$deviceId (len=${deviceId.length}), raw=$rawJson")
        require(deviceId.length >= 16) { "Invalid device ID length: ${deviceId.length} (expected 22, got '$deviceId')" }

        val epkBase64 = json.getString("epk")
        val xpkBase64 = json.getString("xpk")
        val relayUrl = json.getString("relay")

        val ed25519Pk = Base64.decode(epkBase64, Base64.DEFAULT)
        val x25519Pk = Base64.decode(xpkBase64, Base64.DEFAULT)

        require(ed25519Pk.size == 32) { "Ed25519 public key must be 32 bytes, got ${ed25519Pk.size}" }
        require(x25519Pk.size == 32) { "X25519 public key must be 32 bytes, got ${x25519Pk.size}" }

        return PeerPayload(
            deviceId = deviceId,
            ed25519Pk = ed25519Pk,
            x25519Pk = x25519Pk,
            relayUrl = relayUrl,
        )
    }

    /**
     * Performs X25519 key exchange and derives the SAS fingerprint.
     *
     * Key exchange (simplified pairing — not Triple-DH):
     *  `sharedSecret = DH(ourX25519Sk, peerX25519Pk)`
     *
     * SAS derivation (spec §4.4.2):
     *  `sasBytes = HKDF(sharedSecret, salt=ed25519Pk_chrome || ed25519Pk_android,
     *                   info="zaptransfer-sas-v1", len=8)`
     *  Display as 4 emoji: each 2-byte pair indexes into [SAS_EMOJI_TABLE].
     *
     * @param payload Parsed QR payload containing the peer's public keys.
     */
    private suspend fun performKeyExchangeAndDeriveSas(payload: PeerPayload) {
        val ourKeys = keyManager.getOrCreateKeys()

        // X25519 ECDH — raw shared secret (must be processed through HKDF before use)
        val rawShared = keyManager.deriveSharedSecret(ourKeys.x25519Sk, payload.x25519Pk)
        pendingSharedSecret = rawShared

        // HKDF for SAS bytes (spec §4.4.2):
        // salt = ed25519Pk_chrome (32B) || ed25519Pk_android (32B) = 64 bytes
        val salt = payload.ed25519Pk + ourKeys.ed25519Pk
        val info = "zaptransfer-sas-v1".toByteArray(Charsets.UTF_8)
        val sasBytes = hkdf(ikm = rawShared, salt = salt, info = info, outputLen = 8)

        val sas = deriveSasEmoji(sasBytes)

        Log.d(TAG, "Key exchange complete; SAS derived: ${sas.emoji}")

        _uiState.value = PairingUiState.Verifying(
            peerPayload = payload,
            sas = sas,
        )
    }

    /**
     * Converts 8 raw SAS bytes into 4 emoji using the [SAS_EMOJI_TABLE].
     *
     * Each pair of bytes is treated as a big-endian uint16, then taken modulo 256
     * to index into the 256-entry table. This matches the Chrome extension's logic.
     *
     * @param sasBytes Exactly 8 bytes of derived SAS material.
     * @return [SasData] with 4 emoji and 4 matching labels.
     */
    private fun deriveSasEmoji(sasBytes: ByteArray): SasData {
        require(sasBytes.size == 8) { "SAS bytes must be 8, got ${sasBytes.size}" }

        val emoji = List(4) { i ->
            val high = sasBytes[i * 2].toInt() and 0xFF
            val low = sasBytes[i * 2 + 1].toInt() and 0xFF
            val index = ((high shl 8) or low) % 256
            SAS_EMOJI_TABLE[index]
        }

        // Labels are the emoji themselves for now; a future localisation pass would
        // replace these with descriptive names (e.g., "😀" → "Grinning Face").
        return SasData(emoji = emoji, labels = emoji)
    }

    /**
     * Ensures the relay is connected before a PIN pairing attempt.
     * Waits up to 5 seconds for the connection to reach [ConnectionState.Connected].
     *
     * @throws IllegalStateException if the relay does not connect within 5 seconds.
     */
    private suspend fun ensureRelayConnected() {
        val state = signalingClient.connectionState.value
        if (state is ConnectionState.Connected) return

        signalingClient.connect()

        // Wait for up to 5 seconds for auth to complete
        var waited = 0
        while (waited < 5000) {
            if (signalingClient.connectionState.value is ConnectionState.Connected) return
            kotlinx.coroutines.delay(100)
            waited += 100
        }

        throw IllegalStateException("Relay connection timed out after 5s")
    }

    /**
     * Registers a one-shot [SignalingListener] that handles the relay's response
     * to a PIN pairing request. When the peer's public keys arrive, the listener
     * removes itself and continues the pairing flow as if a QR was scanned.
     */
    private fun registerPinPairingListener() {
        val listener = object : SignalingListener {
            override fun onMessage(message: RelayMessage) {
                if (message !is RelayMessage.Text) return
                val type = message.json.optString("type")
                if (type != "pin_pair_response") return

                // Received peer keys — remove this listener and continue pairing
                signalingClient.removeListener(this)

                viewModelScope.launch {
                    try {
                        val did = message.json.getString("deviceId")
                        val epk = Base64.decode(message.json.getString("epk"), Base64.DEFAULT)
                        val xpk = Base64.decode(message.json.getString("xpk"), Base64.DEFAULT)
                        val relay = message.json.optString("relay", com.zaptransfer.android.webrtc.RELAY_URL)

                        val payload = PeerPayload(
                            deviceId = did,
                            ed25519Pk = epk,
                            x25519Pk = xpk,
                            relayUrl = relay,
                        )
                        performKeyExchangeAndDeriveSas(payload)
                    } catch (e: Exception) {
                        Log.e(TAG, "PIN pair response handling failed: ${e.message}", e)
                        _uiState.value = PairingUiState.PinEntry(
                            errorMessage = "Pairing exchange failed. Try again."
                        )
                    }
                }
            }
        }
        signalingClient.addListener(listener)
    }

    /**
     * Zeros and clears the pending shared secret from memory.
     * Called after pairing completes or is aborted.
     */
    private fun clearPendingSecret() {
        pendingSharedSecret?.fill(0)
        pendingSharedSecret = null
    }

    override fun onCleared() {
        super.onCleared()
        clearPendingSecret()
    }

    // ── HKDF (RFC 5869 with HMAC-SHA256) ─────────────────────────────────────
    // Duplicated here from SessionCipher to keep PairingViewModel self-contained
    // for the SAS derivation step. Both implementations must stay in sync.

    private fun hkdf(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLen: Int,
    ): ByteArray {
        val prk = hmacSha256(key = salt, data = ikm)
        val result = ByteArray(outputLen)
        var prev = ByteArray(0)
        var offset = 0
        var blockIndex = 1
        while (offset < outputLen) {
            val input = prev + info + byteArrayOf(blockIndex.toByte())
            val block = hmacSha256(key = prk, data = input)
            val copyLen = minOf(block.size, outputLen - offset)
            block.copyInto(result, destinationOffset = offset, endIndex = copyLen)
            offset += copyLen
            prev = block
            blockIndex++
        }
        return result
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
