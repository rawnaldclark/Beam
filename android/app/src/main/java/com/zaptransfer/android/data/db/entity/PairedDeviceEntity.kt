package com.zaptransfer.android.data.db.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Persistent record of a device that has completed the full pairing ceremony
 * (QR or PIN + SAS verification + naming).
 *
 * Key fields:
 *  - [x25519PublicKey]: peer's static X25519 public key, used for Triple-DH session
 *    key derivation on every transfer.
 *  - [ed25519PublicKey]: peer's identity key; used to verify relay challenge signatures
 *    and to compute the device ID.
 *  - [icon]: one of LAPTOP, DESKTOP, PHONE, TABLET — chosen by the local user at naming time.
 *  - [platform]: "chrome_extension" or "android" — drives UI icon selection and capability flags.
 *
 * NOTE: The peer's private keys are NEVER stored here or anywhere on-device.
 * Our own private keys live in Android Keystore (Ed25519) and EncryptedSharedPreferences (X25519).
 */
@Entity(tableName = "paired_devices")
data class PairedDeviceEntity(

    /** Stable, relay-registered identifier: Base64url(SHA-256(ed25519_pk)[0:16]) — 22 chars. */
    @PrimaryKey
    @ColumnInfo(name = "device_id")
    val deviceId: String,

    /** Human-readable name chosen by the local user during the naming step. */
    @ColumnInfo(name = "name")
    val name: String,

    /**
     * Icon token for UI rendering.
     * Valid values: "LAPTOP", "DESKTOP", "PHONE", "TABLET".
     */
    @ColumnInfo(name = "icon")
    val icon: String,

    /**
     * Platform identifier.
     * Valid values: "chrome_extension", "android".
     */
    @ColumnInfo(name = "platform")
    val platform: String,

    /**
     * Peer's static X25519 Curve25519 public key (32 bytes).
     * Used in Triple-DH: dh1=DH(ephA, staticB), dh2=DH(staticA, ephB).
     */
    @ColumnInfo(name = "x25519_public_key")
    val x25519PublicKey: ByteArray,

    /**
     * Peer's Ed25519 signing public key (32 bytes).
     * Used to:
     *  1. Derive the peer's device ID (SHA-256[0:16]).
     *  2. Verify Ed25519 signatures on wire messages.
     *  3. Compute SAS emoji fingerprint during pairing.
     */
    @ColumnInfo(name = "ed25519_public_key")
    val ed25519PublicKey: ByteArray,

    /** Unix epoch milliseconds when pairing was completed and saved. */
    @ColumnInfo(name = "paired_at")
    val pairedAt: Long,

    /**
     * Unix epoch milliseconds of the last observed online presence event.
     * Null until the device is seen online at least once after pairing.
     * Best-effort — not authoritative; always probe relay before assuming online.
     */
    @ColumnInfo(name = "last_seen_at")
    val lastSeenAt: Long? = null,

    /**
     * Beam v2 long-lived symmetric key ring, stored as JSON because Room
     * does not natively serialise nested generation maps. Schema:
     *
     * ```json
     * {
     *   "currentGeneration": 0,
     *   "keys": {
     *     "0": { "kAB": "<hex 32B>", "createdAt": 1745958123, "expiresAt": 0 }
     *   }
     * }
     * ```
     *
     * `expiresAt` is 0 (= no expiry) for the live generation; populated when
     * a newer generation supersedes this one (via key rotation), giving the
     * old gen a 24-hour grace window before it stops decrypting.
     *
     * Empty string for paired devices created before Beam v2 — the
     * destructive migration in [ZapDatabase] versions ≥ 2 forbids this in
     * practice, but the type is non-null so the column has a default.
     */
    @ColumnInfo(name = "k_ab_ring_json", defaultValue = "")
    val kABRingJson: String = "",
) {
    // ByteArray structural equality — Room serialises arrays as BLOBs; equals/hashCode
    // must compare contents, not references, to avoid spurious DiffUtil updates in the UI.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairedDeviceEntity) return false
        return deviceId == other.deviceId &&
            name == other.name &&
            icon == other.icon &&
            platform == other.platform &&
            x25519PublicKey.contentEquals(other.x25519PublicKey) &&
            ed25519PublicKey.contentEquals(other.ed25519PublicKey) &&
            pairedAt == other.pairedAt &&
            lastSeenAt == other.lastSeenAt &&
            kABRingJson == other.kABRingJson
    }

    override fun hashCode(): Int {
        var result = deviceId.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + icon.hashCode()
        result = 31 * result + platform.hashCode()
        result = 31 * result + x25519PublicKey.contentHashCode()
        result = 31 * result + ed25519PublicKey.contentHashCode()
        result = 31 * result + pairedAt.hashCode()
        result = 31 * result + (lastSeenAt?.hashCode() ?: 0)
        result = 31 * result + kABRingJson.hashCode()
        return result
    }
}
