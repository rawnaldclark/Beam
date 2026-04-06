package com.zaptransfer.android.service

import android.content.Context
import android.net.wifi.WifiManager
import android.os.PowerManager
import android.util.Log

private const val TAG = "WakeLockManager"

/**
 * Acquires and releases [PowerManager.WakeLock] and [WifiManager.WifiLock] for the
 * duration of an active file transfer.
 *
 * ## Why both locks?
 *  - [PowerManager.PARTIAL_WAKE_LOCK] keeps the CPU running when the screen turns off
 *    so the foreground service is not throttled or killed mid-transfer.
 *  - [WifiManager.WIFI_MODE_FULL_HIGH_PERF] prevents the Wi-Fi stack from entering
 *    power-save mode, eliminating the ~200 ms latency spikes that degrade TCP throughput
 *    on aggressive battery-managed devices (Samsung, Xiaomi, Huawei).
 *
 * ## Lifecycle
 *  1. Call [acquire] when a transfer session starts.
 *  2. Call [release] when the last active transfer completes, fails, or is cancelled.
 *  3. Releasing an already-released lock is safe — guarded by [PowerManager.WakeLock.isHeld].
 *
 * ## Manifest requirements
 *  ```xml
 *  <uses-permission android:name="android.permission.WAKE_LOCK" />
 *  <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
 *  ```
 *  Both are already declared in AndroidManifest.xml.
 *
 * @param context Application context (not Activity — this outlives any single screen).
 */
class WakeLockManager(private val context: Context) {

    /**
     * CPU wake lock held for the transfer duration.
     * PARTIAL_WAKE_LOCK keeps CPU on but allows screen and keyboard backlight to turn off.
     */
    private var wakeLock: PowerManager.WakeLock? = null

    /**
     * Wi-Fi performance lock preventing the adapter from entering 802.11 power-save mode.
     * WIFI_MODE_FULL_HIGH_PERF: zero packet latency at cost of ~30 mW extra draw.
     * Acceptable for transfers that are typically < 60 seconds.
     */
    private var wifiLock: WifiManager.WifiLock? = null

    /**
     * Acquires both the CPU wake lock and the Wi-Fi high-performance lock.
     *
     * Idempotent: if called while locks are already held, the call is a no-op.
     * Both locks are reference-counted by the OS — each acquire must be paired
     * with exactly one release.
     */
    fun acquire() {
        if (wakeLock?.isHeld == true) {
            Log.d(TAG, "Locks already held — skipping acquire")
            return
        }

        // CPU wake lock — tag format "ClassName:lock_purpose" per Android conventions
        val pm = context.getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Beam:transfer").apply {
            acquire()
            Log.d(TAG, "CPU wake lock acquired")
        }

        // Wi-Fi high-performance lock — requires CHANGE_WIFI_STATE (normal protection level)
        val wm = context.getSystemService(WifiManager::class.java)
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "Beam:transfer").apply {
            acquire()
            Log.d(TAG, "Wi-Fi high-perf lock acquired")
        }
    }

    /**
     * Releases both locks if they are currently held.
     *
     * Safe to call when locks are not held — checks [PowerManager.WakeLock.isHeld]
     * before releasing to avoid the [RuntimeException] that Android throws on a
     * double-release.
     *
     * Sets both fields to null after release to allow GC.
     */
    fun release() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "CPU wake lock released")
            }
        }
        wakeLock = null

        wifiLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "Wi-Fi high-perf lock released")
            }
        }
        wifiLock = null
    }
}
