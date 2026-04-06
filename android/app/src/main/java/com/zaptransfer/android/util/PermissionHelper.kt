package com.zaptransfer.android.util

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import androidx.activity.ComponentActivity
import com.zaptransfer.android.data.preferences.UserPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "PermissionHelper"

/** 7 days in milliseconds — suppression window between Doze permission re-prompts. */
private val DOZE_REPROMPMT_INTERVAL_MS = TimeUnit.DAYS.toMillis(7)

/**
 * Helper for checking and requesting Android runtime permissions that require
 * both a manifest declaration AND a user-facing prompt.
 *
 * Currently handles:
 *  - **Doze / Battery Optimisation** ([PowerManager.isIgnoringBatteryOptimizations]):
 *    Critical for Samsung, Xiaomi, and Huawei devices where aggressive battery policies
 *    kill foreground services even when the WAKE_LOCK permission is held.
 *    Prompts the user once, then suppresses re-prompts for 7 days via DataStore.
 *
 * Usage — call from a [ComponentActivity] after the first successful pairing:
 * ```kotlin
 * permissionHelper.requestDozeExemptionIfNeeded(this)
 * ```
 *
 * @param userPreferences DataStore preferences for persisting the re-prompt suppression window.
 */
@Singleton
class PermissionHelper @Inject constructor(
    private val userPreferences: UserPreferences,
) {

    private val scope = CoroutineScope(Dispatchers.Main)

    /**
     * Checks whether the app is already exempt from battery optimisation and, if not,
     * shows a single-button dialog explaining why the permission is needed before
     * launching [Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS].
     *
     * ## Re-prompt suppression
     * If the user dismisses the dialog (taps "Maybe later"), the dismissal timestamp
     * is written to [UserPreferences.setDozePromptDismissedAt] and the prompt is
     * suppressed for [DOZE_REPROMPMT_INTERVAL_MS] (7 days).
     *
     * ## When to call
     *  - After the first successful device pairing (recommended by spec §8.4).
     *  - Do NOT call on every launch — the 7-day suppression handles re-prompting.
     *
     * @param activity [ComponentActivity] used to show the dialog and launch the system settings
     *                 intent. Must not be finishing when this method is called.
     */
    fun requestDozeExemptionIfNeeded(activity: ComponentActivity) {
        val pm = activity.getSystemService(PowerManager::class.java)
        val packageName = activity.packageName

        // No action needed if already exempt
        if (pm.isIgnoringBatteryOptimizations(packageName)) {
            Log.d(TAG, "Already ignoring battery optimisations — no prompt needed")
            return
        }

        // Check if we should suppress the prompt for 7 days
        scope.launch {
            val prefs = userPreferences.preferencesFlow.first()
            val timeSinceDismissal = System.currentTimeMillis() - prefs.dozePromptDismissedAt
            if (timeSinceDismissal < DOZE_REPROMPMT_INTERVAL_MS) {
                val daysLeft = (DOZE_REPROMPMT_INTERVAL_MS - timeSinceDismissal) /
                    TimeUnit.DAYS.toMillis(1)
                Log.d(TAG, "Doze prompt suppressed for ~${daysLeft} more day(s)")
                return@launch
            }

            // Show explanation dialog on the main thread before launching system settings
            if (!activity.isFinishing) {
                showDozeExplanationDialog(activity, packageName)
            }
        }
    }

    /**
     * Shows a [AlertDialog] explaining why the battery optimisation exemption is needed,
     * with two actions:
     *  - **"Allow"**: launches [Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS].
     *  - **"Maybe later"**: records the dismissal timestamp to suppress re-prompting for 7 days.
     *
     * @param activity    The activity to anchor the dialog to.
     * @param packageName App package name for the Settings intent URI.
     */
    private fun showDozeExplanationDialog(activity: ComponentActivity, packageName: String) {
        AlertDialog.Builder(activity)
            .setTitle("Keep transfers running in background")
            .setMessage(
                "Beam needs to be excluded from battery optimisation to reliably transfer " +
                    "large files when the screen is off.\n\n" +
                    "On some devices (Samsung, Xiaomi, Huawei), aggressive battery management " +
                    "can interrupt transfers mid-way. Tapping \"Allow\" opens the system settings " +
                    "page where you can grant this exception."
            )
            .setPositiveButton("Allow") { dialog, _ ->
                dialog.dismiss()
                launchDozeExemptionSettings(activity, packageName)
            }
            .setNegativeButton("Maybe later") { dialog, _ ->
                dialog.dismiss()
                // Record dismissal timestamp so we don't re-prompt for 7 days
                scope.launch(Dispatchers.IO) {
                    userPreferences.setDozePromptDismissedAt(System.currentTimeMillis())
                    Log.d(TAG, "Doze prompt dismissed — re-prompt suppressed for 7 days")
                }
            }
            .setCancelable(true)
            .setOnCancelListener {
                // User tapped outside the dialog — treat same as "Maybe later"
                scope.launch(Dispatchers.IO) {
                    userPreferences.setDozePromptDismissedAt(System.currentTimeMillis())
                }
            }
            .show()
    }

    /**
     * Launches [Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS] for this app.
     *
     * On Android 6+ this opens a system dialog asking the user to add the app to the
     * "Don't optimise" list. The result is not delivered back to the app — users must
     * navigate back manually. The [PowerManager.isIgnoringBatteryOptimizations] check
     * on the next call to [requestDozeExemptionIfNeeded] detects whether they approved.
     *
     * Note: Google Play policy requires this permission to be justified. The manifest
     * already declares `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` (a normal-level permission
     * that does not require runtime granting, only the system UI prompt).
     *
     * @param context     Context for launching the intent.
     * @param packageName This app's package name.
     */
    private fun launchDozeExemptionSettings(context: Context, packageName: String) {
        try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            }
            context.startActivity(intent)
            Log.d(TAG, "Launched battery optimisation settings for $packageName")
        } catch (e: Exception) {
            // Fallback: some manufacturers block this intent — open the general battery settings
            Log.w(TAG, "Primary Doze intent failed: ${e.message} — falling back to battery settings")
            try {
                context.startActivity(Intent(Settings.ACTION_BATTERY_SAVER_SETTINGS))
            } catch (fallbackEx: Exception) {
                Log.e(TAG, "Could not open battery settings: ${fallbackEx.message}")
            }
        }
    }
}
