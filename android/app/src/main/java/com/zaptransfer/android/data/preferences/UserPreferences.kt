package com.zaptransfer.android.data.preferences

import android.content.Context
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "UserPreferences"
private const val PREFERENCES_FILE = "beam_user_prefs"

/** Extension property that creates a single DataStore instance per [Context]. */
private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = PREFERENCES_FILE)

/**
 * Typed snapshot of all user-configurable preferences for the Beam application.
 *
 * Emitted by [UserPreferences.preferencesFlow] whenever any value changes.
 * Defaults are specified here so callers never receive null for a missing key.
 *
 * @param saveLocationUri     SAF tree URI string for custom save location.
 *                            Null means "use the system Downloads folder".
 * @param autoAccept          When true, incoming transfers from paired devices
 *                            are accepted automatically without a prompt.
 * @param deviceName          Human-readable name this device advertises to peers.
 *                            Defaults to the device's Build.MODEL.
 * @param dozePromptDismissedAt  Unix epoch ms when the battery optimisation dialog
 *                            was last dismissed. Used to implement the 7-day re-prompt
 *                            suppression window in [PermissionHelper].
 */
data class UserPrefsSnapshot(
    val saveLocationUri: String? = null,
    val autoAccept: Boolean = true,
    val deviceName: String = android.os.Build.MODEL,
    val dozePromptDismissedAt: Long = 0L,
)

/**
 * Repository for user preferences backed by [DataStore<Preferences>].
 *
 * Replaces SharedPreferences for the following reasons:
 *  - Type-safe [Preferences.Key] objects prevent key-string typos.
 *  - [DataStore] exposes preferences as a cold [Flow] — no manual listeners required.
 *  - Writes are non-blocking (suspend functions on Dispatchers.IO internally).
 *  - Atomic, transactional writes via [DataStore.edit] prevent partial-write corruption.
 *
 * Injected as a [Singleton] — one DataStore file for the entire process.
 *
 * @param context Application context — used to resolve the DataStore file path.
 */
@Singleton
class UserPreferences @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    // ── Preference keys ───────────────────────────────────────────────────────

    private object Keys {
        val SAVE_LOCATION_URI = stringPreferencesKey("save_location_uri")
        val AUTO_ACCEPT = booleanPreferencesKey("auto_accept")
        val DEVICE_NAME = stringPreferencesKey("device_name")
        val DOZE_PROMPT_DISMISSED_AT = longPreferencesKey("doze_prompt_dismissed_at")
    }

    // ── Observable flow ───────────────────────────────────────────────────────

    /**
     * Emits the current [UserPrefsSnapshot] immediately and on every write.
     *
     * Errors from [DataStore] (e.g., corrupt file) are caught and replaced with
     * a default snapshot, logged at ERROR level. This is the recommended pattern
     * from the DataStore documentation for non-crash-worthy preference failures.
     */
    val preferencesFlow: Flow<UserPrefsSnapshot> = context.dataStore.data
        .catch { exception ->
            if (exception is IOException) {
                Log.e(TAG, "DataStore read error — emitting defaults: ${exception.message}")
                emit(androidx.datastore.preferences.core.emptyPreferences())
            } else {
                throw exception
            }
        }
        .map { prefs ->
            UserPrefsSnapshot(
                saveLocationUri = prefs[Keys.SAVE_LOCATION_URI],
                autoAccept = prefs[Keys.AUTO_ACCEPT] ?: true,
                deviceName = prefs[Keys.DEVICE_NAME] ?: android.os.Build.MODEL,
                dozePromptDismissedAt = prefs[Keys.DOZE_PROMPT_DISMISSED_AT] ?: 0L,
            )
        }

    // ── Write functions ───────────────────────────────────────────────────────

    /**
     * Persists the SAF tree URI for the user's chosen save location.
     *
     * Pass null to reset to the default Downloads folder.
     *
     * @param uri SAF content tree URI string, or null to revert to Downloads.
     */
    suspend fun setSaveLocationUri(uri: String?) {
        context.dataStore.edit { prefs ->
            if (uri != null) {
                prefs[Keys.SAVE_LOCATION_URI] = uri
            } else {
                prefs.remove(Keys.SAVE_LOCATION_URI)
            }
        }
        Log.d(TAG, "Save location updated: $uri")
    }

    /**
     * Updates the auto-accept setting.
     *
     * When enabled, incoming transfers from paired devices are automatically accepted
     * without a UI confirmation prompt.
     *
     * @param enabled true to enable auto-accept; false to require explicit approval.
     */
    suspend fun setAutoAccept(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.AUTO_ACCEPT] = enabled
        }
        Log.d(TAG, "Auto-accept updated: $enabled")
    }

    /**
     * Updates the name this device advertises to peers.
     *
     * The name is sent in pairing messages and shown on peer devices.
     * Maximum length is enforced by the UI layer (e.g., 30 characters).
     *
     * @param name New device name; must not be blank.
     */
    suspend fun setDeviceName(name: String) {
        require(name.isNotBlank()) { "Device name must not be blank" }
        context.dataStore.edit { prefs ->
            prefs[Keys.DEVICE_NAME] = name.take(50)  // hard cap: 50 chars
        }
        Log.d(TAG, "Device name updated: $name")
    }

    /**
     * Records the timestamp when the Doze / battery-optimisation prompt was dismissed.
     *
     * [PermissionHelper] reads this to suppress re-prompting for 7 days.
     *
     * @param timestampMs Unix epoch milliseconds of the dismissal.
     */
    suspend fun setDozePromptDismissedAt(timestampMs: Long) {
        context.dataStore.edit { prefs ->
            prefs[Keys.DOZE_PROMPT_DISMISSED_AT] = timestampMs
        }
        Log.d(TAG, "Doze prompt dismissed at: $timestampMs")
    }
}
