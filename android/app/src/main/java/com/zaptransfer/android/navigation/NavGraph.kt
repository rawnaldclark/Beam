package com.zaptransfer.android.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.zaptransfer.android.ui.clipboard.ClipboardHistoryScreen
import com.zaptransfer.android.ui.settings.SettingsScreen
import com.zaptransfer.android.ui.transfer.TransferCompleteSheet
import com.zaptransfer.android.ui.transfer.TransferProgressScreen

// ─── Route constants ──────────────────────────────────────────────────────────
// Centralised string tokens prevent typos across call sites.
// Argument names match the NavArgument keys declared in each composable() block.

/** Main screen: paired device list + recent transfers + FAB. */
const val ROUTE_DEVICE_HUB = "deviceHub"

/** Pairing step 1A: CameraX + ML Kit QR code scanner. */
const val ROUTE_PAIRING_SCAN = "pairing/scan"

/** Pairing step 1B: 8-digit PIN fallback entry. */
const val ROUTE_PAIRING_PIN = "pairing/pin"

/**
 * Pairing step 2: SAS emoji verification.
 * Argument: [ARG_SESSION_ID] — the in-flight pairing session ID used to look up
 * the derived SAS bytes in the PairingViewModel.
 */
const val ROUTE_PAIRING_VERIFY = "pairing/verify/{$ARG_SESSION_ID}"

/**
 * Pairing step 3: name the newly paired device and pick its icon.
 * Argument: [ARG_DEVICE_ID] — the remote device's stable ID, used to pre-populate
 * the name field from the peer's self-declared name.
 */
const val ROUTE_PAIRING_NAME = "pairing/name/{$ARG_DEVICE_ID}"

/**
 * Transfer in-progress screen.
 * Argument: [ARG_TRANSFER_ID] — UUID of the active transfer, used to subscribe
 * to TransferViewModel's StateFlow for progress updates.
 */
const val ROUTE_TRANSFER_PROGRESS = "transfer/progress/{$ARG_TRANSFER_ID}"

/**
 * Transfer complete bottom sheet (shown modally over the hub).
 * Argument: [ARG_TRANSFER_ID] — UUID of the completed transfer, used to fetch
 * the final [TransferHistoryEntity] for display.
 */
const val ROUTE_TRANSFER_COMPLETE = "transfer/complete/{$ARG_TRANSFER_ID}"

/** Settings screen: exactly 4 settings per spec §8.3. */
const val ROUTE_SETTINGS = "settings"

/** Clipboard history screen: last 20 received clipboard items. */
const val ROUTE_CLIPBOARD = "clipboard"

// ─── Argument key constants ───────────────────────────────────────────────────
const val ARG_SESSION_ID = "sessionId"
const val ARG_DEVICE_ID = "deviceId"
const val ARG_TRANSFER_ID = "transferId"

/**
 * Root navigation graph for the Beam application.
 *
 * All screens are declared here as a flat list of [composable] destinations.
 * The [NavHostController] is owned by this composable and shared downward
 * only as a parameter to screens that need to navigate — not via CompositionLocal.
 *
 * Screen implementations are stub placeholders in Phase A. Each `TODO` comment
 * marks the Phase that fills in the real composable.
 *
 * Navigation rules:
 *  - Pairing flow is linear: scan/pin → verify/{sessionId} → name/{deviceId} → hub.
 *  - Transfer routes are pushed onto the back stack over the hub.
 *  - Settings and clipboard are top-level destinations accessible from the hub app bar.
 *
 * @param navController  Optional override — inject in tests to assert navigation calls.
 *                       Production callers use the default [rememberNavController].
 */
@Composable
fun BeamNavGraph(
    navController: NavHostController = rememberNavController(),
) {
    NavHost(
        navController = navController,
        startDestination = ROUTE_DEVICE_HUB,
    ) {

        // ── Device Hub ───────────────────────────────────────────────────────
        composable(ROUTE_DEVICE_HUB) {
            com.zaptransfer.android.ui.devicehub.DeviceHubScreen(
                onNavigateToPairScan = { navController.navigate(ROUTE_PAIRING_SCAN) },
                onNavigateToPairPin = { navController.navigate(ROUTE_PAIRING_PIN) },
                onNavigateToSettings = { navController.navigate(ROUTE_SETTINGS) },
                // Phase H: replace stubs below with real send-file / send-text flows
                onSendFile = { /* deviceId -> launch file picker */ },
                onSendText = { /* deviceId -> open text send sheet */ },
            )
        }

        // ── Pairing: QR scanner ──────────────────────────────────────────────
        composable(ROUTE_PAIRING_SCAN) {
            // Phase D (Task 11): replace with QrScannerScreen
            ScreenPlaceholder(
                title = "Scan QR Code",
                onBack = { navController.popBackStack() },
                onNext = { sessionId ->
                    navController.navigate("pairing/verify/$sessionId")
                },
            )
        }

        // ── Pairing: PIN entry ───────────────────────────────────────────────
        composable(ROUTE_PAIRING_PIN) {
            // Phase D (Task 12): replace with PinEntryScreen
            ScreenPlaceholder(
                title = "Enter 8-Digit PIN",
                onBack = { navController.popBackStack() },
                onNext = { sessionId ->
                    navController.navigate("pairing/verify/$sessionId")
                },
            )
        }

        // ── Pairing: SAS verification ────────────────────────────────────────
        composable(
            route = ROUTE_PAIRING_VERIFY,
            arguments = listOf(
                navArgument(ARG_SESSION_ID) { type = NavType.StringType }
            ),
        ) { backStackEntry ->
            val sessionId = backStackEntry.arguments?.getString(ARG_SESSION_ID) ?: return@composable
            // Phase D (Task 14): replace with SasVerificationScreen(sessionId)
            ScreenPlaceholder(
                title = "Verify: $sessionId",
                onBack = { navController.popBackStack() },
                onNext = { deviceId ->
                    navController.navigate("pairing/name/$deviceId") {
                        // Pop verify off the back stack — user cannot go back to SAS after naming
                        popUpTo(ROUTE_PAIRING_SCAN) { inclusive = false }
                    }
                },
            )
        }

        // ── Pairing: device naming ───────────────────────────────────────────
        composable(
            route = ROUTE_PAIRING_NAME,
            arguments = listOf(
                navArgument(ARG_DEVICE_ID) { type = NavType.StringType }
            ),
        ) { backStackEntry ->
            val deviceId = backStackEntry.arguments?.getString(ARG_DEVICE_ID) ?: return@composable
            // Phase D (Task 15): replace with DeviceNamingScreen(deviceId)
            ScreenPlaceholder(
                title = "Name Device: $deviceId",
                onBack = { navController.popBackStack() },
                onNext = {
                    // After naming, clear the entire pairing back stack and return to hub
                    navController.navigate(ROUTE_DEVICE_HUB) {
                        popUpTo(ROUTE_DEVICE_HUB) { inclusive = false }
                    }
                },
            )
        }

        // ── Transfer: progress ───────────────────────────────────────────────
        composable(
            route = ROUTE_TRANSFER_PROGRESS,
            arguments = listOf(
                navArgument(ARG_TRANSFER_ID) { type = NavType.StringType }
            ),
        ) { backStackEntry ->
            val transferId = backStackEntry.arguments?.getString(ARG_TRANSFER_ID) ?: return@composable
            TransferProgressScreen(
                transferId = transferId,
                onBack = { navController.popBackStack() },
                onCancel = { id ->
                    // Navigate back to hub after cancel
                    navController.navigate(ROUTE_DEVICE_HUB) {
                        popUpTo(ROUTE_DEVICE_HUB) { inclusive = false }
                    }
                },
                onComplete = { id ->
                    navController.navigate("transfer/complete/$id") {
                        popUpTo(ROUTE_TRANSFER_PROGRESS.substringBefore("{")) { inclusive = true }
                    }
                },
            )
        }

        // ── Transfer: complete sheet ─────────────────────────────────────────
        composable(
            route = ROUTE_TRANSFER_COMPLETE,
            arguments = listOf(
                navArgument(ARG_TRANSFER_ID) { type = NavType.StringType }
            ),
        ) { backStackEntry ->
            val transferId = backStackEntry.arguments?.getString(ARG_TRANSFER_ID) ?: return@composable
            TransferCompleteSheet(
                transferId = transferId,
                onDismiss = {
                    navController.navigate(ROUTE_DEVICE_HUB) {
                        popUpTo(ROUTE_DEVICE_HUB) { inclusive = false }
                    }
                },
            )
        }

        // ── Settings ─────────────────────────────────────────────────────────
        composable(ROUTE_SETTINGS) {
            SettingsScreen(
                onBack = { navController.popBackStack() },
            )
        }

        // ── Clipboard History ────────────────────────────────────────────────
        composable(ROUTE_CLIPBOARD) {
            ClipboardHistoryScreen(
                onBack = { navController.popBackStack() },
            )
        }
    }
}

// ─── Phase-A placeholder composables ─────────────────────────────────────────
// Minimal stubs so the app compiles and the nav graph is exercisable in isolation.
// These are replaced one-by-one in later phases — do NOT add real UI logic here.

@Composable
private fun DeviceHubPlaceholder(
    onPairDevice: () -> Unit,
    onSettings: () -> Unit,
    onClipboard: () -> Unit,
) {
    androidx.compose.material3.Text("Device Hub — Phase E placeholder")
}

@Composable
private fun ScreenPlaceholder(
    title: String,
    onBack: () -> Unit,
    onNext: (String) -> Unit,
) {
    androidx.compose.material3.Text("$title — placeholder")
}
