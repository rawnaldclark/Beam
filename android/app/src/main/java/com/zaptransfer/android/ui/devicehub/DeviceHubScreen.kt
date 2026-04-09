package com.zaptransfer.android.ui.devicehub

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Laptop
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Tablet
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity

// ── Status colours ─────────────────────────────────────────────────────────────
// Defined locally to avoid adding a new theme token for a single indicator dot.
private val OnlineGreen = Color(0xFF4CAF50)
private val OfflineGrey = Color(0xFF9E9E9E)

/**
 * Device Hub — the main screen of the Beam application.
 *
 * Layout:
 *  - [TopAppBar] with the "Beam" brand title and a settings gear icon.
 *  - [LazyColumn] body:
 *      - If no devices are paired: [EmptyStateOnboarding] replaces the list.
 *      - If devices exist: each is rendered as a [DeviceCard].
 *      - Below the device list: a "Recent Transfers" section with [TransferHistoryItem] rows.
 *  - [ExtendedFloatingActionButton] labelled "+ Pair Device" that navigates to the QR scanner.
 *
 * Navigation contract:
 *  - [onNavigateToPairScan]: push the QR scanner screen.
 *  - [onNavigateToPairPin]: push the PIN entry screen.
 *  - [onNavigateToSettings]: push the settings screen.
 *  - [onSendFile]: open the system file picker for the given device ID.
 *  - [onSendText]: open the clipboard/text send bottom sheet for the given device ID.
 *
 * @param viewModel            Hilt-provided [DeviceHubViewModel]; default via [hiltViewModel].
 * @param onNavigateToPairScan Navigate to pairing/scan.
 * @param onNavigateToPairPin  Navigate to pairing/pin.
 * @param onNavigateToSettings Navigate to settings.
 * @param onSendFile           Callback with the target device ID; caller opens file picker.
 * @param onSendText           Callback with the target device ID; caller opens text send UI.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceHubScreen(
    viewModel: DeviceHubViewModel = hiltViewModel(),
    onNavigateToPairScan: () -> Unit,
    onNavigateToPairPin: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onSendFile: (deviceId: String) -> Unit,
    onSendText: (deviceId: String) -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()
    val recentTransfers by viewModel.recentTransfers.collectAsState()
    val clipboardItems by viewModel.recentClipboard.collectAsState()

    // Observe toast events from the ViewModel (clipboard send/receive feedback).
    val context = LocalContext.current
    LaunchedEffect(Unit) {
        viewModel.toastEvents.collect { message ->
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        }
    }

    // Build a quick lookup map for device names in the history section.
    // This is O(n) per recomposition where n = number of paired devices — acceptable
    // given that the device list is bounded to a small number (dozens at most).
    val deviceNameById: Map<String, String> = remember(uiState.devices) {
        uiState.devices.associate { it.entity.deviceId to it.entity.name }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Beam",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                    )
                },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(
                            imageVector = Icons.Filled.Settings,
                            contentDescription = "Settings",
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onNavigateToPairScan,
                icon = {
                    Icon(
                        imageVector = Icons.Filled.Add,
                        contentDescription = null,
                    )
                },
                text = { Text("Pair Device") },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { innerPadding ->
        when {
            // Spinner on first load before Room emits
            uiState.isLoading -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator()
                }
            }

            // Empty state when no paired devices exist
            uiState.devices.isEmpty() -> {
                EmptyStateOnboarding(
                    onScanQrCode = onNavigateToPairScan,
                    onEnterPin = onNavigateToPairPin,
                    modifier = Modifier.padding(innerPadding),
                )
            }

            // Populated device list + history
            else -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    verticalArrangement = Arrangement.spacedBy(0.dp),
                ) {
                    // ── Section header: Devices ─────────────────────────────────
                    item {
                        SectionHeader(title = "My Devices")
                    }

                    // ── Device cards ────────────────────────────────────────────
                    items(
                        items = uiState.devices,
                        key = { it.entity.deviceId },
                    ) { deviceUi ->
                        DeviceCard(
                            device = deviceUi,
                            onSendFile = { onSendFile(deviceUi.entity.deviceId) },
                            onSendText = { onSendText(deviceUi.entity.deviceId) },
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                        )
                    }

                    // ── Section: Received Clipboard ────────────────────────────
                    if (clipboardItems.isNotEmpty()) {
                        item {
                            Spacer(modifier = Modifier.height(8.dp))
                            SectionHeader(title = "Received Clipboard")
                            Divider(
                                modifier = Modifier.padding(horizontal = 16.dp),
                                color = MaterialTheme.colorScheme.outlineVariant,
                            )
                        }

                        items(
                            items = clipboardItems,
                            key = { it.entryId },
                        ) { entry ->
                            ReceivedClipboardItem(
                                content = entry.content,
                                timestamp = entry.receivedAt,
                                isUrl = entry.isUrl,
                                onCopy = { viewModel.copyToClipboard(entry.content) },
                            )
                        }
                    }

                    // ── Section header: Recent Transfers ────────────────────────
                    if (recentTransfers.isNotEmpty()) {
                        item {
                            Spacer(modifier = Modifier.height(8.dp))
                            SectionHeader(title = "Recent Transfers")
                            Divider(
                                modifier = Modifier.padding(horizontal = 16.dp),
                                color = MaterialTheme.colorScheme.outlineVariant,
                            )
                        }

                        items(
                            items = recentTransfers,
                            key = { it.transferId },
                        ) { transfer ->
                            TransferHistoryItem(
                                entity = transfer,
                                peerName = transfer.deviceId?.let { deviceNameById[it] },
                            )
                            Divider(
                                modifier = Modifier.padding(horizontal = 16.dp),
                                color = MaterialTheme.colorScheme.outlineVariant,
                            )
                        }
                    }

                    // Bottom padding so FAB does not occlude the last list item
                    item { Spacer(modifier = Modifier.height(88.dp)) }
                }
            }
        }
    }
}

// ── Device card ────────────────────────────────────────────────────────────────

/**
 * Material 3 [Card] representing a single paired device.
 *
 * Contents:
 *  - Platform icon (laptop, desktop, phone, or tablet).
 *  - Device name (single-line, ellipsized).
 *  - Online/offline status: green dot + "Online" or grey dot + "Offline".
 *  - Connection type label derived from the platform field.
 *  - "Send File" and "Send Text" buttons — only rendered when [device.isOnline] is true.
 *
 * The action buttons are hidden when offline to prevent the user from initiating a
 * transfer that will fail silently. A tooltip or disabled state would be an
 * alternative; hiding is simpler for V1.
 *
 * @param device    The [PairedDeviceUi] to render.
 * @param onSendFile Callback for the "Send File" button.
 * @param onSendText Callback for the "Send Text" button.
 * @param modifier   Layout modifier applied to the root [Card].
 */
@Composable
fun DeviceCard(
    device: PairedDeviceUi,
    onSendFile: () -> Unit,
    onSendText: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Platform icon
                Icon(
                    imageVector = platformIcon(device.entity),
                    contentDescription = device.entity.platform,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp),
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    // Device name
                    Text(
                        text = device.entity.name,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    Spacer(modifier = Modifier.height(2.dp))

                    // Connection type label
                    Text(
                        text = connectionTypeLabel(device.entity.platform),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                // Online / offline status dot + label
                StatusIndicator(isOnline = device.isOnline)
            }

            // Action buttons — shown only when the device is reachable
            if (device.isOnline) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onSendFile,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                        ),
                    ) {
                        Text(text = "Send File")
                    }
                    OutlinedButton(
                        onClick = onSendText,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(text = "Send Text")
                    }
                }
            }
        }
    }
}

// ── Status indicator ───────────────────────────────────────────────────────────

/**
 * Small coloured dot + label showing online / offline presence.
 *
 * @param isOnline True for a green "Online" indicator; false for grey "Offline".
 * @param modifier Layout modifier.
 */
@Composable
private fun StatusIndicator(
    isOnline: Boolean,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(if (isOnline) OnlineGreen else OfflineGrey),
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = if (isOnline) "Online" else "Offline",
            style = MaterialTheme.typography.labelSmall,
            color = if (isOnline) OnlineGreen else OfflineGrey,
        )
    }
}

// ── Section header ─────────────────────────────────────────────────────────────

/**
 * Small bold category label used to separate the devices section from the
 * transfers history section in the [LazyColumn].
 *
 * @param title   Display text for the section header.
 * @param modifier Layout modifier.
 */
@Composable
private fun SectionHeader(
    title: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = title,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(horizontal = 16.dp, vertical = 12.dp),
    )
}

// ── Icon + label helpers ───────────────────────────────────────────────────────

/**
 * Returns the [ImageVector] that best represents the device's form factor.
 *
 * Mapping:
 *  - icon == "LAPTOP"  → [Icons.Filled.Laptop]
 *  - icon == "DESKTOP" → [Icons.Filled.DesktopWindows]
 *  - icon == "TABLET"  → [Icons.Filled.Tablet]
 *  - anything else     → [Icons.Filled.PhoneAndroid]
 *
 * @param entity The paired device entity containing the [icon] field.
 */
private fun platformIcon(entity: PairedDeviceEntity): ImageVector = when (entity.icon) {
    "LAPTOP" -> Icons.Filled.Laptop
    "DESKTOP" -> Icons.Filled.DesktopWindows
    "TABLET" -> Icons.Filled.Tablet
    else -> Icons.Filled.PhoneAndroid
}

/**
 * Returns the human-readable connection type label for a platform identifier.
 *
 * @param platform Raw platform string stored in [PairedDeviceEntity.platform].
 * @return Display string such as "Browser Extension" or "Android".
 */
private fun connectionTypeLabel(platform: String): String = when (platform) {
    "chrome_extension" -> "Browser Extension"
    "android" -> "Android"
    else -> platform.replaceFirstChar { it.uppercase() }
}

// ── Received Clipboard item ───────────────────────────────────────────────────

/**
 * A single received clipboard entry displayed in the "Received Clipboard" section.
 *
 * Shows a truncated preview of the content (max 80 chars), a relative timestamp,
 * and a "Copy" button that re-copies the content to the system clipboard.
 *
 * @param content   The full clipboard text received from a paired device.
 * @param timestamp Unix epoch millis when the item was received.
 * @param isUrl     True if the content was classified as a URL by the sender.
 * @param onCopy    Callback invoked when the user taps the "Copy" button.
 */
@Composable
fun ReceivedClipboardItem(
    content: String,
    timestamp: Long,
    isUrl: Boolean,
    onCopy: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        ),
        shape = MaterialTheme.shapes.small,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = content.take(80) + if (content.length > 80) "\u2026" else "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = formatRelativeTime(timestamp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Button(
                onClick = onCopy,
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
            ) {
                Text("Copy", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

/**
 * Formats a Unix-epoch timestamp as a human-readable relative time string.
 *
 * @param timestamp Unix epoch millis to format.
 * @return A string like "just now", "3 min ago", "2h ago", or "5d ago".
 */
private fun formatRelativeTime(timestamp: Long): String {
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < 60_000L -> "just now"
        diff < 3_600_000L -> "${diff / 60_000L} min ago"
        diff < 86_400_000L -> "${diff / 3_600_000L}h ago"
        else -> "${diff / 86_400_000L}d ago"
    }
}

