package com.zaptransfer.android.ui.devicehub

import android.os.Build
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.annotation.VisibleForTesting
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.connection.PeerHealth
import com.zaptransfer.android.connection.SelfState
import com.zaptransfer.android.data.db.entity.ClipboardEntryEntity
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.data.db.entity.TransferHistoryEntity
import com.zaptransfer.android.ui.theme.BeamCorner
import com.zaptransfer.android.ui.theme.BeamIcons
import com.zaptransfer.android.ui.theme.BeamMotion
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.ui.theme.BeamRow
import com.zaptransfer.android.ui.theme.BeamSpace
import com.zaptransfer.android.ui.theme.BeamTextStyle
import java.text.DecimalFormat
import kotlin.math.abs

/**
 * Device Hub — the main screen of the Beam application (Beam v1 design).
 *
 * Layout zones:
 *  1. [BeamTopBar] — device alias + online dot + settings gear.
 *  2. [HeroCard] — top online paired device with "pick file" / "send clipboard" verbs.
 *  3. Other Devices section — flat 64dp rows for remaining paired devices.
 *  4. Activity section — unified time-sorted list of recent transfers + clipboard items.
 *  5. [BeamBottomBar] — "Pair" and "Settings" ghost buttons (replaces the old FAB).
 *
 * Empty state: centered message with a "Pair a device" primary button.
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
    val pendingFile by viewModel.pendingFileSave.collectAsState()

    // Observe toast events from the ViewModel (clipboard send/receive feedback).
    val context = LocalContext.current
    LaunchedEffect(Unit) {
        viewModel.toastEvents.collect { message ->
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        }
    }

    // ── Refresh-on-focus: re-register rendezvous on every Activity resume ──
    // Instead of trusting that the persistent push chain delivered accurate
    // presence while the app was backgrounded, we actively poke the server
    // for fresh peer-online events every time the user sees this screen.
    // This makes presence self-healing regardless of idle disconnections.
    val lifecycleOwner = androidx.compose.ui.platform.LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
                viewModel.refreshPresence()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // Build a lookup map for device names used in activity rows.
    val deviceNameById: Map<String, String> = remember(uiState.devices) {
        uiState.devices.associate { it.entity.deviceId to it.entity.name }
    }

    // Sort devices: send-eligible first, then by name. The hero is the first entry.
    // "Send-eligible" matches the row's enabled-state logic (HEALTHY or STALE)
    // so the user's most-actionable target floats to the top.
    val sortedDevices = remember(uiState.devices) {
        uiState.devices.sortedWith(compareByDescending<PairedDeviceUi> { it.isSendable }.thenBy { it.entity.name })
    }

    val heroDevice = sortedDevices.firstOrNull()
    val otherDevices = if (sortedDevices.size > 1) sortedDevices.drop(1) else emptyList()

    // Merge transfers and clipboard items into a unified activity list, capped at 8.
    val activityItems = remember(recentTransfers, clipboardItems) {
        buildActivityList(recentTransfers, clipboardItems, deviceNameById)
    }

    // The user's own device alias — read from Build.MODEL as the ViewModel
    // does not expose userPreferences directly and we must not modify it.
    val ownDeviceAlias = remember { Build.MODEL }

    // The header status dot now binds to the authority's selfState directly:
    // ONLINE = green, anything else = grey. Replaces the prior "any device
    // online" heuristic, which conflated peer presence with relay liveness.
    val isRelayConnected = uiState.selfState is SelfState.Online

    Scaffold(
        topBar = {
            BeamTopBar(
                deviceAlias = ownDeviceAlias,
                isRelayConnected = isRelayConnected,
                onSettingsClick = onNavigateToSettings,
            )
        },
        bottomBar = {
            if (uiState.devices.isNotEmpty()) {
                BeamBottomBar(
                    onPairClick = onNavigateToPairScan,
                    onSettingsClick = onNavigateToSettings,
                )
            }
        },
        containerColor = BeamPalette.bg0,
    ) { innerPadding ->
        when {
            // Spinner on first load before Room emits.
            uiState.isLoading -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    contentAlignment = Alignment.Center,
                ) {
                    // Minimal loading indicator — just a text label in Beam style.
                    Text(
                        text = "Loading\u2026",
                        style = BeamTextStyle.baseRegular,
                        color = BeamPalette.textMid,
                    )
                }
            }

            // Empty state: no paired devices.
            uiState.devices.isEmpty() -> {
                EmptyState(
                    onPairClick = onNavigateToPairScan,
                    modifier = Modifier.padding(innerPadding),
                )
            }

            // Populated main screen.
            else -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                ) {
                    ConnectionBanner(
                        selfState = uiState.selfState,
                        onReconnect = { viewModel.requestReconnect() },
                    )
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = BeamSpace.s4),
                    ) {
                        // ── Zone 2: Hero Card ──────────────────────────────────
                        if (heroDevice != null) {
                            item(key = "hero") {
                                AnimatedVisibility(
                                    visible = true,
                                    enter = fadeIn(
                                        animationSpec = tween(
                                            BeamMotion.durBaseMs,
                                            easing = BeamMotion.easeOut,
                                        ),
                                    ) + slideInVertically(
                                        initialOffsetY = { 8 },
                                        animationSpec = tween(
                                            BeamMotion.durBaseMs,
                                            easing = BeamMotion.easeOut,
                                        ),
                                    ),
                                ) {
                                    HeroCard(
                                        device = heroDevice,
                                        onPickFile = { onSendFile(heroDevice.entity.deviceId) },
                                        onSendClipboard = { onSendText(heroDevice.entity.deviceId) },
                                        modifier = Modifier.padding(
                                            horizontal = BeamSpace.s4,
                                            vertical = BeamSpace.s3,
                                        ),
                                    )
                                }
                            }
                        }

                        // ── Pending file-save prompt ───────────────────────────
                        pendingFile?.let { pf ->
                            item(key = "pending-file") {
                                PendingFileCard(
                                    fileName = pf.fileName,
                                    sizeBytes = pf.data.size.toLong(),
                                    onSave = { viewModel.savePendingFile() },
                                    onDismiss = { viewModel.dismissPendingFile() },
                                    modifier = Modifier.padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s1),
                                )
                            }
                        }

                        // ── Zone 3: Other Devices ──────────────────────────────
                        if (otherDevices.isNotEmpty()) {
                            item(key = "header-other") {
                                SectionHeader(title = "OTHER DEVICES")
                            }

                            items(
                                items = otherDevices,
                                key = { it.entity.deviceId },
                            ) { device ->
                                DeviceRow(
                                    device = device,
                                    onClick = {
                                        if (device.isSendable) {
                                            onSendFile(device.entity.deviceId)
                                        }
                                    },
                                    onLongClick = { /* retarget hero — future feature */ },
                                    modifier = Modifier.animateItemPlacement(),
                                )
                            }
                        }

                        // ── Zone 4: Activity ───────────────────────────────────
                        item(key = "header-activity") {
                            SectionHeader(title = "ACTIVITY")
                        }

                        if (activityItems.isEmpty()) {
                            item(key = "empty-activity") {
                                EmptyActivityMessage()
                            }
                        } else {
                            items(
                                items = activityItems,
                                key = { it.id },
                            ) { item ->
                                ActivityRow(
                                    item = item,
                                    modifier = Modifier.animateItemPlacement(),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Zone 1: Top App Bar ──────────────────────────────────────────────────────

/**
 * Beam top app bar (56dp). Shows the user's own device alias, an online
 * indicator dot, and a settings gear icon button.
 *
 * @param deviceAlias      The user's own device name displayed as the title.
 * @param isRelayConnected Whether the relay connection is established.
 * @param onSettingsClick  Callback when the settings gear is tapped.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BeamTopBar(
    deviceAlias: String,
    isRelayConnected: Boolean,
    onSettingsClick: () -> Unit,
) {
    TopAppBar(
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(BeamSpace.s2),
            ) {
                // Beam wordmark — matches the Chrome identity strip.
                Text(
                    text = "beam",
                    style = BeamTextStyle.lgSemibold,
                    color = BeamPalette.textHi,
                )
                // Device alias as secondary text.
                Text(
                    text = deviceAlias,
                    style = BeamTextStyle.smRegular,
                    color = BeamPalette.textMid,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
        actions = {
            // Online status dot — 8dp circle.
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (isRelayConnected) BeamPalette.online else BeamPalette.offline),
            )
            Spacer(modifier = Modifier.width(BeamSpace.s3))

            // Settings gear.
            IconButton(onClick = onSettingsClick) {
                Icon(
                    imageVector = BeamIcons.settings,
                    contentDescription = "Settings",
                    tint = BeamPalette.textHi,
                )
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = BeamPalette.bg0,
            titleContentColor = BeamPalette.textHi,
            actionIconContentColor = BeamPalette.textHi,
        ),
    )
}

// ── Zone 1.5: Connection banner (selfState != Online) ───────────────────────

/**
 * Top-of-screen banner that surfaces the authority's [SelfState] when the
 * device is not currently in [SelfState.Online]. Mirrors the Chrome popup
 * banner from commit `01e33ba` per spec table line 185.
 *
 * Visibility + content matrix:
 *  - [SelfState.Online]                                       -> hidden.
 *  - [SelfState.Offline]                                      -> "Not connected" + Reconnect button.
 *  - [SelfState.Connecting]                                   -> "Connecting\u2026" (no button — already trying).
 *  - [SelfState.Reconnecting] `(surrenderedToUser=false)`     -> "Reconnecting\u2026" (auto-recovery in flight, no button).
 *  - [SelfState.Reconnecting] `(surrenderedToUser=true)`      -> "Not connected" + Reconnect button (ladder gave up).
 *
 * The button is wired to [ConnectionAuthority.requestReconnect] via
 * [DeviceHubViewModel.requestReconnect]. In skeleton-mode (Task 19 lands
 * before Task 20's Rung 3 work) the authority's `requestReconnect` is a
 * no-op stub — clicking the button is harmless until Task 20 lands.
 *
 * @param selfState   Current [SelfState] from the [ConnectionAuthority].
 * @param onReconnect Click handler for the Reconnect button (when shown).
 * @param modifier    Layout modifier.
 */
@Composable
private fun ConnectionBanner(
    selfState: SelfState,
    onReconnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Banner copy + button visibility per spec UI-mapping table and Chrome
    // popup parity (commit 01e33ba). Reconnect button is shown under BOTH
    // Reconnecting variants — auto-recovery in flight may stall on a
    // stuck rung, and the user must always have an escape hatch during
    // the 30s+ ladder + backoff cycle. Only `Connecting` (already
    // actively trying to reach the relay) suppresses the button.
    val (message, showButton) = when (selfState) {
        is SelfState.Online -> return
        is SelfState.Connecting -> "Connecting\u2026" to false
        is SelfState.Reconnecting ->
            if (selfState.surrenderedToUser) "Not connected" to true
            else "Reconnecting\u2026" to true
        is SelfState.Offline -> "Not connected" to true
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(BeamPalette.bg2)
            .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s2)
            .semantics(mergeDescendants = true) {
                contentDescription = "$message banner"
                if (showButton) role = Role.Button
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(BeamPalette.warning),
        )
        Spacer(modifier = Modifier.width(BeamSpace.s2))
        Text(
            text = message,
            style = BeamTextStyle.smMedium,
            color = BeamPalette.textHi,
            modifier = Modifier.weight(1f),
        )
        if (showButton) {
            TextButton(onClick = onReconnect) {
                Text(
                    text = "Reconnect",
                    style = BeamTextStyle.smMedium,
                    color = BeamPalette.accent,
                )
            }
        }
    }
}

// ── Zone 2: Hero Card ────────────────────────────────────────────────────────

/**
 * Hero card (128dp) for the top online paired device — the default send target.
 *
 * Contains the device alias, online/offline status, and two verb rows:
 * "Tap to pick file" and "Send clipboard". Verbs are disabled when the
 * device is offline.
 *
 * @param device          The hero [PairedDeviceUi] (first online, or first overall).
 * @param onPickFile      Callback to open the system file picker for this device.
 * @param onSendClipboard Callback to send the clipboard to this device.
 * @param modifier        Layout modifier.
 */
@Composable
private fun HeroCard(
    device: PairedDeviceUi,
    onPickFile: () -> Unit,
    onSendClipboard: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val sendable = device.isSendable

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                color = BeamPalette.bg1,
                shape = RoundedCornerShape(BeamCorner.lg),
            )
            .border(
                width = 1.dp,
                color = BeamPalette.borderSubtle,
                shape = RoundedCornerShape(BeamCorner.lg),
            )
            .padding(BeamSpace.s4),
    ) {
        // Device alias.
        Text(
            text = device.entity.name,
            style = BeamTextStyle.xlSemibold,
            color = BeamPalette.textHi,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(modifier = Modifier.height(BeamSpace.s1))

        // Status line: 4-state dot + label. FAILED appends "Reconnecting…"
        // per the spec table line 183 so the user sees recovery is in flight.
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(peerHealthDotColor(device.health)),
            )
            Spacer(modifier = Modifier.width(BeamSpace.s1))
            Text(
                text = peerHealthStatusLabel(device.health),
                style = BeamTextStyle.smRegular,
                color = BeamPalette.textMid,
            )
        }

        Spacer(modifier = Modifier.height(BeamSpace.s3))

        // Verb divider.
        HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)

        // Verb row 1: "Tap to pick file".
        HeroVerbRow(
            label = "Tap to pick file",
            accessibilityLabel = "Send file to ${device.entity.name}",
            enabled = sendable,
            onClick = onPickFile,
        )

        // Verb divider.
        HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)

        // Verb row 2: "Send clipboard".
        HeroVerbRow(
            label = "Send clipboard",
            accessibilityLabel = "Send clipboard to ${device.entity.name}",
            enabled = sendable,
            onClick = onSendClipboard,
        )
    }
}

/**
 * A single verb row inside the [HeroCard] with a 48dp minimum touch target.
 *
 * @param label              Display text for the action.
 * @param accessibilityLabel Semantic label announced by TalkBack.
 * @param enabled            Whether the row is interactive (online) or disabled (offline).
 * @param onClick            Callback on tap.
 */
@Composable
private fun HeroVerbRow(
    label: String,
    accessibilityLabel: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp)
            .semantics { contentDescription = accessibilityLabel }
            .then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier),
        contentAlignment = Alignment.CenterStart,
    ) {
        Text(
            text = label,
            style = BeamTextStyle.mdMedium,
            color = if (enabled) BeamPalette.textHi else BeamPalette.textDisabled,
        )
    }
}

// ── Pending file card ────────────────────────────────────────────────────────

/**
 * Card shown when a file has been received but not yet saved (auto-save OFF).
 *
 * @param fileName  Name of the received file.
 * @param sizeBytes Size in bytes.
 * @param onSave    Callback for the "Save to Downloads" action.
 * @param onDismiss Callback for the "Dismiss" action.
 * @param modifier  Layout modifier.
 */
@Composable
private fun PendingFileCard(
    fileName: String,
    sizeBytes: Long,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                color = BeamPalette.bg2,
                shape = RoundedCornerShape(BeamCorner.lg),
            )
            .border(
                width = 1.dp,
                color = BeamPalette.borderSubtle,
                shape = RoundedCornerShape(BeamCorner.lg),
            )
            .padding(BeamSpace.s4),
    ) {
        Text(
            text = fileName,
            style = BeamTextStyle.baseMedium,
            color = BeamPalette.textHi,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(modifier = Modifier.height(BeamSpace.s1))
        Text(
            text = formatFileSize(sizeBytes),
            style = BeamTextStyle.smMono,
            color = BeamPalette.textMid,
        )
        Spacer(modifier = Modifier.height(BeamSpace.s3))
        Row(horizontalArrangement = Arrangement.spacedBy(BeamSpace.s2)) {
            Button(
                onClick = onSave,
                colors = ButtonDefaults.buttonColors(
                    containerColor = BeamPalette.accent,
                    contentColor = Color.Black,
                ),
                shape = RoundedCornerShape(BeamCorner.md),
            ) {
                Text("Save to Downloads", style = BeamTextStyle.smMedium)
            }
            TextButton(onClick = onDismiss) {
                Text(
                    "Dismiss",
                    style = BeamTextStyle.smMedium,
                    color = BeamPalette.textMid,
                )
            }
        }
    }
}

// ── Zone 3: Device rows ──────────────────────────────────────────────────────

/**
 * A flat 64dp row representing a paired device in the "Other devices" section.
 *
 * Shows: [status dot] [device icon] [device name] [trailing "send" or "offline"].
 * Online devices render at full opacity; offline devices at 0.55.
 *
 * @param device      The [PairedDeviceUi] to render.
 * @param onClick     Called on single tap (sends staged content if any).
 * @param onLongClick Called on long-press (retargets hero card — future feature).
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun DeviceRow(
    device: PairedDeviceUi,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val rowAlpha = if (device.isSendable) 1f else 0.55f

    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(BeamRow.height)
            .alpha(rowAlpha)
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongClick,
            )
            .padding(horizontal = BeamRow.paddingHorizontal, vertical = BeamRow.paddingVertical),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // 4-state status dot (8dp). HEALTHY/STALE = green, FAILED = warning
        // yellow, OFFLINE/UNKNOWN = grey. STALE pulse animation is deferred —
        // see PeerHealth.Stale branch in [peerHealthDotColor].
        Box(
            modifier = Modifier
                .size(BeamRow.dotSize)
                .clip(CircleShape)
                .background(peerHealthDotColor(device.health)),
        )

        Spacer(modifier = Modifier.width(BeamSpace.s2))

        // Device type icon (24dp).
        Icon(
            imageVector = platformIcon(device.entity),
            contentDescription = deviceTypeLabel(device.entity.icon),
            tint = BeamPalette.textHi,
            modifier = Modifier.size(24.dp),
        )

        Spacer(modifier = Modifier.width(BeamSpace.s2))

        // Device name + optional FAILED subtext. Wrapped in a Column so the
        // "Reconnecting…" hint sits directly under the device name only when
        // the peer is FAILED (mirrors Chrome popup.js's per-row subtext div).
        Column(
            modifier = Modifier.weight(1f),
        ) {
            Text(
                text = device.entity.name,
                style = BeamTextStyle.baseMedium,
                color = BeamPalette.textHi,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (device.health is PeerHealth.Failed) {
                Text(
                    text = "Reconnecting\u2026",
                    style = BeamTextStyle.xsRegular,
                    color = BeamPalette.warning,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        Spacer(modifier = Modifier.width(BeamSpace.s2))

        // Trailing label: "send" when sendable, "offline" otherwise.
        Text(
            text = if (device.isSendable) "send" else "offline",
            style = BeamTextStyle.xsMono,
            color = BeamPalette.textLo,
        )
    }
}

/**
 * Map a [PeerHealth] value to the dot colour rendered in [HeroCard] and
 * [DeviceRow] per the spec table at lines 181-184:
 *
 *  - [PeerHealth.Healthy] -> green
 *  - [PeerHealth.Stale]   -> green (pulse animation deferred — see KDoc note)
 *  - [PeerHealth.Failed]  -> warning yellow (paired with "Reconnecting…" subtext)
 *  - [PeerHealth.Offline] -> grey
 *  - [PeerHealth.Unknown] -> grey (conservative — matches Chrome popup.js)
 *
 * **STALE pulse note:** Chrome's `dot-stale` CSS class adds a subtle pulse
 * animation. The Compose equivalent (`rememberInfiniteTransition` driving
 * an alpha float) is intentionally NOT added in this initial port — STALE
 * is invisible-to-user signal (background re-pinging in flight, recovery
 * not yet warranted) and an extra Compose recomposition source per row is
 * an avoidable hot-path cost for a UX subtlety that no real-device feedback
 * has yet asked for. Visual parity with Chrome can land as a follow-up if
 * the team decides STALE needs to be visually distinct.
 */
@VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
internal fun peerHealthDotColor(health: PeerHealth): Color = when (health) {
    is PeerHealth.Healthy -> BeamPalette.online
    is PeerHealth.Stale -> BeamPalette.online
    is PeerHealth.Failed -> BeamPalette.warning
    is PeerHealth.Offline -> BeamPalette.offline
    is PeerHealth.Unknown -> BeamPalette.offline
}

/**
 * Map a [PeerHealth] value to the short status label shown next to the
 * 8dp dot inside [HeroCard]. STALE collapses to "online" because the user-
 * facing distinction between HEALTHY and STALE is not meaningful (both are
 * sendable; STALE is purely "background re-pinging").
 *
 * FAILED reads "reconnecting" rather than "offline" so the label matches
 * the dot colour cue (warning yellow) and the row-level subtext.
 */
@VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
internal fun peerHealthStatusLabel(health: PeerHealth): String = when (health) {
    is PeerHealth.Healthy, is PeerHealth.Stale -> "online"
    is PeerHealth.Failed -> "reconnecting"
    is PeerHealth.Offline, is PeerHealth.Unknown -> "offline"
}

// ── Zone 4: Activity ─────────────────────────────────────────────────────────

/**
 * Represents a single entry in the unified activity list, merging transfers
 * and clipboard items into a time-sorted feed.
 *
 * @property id          Stable unique key for LazyColumn.
 * @property direction   "SENT" or "RECEIVED" — drives the direction icon.
 * @property description File name or clipboard content preview.
 * @property sizeLabel   Human-readable size for files, or null for clipboard items.
 * @property deviceName  Name of the remote device, or null if unknown.
 * @property timestamp   Unix epoch millis for relative-time display.
 */
data class ActivityItem(
    val id: String,
    val direction: String,
    val description: String,
    val sizeLabel: String?,
    val deviceName: String?,
    val timestamp: Long,
)

/**
 * Merges file transfers and clipboard entries into a unified, time-sorted
 * activity list capped at 8 items.
 *
 * @param transfers    Recent file transfer history from Room.
 * @param clipboard    Recent clipboard entries from Room.
 * @param deviceNames  Lookup map of deviceId to display name.
 * @return At most 8 [ActivityItem] entries, newest first.
 */
private fun buildActivityList(
    transfers: List<TransferHistoryEntity>,
    clipboard: List<ClipboardEntryEntity>,
    deviceNames: Map<String, String>,
): List<ActivityItem> {
    val transferItems = transfers.map { t ->
        ActivityItem(
            id = "transfer-${t.transferId}",
            direction = t.direction,
            description = t.fileName,
            sizeLabel = formatFileSize(t.fileSizeBytes),
            deviceName = t.deviceId?.let { deviceNames[it] },
            timestamp = t.completedAt ?: t.startedAt,
        )
    }

    val clipboardItemsMapped = clipboard.map { c ->
        ActivityItem(
            id = "clipboard-${c.entryId}",
            direction = "RECEIVED",
            description = c.content.take(40) + if (c.content.length > 40) "\u2026" else "",
            sizeLabel = null,
            deviceName = deviceNames[c.deviceId],
            timestamp = c.receivedAt,
        )
    }

    return (transferItems + clipboardItemsMapped)
        .sortedByDescending { it.timestamp }
        .take(8)
}

/**
 * A single 64dp activity row showing transfer direction, description, size,
 * device name, and a relative timestamp.
 *
 * @param item The unified [ActivityItem] to display.
 */
@Composable
private fun ActivityRow(
    item: ActivityItem,
    modifier: Modifier = Modifier,
) {
    val isSent = item.direction == "SENT"
    val relativeTime = remember(item.timestamp) { formatRelativeTime(item.timestamp) }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(BeamRow.height)
            .padding(horizontal = BeamRow.paddingHorizontal, vertical = BeamRow.paddingVertical),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Direction icon.
        Icon(
            imageVector = if (isSent) BeamIcons.transferOut else BeamIcons.transferIn,
            contentDescription = if (isSent) "Sent" else "Received",
            tint = BeamPalette.textMid,
            modifier = Modifier.size(20.dp),
        )

        Spacer(modifier = Modifier.width(BeamSpace.s2))

        // Filename / clipboard preview.
        Text(
            text = item.description,
            style = BeamTextStyle.baseMedium,
            color = BeamPalette.textHi,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )

        // File size (if present).
        if (item.sizeLabel != null) {
            Spacer(modifier = Modifier.width(BeamSpace.s2))
            Text(
                text = item.sizeLabel,
                style = BeamTextStyle.smMono,
                color = BeamPalette.textLo,
            )
        }

        // Device name.
        if (item.deviceName != null) {
            Spacer(modifier = Modifier.width(BeamSpace.s2))
            Text(
                text = item.deviceName,
                style = BeamTextStyle.smRegular,
                color = BeamPalette.textLo,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        // Relative timestamp.
        Spacer(modifier = Modifier.width(BeamSpace.s2))
        Text(
            text = relativeTime,
            style = BeamTextStyle.smMono,
            color = BeamPalette.textLo,
        )
    }
}

/**
 * Empty-state message shown when no activity exists.
 */
@Composable
private fun EmptyActivityMessage(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s6),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = "Nothing sent yet. Share into Beam to start.",
            style = BeamTextStyle.smRegular,
            color = BeamPalette.textLo,
            textAlign = TextAlign.Center,
        )
    }
}

// ── Zone 5: Bottom Bar ───────────────────────────────────────────────────────

/**
 * Fixed bottom bar (56dp) with "Pair" and "Settings" ghost text buttons.
 * Replaces the old FAB from the utilitarian layout.
 *
 * @param onPairClick     Callback when "Pair" is tapped.
 * @param onSettingsClick Callback when "Settings" is tapped.
 */
@Composable
private fun BeamBottomBar(
    onPairClick: () -> Unit,
    onSettingsClick: () -> Unit,
) {
    Column(
        modifier = Modifier.navigationBarsPadding(),
    ) {
        // Top border line.
        HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .background(BeamPalette.bg1),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onPairClick) {
                Text(
                    text = "Pair",
                    style = BeamTextStyle.mdMedium,
                    color = BeamPalette.textHi,
                )
            }
            TextButton(onClick = onSettingsClick) {
                Text(
                    text = "Settings",
                    style = BeamTextStyle.mdMedium,
                    color = BeamPalette.textHi,
                )
            }
        }
    }
}

// ── Section header ───────────────────────────────────────────────────────────

/**
 * Section header label used to separate content zones (e.g., "OTHER DEVICES",
 * "ACTIVITY"). Uses uppercase text with wide letter-spacing per the Beam v1 spec.
 *
 * @param title   Display text (should be provided pre-uppercased or will be rendered as-is).
 * @param modifier Layout modifier.
 */
@Composable
private fun SectionHeader(
    title: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = title,
        style = BeamTextStyle.smMedium.copy(letterSpacing = 0.6.sp),
        color = BeamPalette.textMid,
        modifier = modifier.padding(
            start = BeamSpace.s4,
            top = BeamSpace.s3,
            bottom = BeamSpace.s1,
        ),
    )
}

// ── Empty state (no paired devices) ──────────────────────────────────────────

/**
 * Full-screen empty state shown when no devices are paired.
 *
 * Centered vertically with a heading, subheading, and a "Pair a device"
 * primary button using BeamPalette.accent.
 *
 * @param onPairClick Callback to initiate device pairing.
 * @param modifier    Layout modifier.
 */
@Composable
private fun EmptyState(
    onPairClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = BeamSpace.s8),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "No devices paired.",
            style = BeamTextStyle.xlSemibold,
            color = BeamPalette.textHi,
            textAlign = TextAlign.Center,
        )

        Spacer(modifier = Modifier.height(BeamSpace.s2))

        Text(
            text = "Pair one to start sending.",
            style = BeamTextStyle.baseRegular,
            color = BeamPalette.textMid,
            textAlign = TextAlign.Center,
        )

        Spacer(modifier = Modifier.height(BeamSpace.s8))

        Button(
            onClick = onPairClick,
            modifier = Modifier.height(56.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = BeamPalette.accent,
                contentColor = Color.White,
            ),
            shape = RoundedCornerShape(BeamCorner.md),
        ) {
            Text(
                text = "Pair a device",
                style = BeamTextStyle.mdMedium,
                color = Color.White,
            )
        }
    }
}

// ── Icon + label helpers ─────────────────────────────────────────────────────

/**
 * Returns the [ImageVector] that best represents the device's form factor.
 * Delegates to [BeamIcons.forDeviceType] for the semantic icon mapping.
 *
 * @param entity The paired device entity containing the [icon] field.
 */
private fun platformIcon(entity: PairedDeviceEntity): ImageVector =
    BeamIcons.forDeviceType(entity.icon?.lowercase())

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

/**
 * Returns a human-readable accessibility label for a device type icon token.
 *
 * @param iconToken The icon token stored in [PairedDeviceEntity.icon], e.g. "LAPTOP".
 * @return Display string such as "Laptop", "Desktop", "Phone", or "Tablet".
 */
private fun deviceTypeLabel(iconToken: String?): String = when (iconToken?.lowercase()) {
    "laptop" -> "Laptop"
    "desktop" -> "Desktop"
    "phone" -> "Phone"
    "tablet" -> "Tablet"
    else -> "Device"
}

// ── Formatting helpers ───────────────────────────────────────────────────────

/**
 * Formats a Unix-epoch timestamp as a human-readable relative time string.
 *
 * @param timestamp Unix epoch millis to format.
 * @return A string like "just now", "3m ago", "2h ago", or "5d ago".
 */
private fun formatRelativeTime(timestamp: Long): String {
    val diff = abs(System.currentTimeMillis() - timestamp)
    return when {
        diff < 60_000L -> "just now"
        diff < 3_600_000L -> "${diff / 60_000L}m ago"
        diff < 86_400_000L -> "${diff / 3_600_000L}h ago"
        else -> "${diff / 86_400_000L}d ago"
    }
}

/**
 * Formats a raw byte count into a compact SI-prefixed string.
 *
 * @param bytes Non-negative byte count.
 * @return Human-readable size string with one decimal place for KB/MB/GB.
 */
private fun formatFileSize(bytes: Long): String {
    val fmt = DecimalFormat("0.#")
    return when {
        bytes < 1_024L -> "$bytes B"
        bytes < 1_048_576L -> "${fmt.format(bytes / 1_024.0)} KB"
        bytes < 1_073_741_824L -> "${fmt.format(bytes / 1_048_576.0)} MB"
        else -> "${fmt.format(bytes / 1_073_741_824.0)} GB"
    }
}
