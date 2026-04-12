package com.zaptransfer.android.ui.settings

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.ui.theme.BeamCorner
import com.zaptransfer.android.ui.theme.BeamIcons
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.ui.theme.BeamSpace
import com.zaptransfer.android.ui.theme.BeamTextStyle
import com.zaptransfer.android.ui.theme.BeamTheme

/**
 * Settings screen with exactly 4 configurable items per spec §8.3:
 *
 *  1. **Save location** — shows current path; tapping opens the SAF directory picker.
 *  2. **Auto-accept** — [Switch] to toggle auto-acceptance of transfers from paired devices.
 *  3. **Device name** — displays current name; tapping opens an edit [AlertDialog].
 *  4. **Paired devices** — count of paired devices; tapping expands an inline sub-list
 *     where each entry has an "Unpair" text button.
 *
 * Navigation: [onBack] pops this screen from the back stack.
 *
 * @param onBack    Called when the user taps the back arrow in the [TopAppBar].
 * @param viewModel [SettingsViewModel] injected via Hilt — holds DataStore + Room state.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()

    SettingsContent(
        uiState = uiState,
        onBack = onBack,
        onSaveLocationSelected = { uri -> viewModel.setSaveLocation(uri) },
        onClearSaveLocation = { viewModel.clearSaveLocation() },
        onAutoAcceptChanged = { enabled -> viewModel.setAutoAccept(enabled) },
        onAutoCopyChanged = { enabled -> viewModel.setAutoCopyClipboard(enabled) },
        onAutoSaveChanged = { enabled -> viewModel.setAutoSaveFiles(enabled) },
        onDeviceNameChanged = { name -> viewModel.setDeviceName(name) },
        onUnpair = { deviceId -> viewModel.unPairDevice(deviceId) },
    )
}

/**
 * Stateless content layer for [SettingsScreen].
 *
 * Separated from the ViewModel-wired version to allow pure Composable previews
 * without Hilt.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsContent(
    uiState: SettingsUiState,
    onBack: () -> Unit,
    onSaveLocationSelected: (String) -> Unit,
    onClearSaveLocation: () -> Unit,
    onAutoAcceptChanged: (Boolean) -> Unit,
    onAutoCopyChanged: (Boolean) -> Unit,
    onAutoSaveChanged: (Boolean) -> Unit,
    onDeviceNameChanged: (String) -> Unit,
    onUnpair: (String) -> Unit,
) {
    // Dialog state for device name edit
    var showNameDialog by remember { mutableStateOf(false) }
    var nameInput by remember(uiState.prefs.deviceName) {
        mutableStateOf(uiState.prefs.deviceName)
    }

    // SAF directory picker
    val context = LocalContext.current
    val dirPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree(),
    ) { uri: Uri? ->
        if (uri != null) {
            // Persist read + write permission across reboots
            context.contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
            onSaveLocationSelected(uri.toString())
        }
    }

    // Custom switch colors matching Beam tokens
    val beamSwitchColors = SwitchDefaults.colors(
        checkedThumbColor = Color.White,
        checkedTrackColor = BeamPalette.accent,
        uncheckedThumbColor = BeamPalette.textLo,
        uncheckedTrackColor = BeamPalette.borderSubtle,
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Settings",
                        style = BeamTextStyle.lgSemibold,
                        color = BeamPalette.textHi,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = BeamIcons.back,
                            contentDescription = "Back",
                            tint = BeamPalette.textMid,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = BeamPalette.bg0,
                    titleContentColor = BeamPalette.textHi,
                    navigationIconContentColor = BeamPalette.textMid,
                ),
            )
        },
        containerColor = BeamPalette.bg0,
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {

            // ── Section: Transfers ──────────────────────────────────────────
            item {
                SectionHeader(title = "TRANSFERS")
            }

            // Auto-copy clipboard
            item {
                SettingsToggleRow(
                    label = "Auto-copy clipboard",
                    description = if (uiState.prefs.autoCopyClipboard) {
                        "Incoming clipboard content is copied automatically"
                    } else {
                        "Tap received clipboard items to copy manually"
                    },
                    checked = uiState.prefs.autoCopyClipboard,
                    onCheckedChange = onAutoCopyChanged,
                    switchColors = beamSwitchColors,
                )
                HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)
            }

            // Auto-save files
            item {
                SettingsToggleRow(
                    label = "Auto-save files",
                    description = if (uiState.prefs.autoSaveFiles) {
                        "Incoming files are saved automatically"
                    } else {
                        "You will be prompted before saving received files"
                    },
                    checked = uiState.prefs.autoSaveFiles,
                    onCheckedChange = onAutoSaveChanged,
                    switchColors = beamSwitchColors,
                )
                HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)
            }

            // Auto-accept transfers
            item {
                SettingsToggleRow(
                    label = "Auto-accept transfers",
                    description = if (uiState.prefs.autoAccept) {
                        "Incoming files from paired devices are accepted automatically"
                    } else {
                        "You will be prompted before each incoming transfer"
                    },
                    checked = uiState.prefs.autoAccept,
                    onCheckedChange = onAutoAcceptChanged,
                    switchColors = beamSwitchColors,
                )
                HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)
            }

            // ── Section: Save Location ──────────────────────────────────────
            item {
                SectionHeader(title = "SAVE LOCATION")
            }

            item {
                val locationLabel = uiState.prefs.saveLocationUri
                    ?.let { uri ->
                        Uri.parse(uri).lastPathSegment ?: uri
                    }
                    ?: "Downloads (default)"

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .clickable { dirPickerLauncher.launch(null) }
                        .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s3),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Save location",
                            style = BeamTextStyle.xsRegular,
                            color = BeamPalette.textMid,
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = locationLabel,
                            style = BeamTextStyle.baseRegular,
                            color = BeamPalette.textHi,
                        )
                    }
                    Icon(
                        imageVector = BeamIcons.folderOpen,
                        contentDescription = "Choose folder",
                        tint = BeamPalette.textMid,
                        modifier = Modifier.size(24.dp),
                    )
                }
                HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)
            }

            // ── Section: Device ─────────────────────────────────────────────
            item {
                SectionHeader(title = "DEVICE")
            }

            // Device name
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .clickable { showNameDialog = true }
                        .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s3),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Device name",
                            style = BeamTextStyle.xsRegular,
                            color = BeamPalette.textMid,
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = uiState.prefs.deviceName,
                            style = BeamTextStyle.baseMedium,
                            color = BeamPalette.textHi,
                        )
                    }
                    Icon(
                        imageVector = BeamIcons.edit,
                        contentDescription = "Edit device name",
                        tint = BeamPalette.textMid,
                        modifier = Modifier.size(24.dp),
                    )
                }
                HorizontalDivider(color = BeamPalette.borderSubtle, thickness = 1.dp)
            }

            // ── Section: Paired Devices ─────────────────────────────────────
            item {
                SectionHeader(title = "PAIRED DEVICES")
            }

            if (uiState.pairedDevices.isEmpty()) {
                item {
                    Text(
                        text = "No paired devices",
                        style = BeamTextStyle.baseRegular,
                        color = BeamPalette.textLo,
                        modifier = Modifier.padding(
                            horizontal = BeamSpace.s4,
                            vertical = BeamSpace.s3,
                        ),
                    )
                }
            } else {
                items(
                    items = uiState.pairedDevices,
                    key = { it.deviceId },
                ) { device ->
                    PairedDeviceRow(
                        device = device,
                        onUnpair = { onUnpair(device.deviceId) },
                    )
                    HorizontalDivider(
                        color = BeamPalette.borderSubtle,
                        thickness = 1.dp,
                        modifier = Modifier.padding(start = BeamSpace.s4),
                    )
                }
            }

            // ── Section: About ──────────────────────────────────────────────
            item {
                SectionHeader(title = "ABOUT")
            }

            item {
                Text(
                    text = "Version 0.1.0",
                    style = BeamTextStyle.xsRegular,
                    color = BeamPalette.textLo,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = BeamSpace.s3),
                )
            }

            // Bottom spacer for comfortable last-item visibility
            item { Spacer(modifier = Modifier.height(BeamSpace.s6)) }
        }
    }

    // ── Device name edit dialog ──────────────────────────────────────────────
    if (showNameDialog) {
        AlertDialog(
            onDismissRequest = { showNameDialog = false },
            containerColor = BeamPalette.bg2,
            titleContentColor = BeamPalette.textHi,
            textContentColor = BeamPalette.textMid,
            title = {
                Text(
                    text = "Device name",
                    style = BeamTextStyle.lgSemibold,
                    color = BeamPalette.textHi,
                )
            },
            text = {
                Column {
                    Text(
                        text = "Choose a name that your paired devices will see.",
                        style = BeamTextStyle.baseRegular,
                        color = BeamPalette.textMid,
                    )
                    Spacer(modifier = Modifier.height(BeamSpace.s3))
                    OutlinedTextField(
                        value = nameInput,
                        onValueChange = { if (it.length <= 50) nameInput = it },
                        label = {
                            Text(
                                text = "Name",
                                style = BeamTextStyle.smRegular,
                            )
                        },
                        textStyle = BeamTextStyle.baseMedium.copy(color = BeamPalette.textHi),
                        singleLine = true,
                        supportingText = {
                            Text(
                                text = "${nameInput.length}/50",
                                style = BeamTextStyle.xsRegular,
                                color = BeamPalette.textLo,
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(BeamCorner.md),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedContainerColor = BeamPalette.bg1,
                            unfocusedContainerColor = BeamPalette.bg1,
                            focusedBorderColor = BeamPalette.accent,
                            unfocusedBorderColor = BeamPalette.borderSubtle,
                            cursorColor = BeamPalette.accent,
                            focusedLabelColor = BeamPalette.accent,
                            unfocusedLabelColor = BeamPalette.textMid,
                        ),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDeviceNameChanged(nameInput)
                        showNameDialog = false
                    },
                    enabled = nameInput.isNotBlank(),
                ) {
                    Text(
                        text = "Save",
                        style = BeamTextStyle.baseMedium,
                        color = if (nameInput.isNotBlank()) BeamPalette.accent else BeamPalette.textDisabled,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showNameDialog = false }) {
                    Text(
                        text = "Cancel",
                        style = BeamTextStyle.baseMedium,
                        color = BeamPalette.textMid,
                    )
                }
            },
        )
    }
}

// ── Section header ──────────────────────────────────────────────────────────

/**
 * Section header for settings groups.
 *
 * @param title The section title text (should be passed as uppercase).
 */
@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = BeamTextStyle.smMedium.copy(letterSpacing = 2.sp),
        color = BeamPalette.textMid,
        modifier = Modifier.padding(
            start = BeamSpace.s4,
            top = BeamSpace.s4,
            bottom = BeamSpace.s1,
        ),
    )
}

// ── Toggle row ──────────────────────────────────────────────────────────────

/**
 * A settings row with a label, description, and toggle switch.
 *
 * @param label          Primary label text.
 * @param description    Supporting description text.
 * @param checked        Current toggle state.
 * @param onCheckedChange Callback when the toggle changes.
 * @param switchColors   Colors for the Material Switch.
 */
@Composable
private fun SettingsToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    switchColors: androidx.compose.material3.SwitchColors,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s3),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = BeamTextStyle.baseMedium,
                color = BeamPalette.textHi,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = description,
                style = BeamTextStyle.xsRegular,
                color = BeamPalette.textLo,
            )
        }
        Spacer(modifier = Modifier.width(BeamSpace.s3))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = switchColors,
        )
    }
}

// ── Paired device row ───────────────────────────────────────────────────────

/**
 * A single row in the paired-devices list.
 *
 * Shows the device icon, name, and an "Unpair" text button that triggers a
 * confirmation dialog.
 *
 * @param device  The paired device record.
 * @param onUnpair Called when the user confirms the unpair action.
 */
@Composable
private fun PairedDeviceRow(
    device: PairedDeviceEntity,
    onUnpair: () -> Unit,
) {
    var showConfirm by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s3),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Device type icon
        Icon(
            imageVector = BeamIcons.forDeviceType(device.icon?.lowercase()),
            contentDescription = null,
            tint = BeamPalette.textMid,
            modifier = Modifier.size(24.dp),
        )
        Spacer(modifier = Modifier.width(BeamSpace.s3))

        // Device name
        Text(
            text = device.name,
            style = BeamTextStyle.baseMedium,
            color = BeamPalette.textHi,
            modifier = Modifier.weight(1f),
        )

        // Unpair text button
        TextButton(onClick = { showConfirm = true }) {
            Text(
                text = "Unpair",
                style = BeamTextStyle.smMedium,
                color = BeamPalette.danger,
            )
        }
    }

    // Confirmation dialog so users don't accidentally unpair
    if (showConfirm) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            containerColor = BeamPalette.bg2,
            titleContentColor = BeamPalette.textHi,
            textContentColor = BeamPalette.textMid,
            title = {
                Text(
                    text = "Unpair device?",
                    style = BeamTextStyle.lgSemibold,
                    color = BeamPalette.textHi,
                )
            },
            text = {
                Text(
                    text = "\"${device.name}\" will no longer be able to transfer files to or from this device.",
                    style = BeamTextStyle.baseRegular,
                    color = BeamPalette.textMid,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onUnpair()
                        showConfirm = false
                    },
                ) {
                    Text(
                        text = "Unpair",
                        style = BeamTextStyle.baseMedium,
                        color = BeamPalette.danger,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }) {
                    Text(
                        text = "Cancel",
                        style = BeamTextStyle.baseMedium,
                        color = BeamPalette.textMid,
                    )
                }
            },
        )
    }
}

// ── Previews ─────────────────────────────────────────────────────────────────

@Preview(showBackground = true, name = "Settings — populated")
@Composable
private fun SettingsScreenPreview() {
    BeamTheme {
        SettingsContent(
            uiState = SettingsUiState(
                pairedDevices = listOf(
                    PairedDeviceEntity(
                        deviceId = "abc123",
                        name = "Alice's MacBook",
                        icon = "LAPTOP",
                        platform = "chrome_extension",
                        x25519PublicKey = ByteArray(32),
                        ed25519PublicKey = ByteArray(32),
                        pairedAt = System.currentTimeMillis(),
                    )
                )
            ),
            onBack = {},
            onSaveLocationSelected = {},
            onClearSaveLocation = {},
            onAutoAcceptChanged = {},
            onAutoCopyChanged = {},
            onAutoSaveChanged = {},
            onDeviceNameChanged = {},
            onUnpair = {},
        )
    }
}

@Preview(showBackground = true, name = "Settings — empty devices")
@Composable
private fun SettingsScreenEmptyPreview() {
    BeamTheme {
        SettingsContent(
            uiState = SettingsUiState(),
            onBack = {},
            onSaveLocationSelected = {},
            onClearSaveLocation = {},
            onAutoAcceptChanged = {},
            onAutoCopyChanged = {},
            onAutoSaveChanged = {},
            onDeviceNameChanged = {},
            onUnpair = {},
        )
    }
}
