package com.zaptransfer.android.ui.settings

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.data.db.entity.PairedDeviceEntity
import com.zaptransfer.android.ui.theme.BeamTheme

/**
 * Settings screen with exactly 4 configurable items per spec §8.3:
 *
 *  1. **Save location** — shows current path; tapping opens the SAF directory picker.
 *  2. **Auto-accept** — [Switch] to toggle auto-acceptance of transfers from paired devices.
 *  3. **Device name** — displays current name; tapping opens an edit [AlertDialog].
 *  4. **Paired devices** — count of paired devices; tapping expands an inline sub-list
 *     where each entry has an "Unpair" [IconButton].
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
    onDeviceNameChanged: (String) -> Unit,
    onUnpair: (String) -> Unit,
) {
    // Dialog state for setting 3 (device name edit)
    var showNameDialog by remember { mutableStateOf(false) }
    var nameInput by remember(uiState.prefs.deviceName) {
        mutableStateOf(uiState.prefs.deviceName)
    }

    // Whether the paired devices sub-list is expanded (setting 4)
    var devicesExpanded by remember { mutableStateOf(false) }

    // SAF directory picker for setting 1
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
            )
        },
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {

            // ── Setting 1: Save location ─────────────────────────────────────
            item {
                val locationLabel = uiState.prefs.saveLocationUri
                    ?.let { uri ->
                        // Show only the last path segment for readability
                        Uri.parse(uri).lastPathSegment ?: uri
                    }
                    ?: "Downloads (default)"

                ListItem(
                    modifier = Modifier.clickable { dirPickerLauncher.launch(null) },
                    headlineContent = { Text("Save location") },
                    supportingContent = { Text(locationLabel) },
                    leadingContent = {
                        Icon(
                            imageVector = Icons.Default.FolderOpen,
                            contentDescription = null,
                        )
                    },
                    trailingContent = {
                        if (uiState.prefs.saveLocationUri != null) {
                            TextButton(onClick = onClearSaveLocation) {
                                Text("Reset")
                            }
                        }
                    },
                )
                HorizontalDivider()
            }

            // ── Setting 2: Auto-accept ────────────────────────────────────────
            item {
                ListItem(
                    headlineContent = { Text("Auto-accept transfers") },
                    supportingContent = {
                        Text(
                            if (uiState.prefs.autoAccept) {
                                "Incoming files from paired devices are accepted automatically"
                            } else {
                                "You will be prompted before each incoming transfer"
                            }
                        )
                    },
                    trailingContent = {
                        Switch(
                            checked = uiState.prefs.autoAccept,
                            onCheckedChange = onAutoAcceptChanged,
                        )
                    },
                )
                HorizontalDivider()
            }

            // ── Setting 3: Device name ────────────────────────────────────────
            item {
                ListItem(
                    modifier = Modifier.clickable { showNameDialog = true },
                    headlineContent = { Text("Device name") },
                    supportingContent = { Text(uiState.prefs.deviceName) },
                    trailingContent = {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = "Edit device name",
                        )
                    },
                )
                HorizontalDivider()
            }

            // ── Setting 4: Paired devices header ─────────────────────────────
            item {
                ListItem(
                    modifier = Modifier.clickable { devicesExpanded = !devicesExpanded },
                    headlineContent = { Text("Paired devices") },
                    supportingContent = {
                        val count = uiState.pairedDevices.size
                        Text(if (count == 0) "No paired devices" else "$count device(s)")
                    },
                )
            }

            // ── Setting 4 sub-list: individual paired devices ─────────────────
            if (devicesExpanded && uiState.pairedDevices.isNotEmpty()) {
                items(
                    items = uiState.pairedDevices,
                    key = { it.deviceId },
                ) { device ->
                    PairedDeviceRow(
                        device = device,
                        onUnpair = { onUnpair(device.deviceId) },
                    )
                }
            }

            // Bottom spacer for comfortable last-item visibility
            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }

    // ── Device name edit dialog ───────────────────────────────────────────────
    if (showNameDialog) {
        AlertDialog(
            onDismissRequest = { showNameDialog = false },
            title = { Text("Device name") },
            text = {
                Column {
                    Text(
                        text = "Choose a name that your paired devices will see.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = nameInput,
                        onValueChange = { if (it.length <= 50) nameInput = it },
                        label = { Text("Name") },
                        singleLine = true,
                        supportingText = { Text("${nameInput.length}/50") },
                        modifier = Modifier.fillMaxWidth(),
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
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showNameDialog = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}

/**
 * A single row in the paired-devices sub-list.
 *
 * Shows the device name and an "Unpair" icon button that triggers a confirmation.
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
            .padding(start = 32.dp, end = 16.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = device.name,
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = device.platform,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = { showConfirm = true }) {
            Icon(
                imageVector = Icons.Default.Delete,
                contentDescription = "Unpair ${device.name}",
                tint = MaterialTheme.colorScheme.error,
            )
        }
    }
    HorizontalDivider(modifier = Modifier.padding(start = 32.dp))

    // Confirmation dialog so users don't accidentally unpair
    if (showConfirm) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Unpair device?") },
            text = { Text("\"${device.name}\" will no longer be able to transfer files to or from this device.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        onUnpair()
                        showConfirm = false
                    },
                ) {
                    Text("Unpair", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }) {
                    Text("Cancel")
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
            onDeviceNameChanged = {},
            onUnpair = {},
        )
    }
}
