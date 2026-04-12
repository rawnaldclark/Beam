package com.zaptransfer.android.ui.pairing

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zaptransfer.android.ui.theme.BeamCorner
import com.zaptransfer.android.ui.theme.BeamIcons
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.ui.theme.BeamSpace
import com.zaptransfer.android.ui.theme.BeamTextStyle

// ── Icon definitions ──────────────────────────────────────────────────────────

/**
 * Available device icon options shown in the icon picker grid.
 *
 * The [token] value is stored in [PairedDeviceEntity.icon] and used by the
 * Device Hub to select the correct icon when rendering device cards.
 */
private data class DeviceIconOption(
    val token: String,
    val icon: ImageVector,
    val label: String,
)

private val ICON_OPTIONS = listOf(
    DeviceIconOption("LAPTOP", BeamIcons.laptop, "Laptop"),
    DeviceIconOption("DESKTOP", BeamIcons.desktop, "Desktop"),
    DeviceIconOption("PHONE", BeamIcons.phone, "Phone"),
    DeviceIconOption("TABLET", BeamIcons.tablet, "Tablet"),
)

/** Default icon token used when no selection has been made explicitly. */
private const val DEFAULT_ICON = "LAPTOP"

// ── DeviceNamingScreen ────────────────────────────────────────────────────────

/**
 * Device naming screen — Phase D, Task 15.
 *
 * The final step of the pairing ceremony. Allows the user to:
 *  1. Edit the suggested device name (pre-filled from the peer's self-reported name).
 *  2. Pick an icon from a 4-option grid (Laptop, Desktop, Phone, Tablet).
 *  3. Tap "Done" to save the [PairedDeviceEntity] to Room and complete pairing.
 *
 * Validation:
 *  - The "Done" button is disabled when the name field is empty or blank.
 *  - Name is trimmed before saving.
 *
 * Navigation triggers:
 *  - "Done" → [viewModel.onNamingComplete] → [PairingUiState.Complete] → [onNavigateToHub]
 *  - Back → [onBack] (returns to SAS verification; user cannot re-verify from here)
 *
 * @param viewModel       Shared [PairingViewModel]; must be in [PairingUiState.Naming].
 * @param onNavigateToHub Callback to navigate to the Device Hub (clears pairing back stack).
 * @param onBack          Pop back to the SAS verification screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceNamingScreen(
    viewModel: PairingViewModel,
    onNavigateToHub: () -> Unit,
    onBack: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()

    // Navigate to hub when naming completes
    LaunchedEffect(uiState) {
        if (uiState is PairingUiState.Complete) {
            onNavigateToHub()
        }
    }

    // Guard: only render when in the Naming state
    val namingState = uiState as? PairingUiState.Naming ?: return

    // Local UI state — not hoisted to ViewModel since it is ephemeral form state
    var name by remember { mutableStateOf(namingState.suggestedName) }
    var selectedIcon by remember { mutableStateOf(DEFAULT_ICON) }

    val isDoneEnabled = name.isNotBlank()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Name This Device",
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
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = BeamSpace.s6)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {

            Spacer(modifier = Modifier.height(BeamSpace.s7))

            // ── Subtitle ─────────────────────────────────────────────────────
            Text(
                text = "Give this device a name so you can recognise it in your device list.",
                style = BeamTextStyle.baseRegular,
                color = BeamPalette.textMid,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(BeamSpace.s7))

            // ── Device name field ────────────────────────────────────────────
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = {
                    Text(
                        text = "Device name",
                        style = BeamTextStyle.smRegular,
                    )
                },
                placeholder = {
                    Text(
                        text = "e.g. Work Laptop, Home Desktop",
                        style = BeamTextStyle.baseRegular,
                        color = BeamPalette.textLo,
                    )
                },
                textStyle = BeamTextStyle.baseMedium.copy(color = BeamPalette.textHi),
                singleLine = true,
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
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Words,
                    imeAction = ImeAction.Done,
                ),
                isError = name.isBlank() && name.isNotEmpty(), // error only after user clears
                supportingText = if (name.isBlank() && name.isNotEmpty()) {
                    {
                        Text(
                            text = "Name cannot be empty",
                            style = BeamTextStyle.xsRegular,
                            color = BeamPalette.danger,
                        )
                    }
                } else null,
            )

            Spacer(modifier = Modifier.height(BeamSpace.s8))

            // ── Icon picker ──────────────────────────────────────────────────
            Text(
                text = "Choose an icon",
                style = BeamTextStyle.mdMedium,
                color = BeamPalette.textHi,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(BeamSpace.s4))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(BeamSpace.s3),
            ) {
                ICON_OPTIONS.forEach { option ->
                    DeviceIconTile(
                        option = option,
                        isSelected = selectedIcon == option.token,
                        onClick = { selectedIcon = option.token },
                    )
                }
            }

            Spacer(modifier = Modifier.height(BeamSpace.s8))

            // ── Done button ──────────────────────────────────────────────────
            Button(
                onClick = {
                    viewModel.onNamingComplete(name = name.trim(), icon = selectedIcon)
                },
                enabled = isDoneEnabled,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = BeamPalette.accent,
                    contentColor = Color.White,
                    disabledContainerColor = BeamPalette.accent.copy(alpha = 0.4f),
                    disabledContentColor = Color.White.copy(alpha = 0.5f),
                ),
                shape = RoundedCornerShape(BeamCorner.md),
            ) {
                Text(
                    text = "Done",
                    style = BeamTextStyle.baseMedium,
                    color = Color.White,
                )
            }

            Spacer(modifier = Modifier.height(BeamSpace.s7))
        }
    }
}

// ── Device icon tile ─────────────────────────────────────────────────────────

/**
 * A tappable icon tile for the icon picker grid.
 *
 * Selected state: accent-12 fill with accent border.
 * Unselected state: bg/1 fill with borderSubtle border.
 *
 * @param option     The [DeviceIconOption] this tile represents.
 * @param isSelected Whether this tile is the currently selected icon.
 * @param onClick    Callback to select this icon.
 */
@Composable
private fun DeviceIconTile(
    option: DeviceIconOption,
    isSelected: Boolean,
    onClick: () -> Unit,
) {
    val shape = RoundedCornerShape(BeamCorner.md)
    val borderColor = if (isSelected) BeamPalette.accent else BeamPalette.borderSubtle
    val containerColor = if (isSelected) BeamPalette.accent12 else BeamPalette.bg1
    val contentColor = if (isSelected) BeamPalette.accent else BeamPalette.textMid

    Box(
        modifier = Modifier
            .size(48.dp)
            .clip(shape)
            .background(containerColor)
            .border(
                width = if (isSelected) 2.dp else 1.dp,
                color = borderColor,
                shape = shape,
            )
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = option.icon,
            contentDescription = option.label,
            tint = contentColor,
            modifier = Modifier.size(24.dp),
        )
    }
}
