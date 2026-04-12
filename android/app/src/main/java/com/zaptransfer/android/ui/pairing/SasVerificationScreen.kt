package com.zaptransfer.android.ui.pairing

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zaptransfer.android.ui.theme.BeamCorner
import com.zaptransfer.android.ui.theme.BeamIcons
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.ui.theme.BeamSpace
import com.zaptransfer.android.ui.theme.BeamTextStyle

/**
 * SAS (Short Authentication String) emoji verification screen — Phase D, Task 14.
 *
 * Displays the 4 emoji derived from the X25519 key exchange and prompts the user
 * to visually confirm they match the emoji shown on the paired device (Chrome extension).
 *
 * The emoji table is identical between this app and the Chrome extension (spec §4.4.2).
 * Both sides must derive the same 4 emoji from the shared secret — a mismatch means
 * a MITM attack is in progress and the user should tap "No Match".
 *
 * Layout:
 *  - Instruction text explaining the verification step
 *  - 4 large emoji in a 2×2 grid, each with a text label below
 *  - "They Match" filled button (accent)
 *  - "No Match" outlined button (danger colour)
 *
 * Navigation triggers:
 *  - "They Match" → [viewModel.onSasConfirmed] → [PairingUiState.Naming] → [onNavigateToNaming]
 *  - "No Match"   → [viewModel.onSasDenied]    → [PairingUiState.Scanning] → [onBack] twice
 *
 * @param viewModel         Shared [PairingViewModel]; must be in [PairingUiState.Verifying].
 * @param onNavigateToNaming Callback to push the device naming screen.
 * @param onBack             Pop back to the scanner (after "No Match").
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SasVerificationScreen(
    viewModel: PairingViewModel,
    onNavigateToNaming: () -> Unit,
    onBack: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()

    // Navigate to naming when SAS is confirmed
    LaunchedEffect(uiState) {
        when (uiState) {
            is PairingUiState.Naming -> onNavigateToNaming()
            is PairingUiState.Scanning -> onBack()  // "No Match" or error reset
            else -> Unit
        }
    }

    // Guard: only render the SAS UI when in the Verifying state
    val verifyingState = uiState as? PairingUiState.Verifying
        ?: return  // Screen was opened without going through the correct flow

    val sas = verifyingState.sas

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Verify Connection",
                        style = BeamTextStyle.lgSemibold,
                        color = BeamPalette.textHi,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = {
                        viewModel.onSasDenied()
                        // onBack is called reactively via the LaunchedEffect above
                    }) {
                        Icon(
                            imageVector = BeamIcons.back,
                            contentDescription = "Cancel pairing",
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
                .padding(horizontal = BeamSpace.s4),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {

            // ── Title ────────────────────────────────────────────────────────
            Text(
                text = "Verify connection",
                style = BeamTextStyle.lgSemibold,
                color = BeamPalette.textHi,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(BeamSpace.s2))

            // ── Instruction ──────────────────────────────────────────────────
            Text(
                text = "Do these emoji match on both devices?",
                style = BeamTextStyle.baseRegular,
                color = BeamPalette.textMid,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(BeamSpace.s8))

            // ── 2×2 emoji grid ───────────────────────────────────────────────
            Column(
                verticalArrangement = Arrangement.spacedBy(BeamSpace.s3),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                // Row 1: emoji 0 and 1
                Row(
                    horizontalArrangement = Arrangement.spacedBy(BeamSpace.s3),
                ) {
                    sas.emoji.take(2).forEachIndexed { index, emoji ->
                        EmojiCard(
                            emoji = emoji,
                            label = sas.labels.getOrElse(index) { emoji },
                        )
                    }
                }
                // Row 2: emoji 2 and 3
                Row(
                    horizontalArrangement = Arrangement.spacedBy(BeamSpace.s3),
                ) {
                    sas.emoji.drop(2).take(2).forEachIndexed { index, emoji ->
                        EmojiCard(
                            emoji = emoji,
                            label = sas.labels.getOrElse(index + 2) { emoji },
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(BeamSpace.s8))

            // ── Action buttons ───────────────────────────────────────────────
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = BeamSpace.s4),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(BeamSpace.s3),
            ) {
                // "They Match" — accent filled button
                Button(
                    onClick = { viewModel.onSasConfirmed() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = BeamPalette.accent,
                        contentColor = Color.White,
                    ),
                    shape = RoundedCornerShape(BeamCorner.md),
                ) {
                    Text(
                        text = "They Match",
                        style = BeamTextStyle.baseMedium,
                        color = Color.White,
                    )
                }

                // "No Match" — outlined danger button
                OutlinedButton(
                    onClick = { viewModel.onSasDenied() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    border = BorderStroke(
                        width = 1.dp,
                        color = BeamPalette.danger,
                    ),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = BeamPalette.danger,
                    ),
                    shape = RoundedCornerShape(BeamCorner.md),
                ) {
                    Text(
                        text = "No Match",
                        style = BeamTextStyle.baseMedium,
                        color = BeamPalette.danger,
                    )
                }
            }

            Spacer(modifier = Modifier.height(BeamSpace.s6))

            Text(
                text = "If the symbols don't match, someone may be intercepting " +
                    "your connection. Tap \"No Match\" to cancel.",
                style = BeamTextStyle.smRegular,
                color = BeamPalette.textLo,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = BeamSpace.s4),
            )
        }
    }
}

// ── Single emoji card ─────────────────────────────────────────────────────────

/**
 * Displays one SAS emoji in an 80×80dp card with a text label below.
 *
 * @param emoji The emoji character to display (single code point or ZWJ sequence).
 * @param label Descriptive label below the emoji.
 */
@Composable
private fun EmojiCard(
    emoji: String,
    label: String,
) {
    val shape = RoundedCornerShape(BeamCorner.lg)
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(80.dp)
                .background(color = BeamPalette.bg1, shape = shape)
                .border(
                    width = 1.dp,
                    color = BeamPalette.borderSubtle,
                    shape = shape,
                ),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = emoji,
                fontSize = 32.sp,
                textAlign = TextAlign.Center,
            )
        }
        if (label.isNotEmpty()) {
            Spacer(modifier = Modifier.height(BeamSpace.s1))
            Text(
                text = label,
                style = BeamTextStyle.xsRegular,
                color = BeamPalette.textLo,
                textAlign = TextAlign.Center,
            )
        }
    }
}
