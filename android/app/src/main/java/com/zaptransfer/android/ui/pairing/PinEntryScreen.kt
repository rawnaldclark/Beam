package com.zaptransfer.android.ui.pairing

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zaptransfer.android.ui.theme.BeamCorner
import com.zaptransfer.android.ui.theme.BeamIcons
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.ui.theme.BeamSpace
import com.zaptransfer.android.ui.theme.BeamTextStyle

private const val PIN_LENGTH = 8

/**
 * PIN entry screen using a single hidden BasicTextField with visual digit boxes.
 * This is the standard pattern for OTP/PIN inputs — avoids focus management issues
 * with multiple TextFields.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinEntryScreen(
    viewModel: PairingViewModel,
    onNavigateToVerify: () -> Unit,
    onBack: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()

    LaunchedEffect(uiState) {
        if (uiState is PairingUiState.Verifying) {
            onNavigateToVerify()
        }
    }

    val errorMessage: String? = (uiState as? PairingUiState.PinEntry)?.errorMessage

    var pinText by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current

    // Auto-focus and show keyboard on launch
    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }

    // Auto-submit when all 8 digits entered
    LaunchedEffect(pinText) {
        if (pinText.length == PIN_LENGTH) {
            keyboardController?.hide()
            viewModel.onPinSubmitted(pinText)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Enter Pairing PIN",
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
                .padding(horizontal = BeamSpace.s6),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "Enter the 8-digit PIN",
                style = BeamTextStyle.lgSemibold,
                color = BeamPalette.textHi,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(BeamSpace.s2))

            Text(
                text = "Find the PIN displayed on the other device.",
                style = BeamTextStyle.baseRegular,
                color = BeamPalette.textMid,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(BeamSpace.s8))

            // Hidden BasicTextField that captures all keyboard input.
            // Rendered with 0 alpha but full width so it's focusable.
            BasicTextField(
                value = pinText,
                onValueChange = { newVal ->
                    val filtered = newVal.filter { it.isDigit() }.take(PIN_LENGTH)
                    pinText = filtered
                },
                modifier = Modifier
                    .focusRequester(focusRequester)
                    .fillMaxWidth()
                    .height(1.dp)
                    .alpha(0f),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done,
                ),
                singleLine = true,
            )

            // Visual digit boxes — tapping anywhere re-focuses the hidden input
            // Row 1: digits 1-4
            Row(
                horizontalArrangement = Arrangement.spacedBy(BeamSpace.s2, Alignment.CenterHorizontally),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(
                        indication = null,
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        focusRequester.requestFocus()
                        keyboardController?.show()
                    },
            ) {
                repeat(4) { index ->
                    DigitBox(
                        digit = pinText.getOrNull(index)?.toString() ?: "",
                        isFocused = index == pinText.length,
                        hasError = errorMessage != null,
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            Spacer(modifier = Modifier.height(BeamSpace.s3))

            // Row 2: digits 5-8
            Row(
                horizontalArrangement = Arrangement.spacedBy(BeamSpace.s2, Alignment.CenterHorizontally),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(
                        indication = null,
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        focusRequester.requestFocus()
                        keyboardController?.show()
                    },
            ) {
                repeat(4) { index ->
                    val actualIndex = index + 4
                    DigitBox(
                        digit = pinText.getOrNull(actualIndex)?.toString() ?: "",
                        isFocused = actualIndex == pinText.length,
                        hasError = errorMessage != null,
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            // Error message
            if (errorMessage != null) {
                Spacer(modifier = Modifier.height(BeamSpace.s4))
                Text(
                    text = errorMessage,
                    color = BeamPalette.danger,
                    style = BeamTextStyle.smRegular,
                    textAlign = TextAlign.Center,
                )
            }

            Spacer(modifier = Modifier.height(BeamSpace.s6))

            Text(
                text = "The PIN expires after 60 seconds.",
                style = BeamTextStyle.smRegular,
                color = BeamPalette.textLo,
            )
        }
    }
}

/**
 * Individual digit box for the PIN entry grid.
 *
 * @param digit     The digit character to display, or empty string if unfilled.
 * @param isFocused Whether this box is the next to receive input.
 * @param hasError  Whether the PIN entry is in an error state.
 * @param modifier  Layout modifier — typically [Modifier.weight] for equal sizing.
 */
@Composable
private fun DigitBox(
    digit: String,
    isFocused: Boolean,
    hasError: Boolean,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(BeamCorner.md)
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .width(48.dp)
            .height(56.dp)
            .border(
                width = if (isFocused) 2.dp else 1.dp,
                color = when {
                    hasError -> BeamPalette.danger
                    isFocused -> BeamPalette.accent
                    else -> BeamPalette.borderSubtle
                },
                shape = shape,
            )
            .background(
                color = BeamPalette.bg1,
                shape = shape,
            ),
    ) {
        if (digit.isNotEmpty()) {
            Text(
                text = digit,
                style = BeamTextStyle.xlMono,
                color = BeamPalette.textHi,
                textAlign = TextAlign.Center,
            )
        }
    }
}
