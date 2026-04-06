package com.zaptransfer.android.ui.pairing

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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

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
                title = { Text("Enter Pairing PIN") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "Enter the 8-digit PIN",
                style = MaterialTheme.typography.headlineSmall,
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Find the PIN displayed on the other device.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(40.dp))

            // Single hidden BasicTextField that captures all keyboard input.
            // The visual boxes below are decorative — they read from pinText state.
            BasicTextField(
                value = pinText,
                onValueChange = { newVal ->
                    // Filter to digits only, cap at PIN_LENGTH
                    val filtered = newVal.filter { it.isDigit() }.take(PIN_LENGTH)
                    pinText = filtered
                },
                modifier = Modifier
                    .focusRequester(focusRequester)
                    // Make the field "invisible" but still focusable
                    .size(1.dp)
                    ,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done,
                ),
                singleLine = true,
            )

            // Visual digit boxes — read-only display of pinText characters
            Row(
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                repeat(PIN_LENGTH) { index ->
                    if (index == 4) {
                        // Separator between groups of 4
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "—",
                            style = MaterialTheme.typography.headlineMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                    }

                    val digit = pinText.getOrNull(index)?.toString() ?: ""
                    val isFocused = index == pinText.length // next digit to enter
                    val hasError = errorMessage != null

                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(width = 48.dp, height = 60.dp)
                            .border(
                                width = if (isFocused) 2.dp else 1.dp,
                                color = when {
                                    hasError -> MaterialTheme.colorScheme.error
                                    isFocused -> MaterialTheme.colorScheme.primary
                                    digit.isNotEmpty() -> MaterialTheme.colorScheme.outline
                                    else -> MaterialTheme.colorScheme.outlineVariant
                                },
                                shape = RoundedCornerShape(12.dp),
                            )
                            .background(
                                color = if (digit.isNotEmpty())
                                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                                else Color.Transparent,
                                shape = RoundedCornerShape(12.dp),
                            ),
                    ) {
                        Text(
                            text = digit,
                            style = TextStyle(
                                fontSize = 28.sp,
                                textAlign = TextAlign.Center,
                                color = MaterialTheme.colorScheme.onSurface,
                            ),
                        )
                    }

                    if (index < PIN_LENGTH - 1 && index != 3) {
                        Spacer(modifier = Modifier.width(6.dp))
                    }
                }
            }

            // Error message
            if (errorMessage != null) {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "The PIN expires after 60 seconds.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
