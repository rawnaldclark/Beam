package com.zaptransfer.android.ui.pairing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private const val PIN_LENGTH = 8

/**
 * 8-digit PIN fallback entry screen — Phase D, Task 12.
 *
 * Layout:
 *  - Title + subtitle explaining PIN-based pairing
 *  - 8 individual [OutlinedTextField] boxes arranged in a row (4 + 4 with a separator)
 *  - Numeric keyboard forced via [KeyboardType.NumberPassword]
 *  - Auto-focus on digit box 0 on first composition
 *  - Auto-advance focus: after each character entry the focus moves to the next box
 *  - Auto-submit: on the 8th digit, calls [viewModel.onPinSubmitted]
 *  - Backspace handling: clears the current box and moves focus back
 *  - Error message displayed below the digit boxes
 *
 * Security note: [KeyboardType.NumberPassword] suppresses the keyboard's
 * suggestion / auto-correct bar to reduce the risk of PIN leakage via keyboard
 * personalisation data.
 *
 * @param viewModel          Shared [PairingViewModel]; provides [PairingUiState.PinEntry].
 * @param onNavigateToVerify Called after PIN is submitted and key exchange succeeds
 *                           (ViewModel transitions to [PairingUiState.Verifying]).
 * @param onBack             Pop back to the QR scanner.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinEntryScreen(
    viewModel: PairingViewModel,
    onNavigateToVerify: () -> Unit,
    onBack: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()

    // Navigate when ViewModel transitions to Verifying
    LaunchedEffect(uiState) {
        if (uiState is PairingUiState.Verifying) {
            onNavigateToVerify()
        }
    }

    val errorMessage: String? = (uiState as? PairingUiState.PinEntry)?.errorMessage

    // Per-digit state: each box holds at most one character
    val digits = remember { Array(PIN_LENGTH) { mutableStateOf("") } }
    val focusRequesters = remember { Array(PIN_LENGTH) { FocusRequester() } }

    // Auto-focus the first digit box when the screen appears
    LaunchedEffect(Unit) {
        focusRequesters[0].requestFocus()
    }

    /**
     * Called when a digit box at [index] receives a character.
     * Accepts only the first character if [value] is longer (e.g., paste).
     * Advances focus to the next box and auto-submits on the 8th digit.
     */
    fun onDigitChanged(index: Int, value: String) {
        // Accept only the last character if the system inserts more than one
        val digit = value.lastOrNull()?.toString() ?: ""
        if (digit.isNotEmpty() && !digit.first().isDigit()) return  // reject non-numeric

        digits[index].value = digit

        if (digit.isNotEmpty()) {
            if (index < PIN_LENGTH - 1) {
                // Advance to next box
                focusRequesters[index + 1].requestFocus()
            } else {
                // Last digit entered — compile and auto-submit
                val pin = digits.joinToString("") { it.value }
                if (pin.length == PIN_LENGTH) {
                    viewModel.onPinSubmitted(pin)
                }
            }
        }
    }

    /**
     * Called when backspace is pressed in a digit box.
     * If the current box is empty, clears the previous box and moves focus back.
     */
    fun onBackspace(index: Int) {
        if (digits[index].value.isNotEmpty()) {
            digits[index].value = ""
        } else if (index > 0) {
            digits[index - 1].value = ""
            focusRequesters[index - 1].requestFocus()
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
                text = "Find the PIN displayed on the paired device's screen.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(40.dp))

            // ── 8 digit boxes (4 + separator + 4) ────────────────────────────
            Row(
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                // First group of 4 digits
                repeat(4) { index ->
                    DigitBox(
                        value = digits[index].value,
                        focusRequester = focusRequesters[index],
                        isError = errorMessage != null,
                        onValueChange = { onDigitChanged(index, it) },
                        onBackspace = { onBackspace(index) },
                    )
                    if (index < 3) {
                        Spacer(modifier = Modifier.width(6.dp))
                    }
                }

                // Visual separator dash
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = "—",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.width(12.dp))

                // Second group of 4 digits
                repeat(4) { i ->
                    val index = i + 4
                    DigitBox(
                        value = digits[index].value,
                        focusRequester = focusRequesters[index],
                        isError = errorMessage != null,
                        isLast = index == PIN_LENGTH - 1,
                        onValueChange = { onDigitChanged(index, it) },
                        onBackspace = { onBackspace(index) },
                    )
                    if (i < 3) {
                        Spacer(modifier = Modifier.width(6.dp))
                    }
                }
            }

            // ── Error message ─────────────────────────────────────────────────
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

// ── Single digit input box ────────────────────────────────────────────────────

/**
 * A single [OutlinedTextField] configured for one numeric digit.
 *
 * Design decisions:
 *  - Width fixed at 40dp so 8 boxes fit on a 360dp phone with a separator.
 *  - [KeyboardType.NumberPassword] suppresses the suggestion bar.
 *  - [ImeAction.Next] for boxes 1–7 moves IME focus; box 8 uses [ImeAction.Done].
 *  - The field's `onValueChange` rejects non-numeric input and limits to 1 character.
 *
 * @param value          Current digit value ("" or a single digit character).
 * @param focusRequester Used by the parent to programmatically advance focus.
 * @param isError        If true, the box renders in error colour (red outline).
 * @param onValueChange  Called with the new single-character string value.
 * @param onBackspace    Called when the backspace key is detected while the field is empty.
 */
@Composable
private fun DigitBox(
    value: String,
    focusRequester: FocusRequester,
    isError: Boolean,
    isLast: Boolean = false,
    onValueChange: (String) -> Unit,
    onBackspace: () -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = { newVal ->
            when {
                newVal.isEmpty() -> onBackspace()
                else -> {
                    val filtered = newVal.filter { it.isDigit() }
                    if (filtered.isNotEmpty()) {
                        onValueChange(filtered.last().toString())
                    }
                }
            }
        },
        modifier = Modifier
            .size(width = 44.dp, height = 58.dp)
            .focusRequester(focusRequester),
        textStyle = TextStyle(
            fontSize = 22.sp,
            textAlign = TextAlign.Center,
        ),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.NumberPassword,
            imeAction = if (isLast) ImeAction.Done else ImeAction.Next,
        ),
        singleLine = true,
        isError = isError,
    )
}
