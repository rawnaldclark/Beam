package com.zaptransfer.android.ui.transfer

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CellTower
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.service.TransferProgress
import com.zaptransfer.android.ui.theme.BeamTheme

/**
 * Screen displayed while a file transfer is in progress.
 *
 * Shows:
 *  - File name and human-readable size
 *  - [LinearProgressIndicator] with percentage label
 *  - Current transfer speed in MB/s and estimated time remaining
 *  - Connection type chip (Local WiFi / Relay / Cellular)
 *  - Cancel button that stops the transfer
 *
 * The screen automatically shows a loading state if the [transferId] has not yet
 * appeared in [TransferProgressViewModel.progress].
 *
 * @param transferId  UUID of the active transfer (from nav argument).
 * @param onBack      Called when the back button is tapped (before transfer completes).
 * @param onCancel    Called when the user confirms cancellation.
 * @param onComplete  Called when the progress state transitions to COMPLETE —
 *                    the nav graph replaces this screen with [TransferCompleteSheet].
 * @param viewModel   Injected [TransferProgressViewModel].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransferProgressScreen(
    transferId: String,
    onBack: () -> Unit,
    onCancel: (String) -> Unit,
    onComplete: (String) -> Unit,
    viewModel: TransferProgressViewModel = hiltViewModel(),
) {
    val progressMap by viewModel.progress.collectAsState()
    val connectionLabel by viewModel.connectionLabel.collectAsState()
    val snapshot = progressMap[transferId]

    // Auto-navigate to complete sheet when terminal state is reached
    if (snapshot?.state == "COMPLETE") {
        onComplete(transferId)
    }

    TransferProgressContent(
        snapshot = snapshot,
        transferId = transferId,
        connectionLabel = connectionLabel,
        onBack = onBack,
        onCancel = { onCancel(transferId) },
    )
}

/**
 * Stateless content for [TransferProgressScreen].
 *
 * Separated for testability and pure Compose previews.
 *
 * @param snapshot         Current [TransferProgress] for this transfer; null = loading.
 * @param transferId       Transfer UUID displayed in the loading state.
 * @param connectionLabel  Human-readable connection type: "Local WiFi", "Relay", or "Cellular".
 * @param onBack           Back navigation callback.
 * @param onCancel         Cancel the transfer callback.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TransferProgressContent(
    snapshot: TransferProgress?,
    transferId: String,
    connectionLabel: String,
    onBack: () -> Unit,
    onCancel: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Transfer") },
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
        if (snapshot == null) {
            // Loading state — transfer ID just appeared in the nav graph but
            // hasn't published a progress event yet
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        val progressFraction = if (snapshot.totalBytes > 0) {
            (snapshot.transferredBytes.toFloat() / snapshot.totalBytes).coerceIn(0f, 1f)
        } else 0f
        val progressPercent = (progressFraction * 100).toInt()

        val speedMBs = snapshot.speedBytesPerSec / 1_048_576f
        val remainingBytes = snapshot.totalBytes - snapshot.transferredBytes
        val etaSeconds = if (snapshot.speedBytesPerSec > 0) {
            remainingBytes / snapshot.speedBytesPerSec
        } else 0L

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // ── File name and size ────────────────────────────────────────────
            Text(
                text = snapshot.fileName,
                style = MaterialTheme.typography.headlineSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = formatBytes(snapshot.totalBytes),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(8.dp))

            // ── Progress bar + percentage ─────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                LinearProgressIndicator(
                    progress = { progressFraction },
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = "$progressPercent%",
                    style = MaterialTheme.typography.labelLarge,
                )
            }

            // ── Speed and ETA ─────────────────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = if (speedMBs > 0) "%.1f MB/s".format(speedMBs) else "Calculating…",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = if (etaSeconds > 0) formatEta(etaSeconds) else "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // ── Connection type chip ──────────────────────────────────────────
            val connectionIcon = when {
                connectionLabel.contains("WiFi", ignoreCase = true) -> Icons.Default.Wifi
                else -> Icons.Default.CellTower
            }
            SuggestionChip(
                onClick = { /* informational — no action */ },
                label = { Text(connectionLabel) },
                icon = {
                    Icon(
                        imageVector = connectionIcon,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                },
            )

            Spacer(modifier = Modifier.weight(1f))

            // ── Cancel button ─────────────────────────────────────────────────
            Button(
                onClick = onCancel,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                ),
            ) {
                Icon(
                    imageVector = Icons.Default.Cancel,
                    contentDescription = null,
                    modifier = Modifier.padding(end = 8.dp),
                )
                Text("Cancel Transfer")
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/**
 * Converts a byte count to a human-readable string (e.g., "45.3 MB").
 *
 * @param bytes Byte count to format.
 * @return Human-readable string with 1 decimal place.
 */
private fun formatBytes(bytes: Long): String = when {
    bytes >= 1_073_741_824L -> "%.1f GB".format(bytes / 1_073_741_824.0)
    bytes >= 1_048_576L -> "%.1f MB".format(bytes / 1_048_576.0)
    bytes >= 1_024L -> "%.1f KB".format(bytes / 1_024.0)
    else -> "$bytes B"
}

/**
 * Converts a duration in seconds to a human-readable ETA string.
 *
 * @param seconds Remaining seconds.
 * @return String like "2 min 34 s" or "45 s".
 */
private fun formatEta(seconds: Long): String {
    val minutes = seconds / 60
    val secs = seconds % 60
    return if (minutes > 0) "$minutes min $secs s remaining" else "$secs s remaining"
}

// ── Preview ───────────────────────────────────────────────────────────────────

@Preview(showBackground = true, name = "Transfer progress — mid transfer")
@Composable
private fun TransferProgressPreview() {
    BeamTheme {
        TransferProgressContent(
            snapshot = TransferProgress(
                transferId = "abc-123",
                direction = "receive",
                fileName = "project_backup_final_v2.zip",
                totalBytes = 104_857_600L,   // 100 MB
                transferredBytes = 47_185_920L,  // ~45 MB
                speedBytesPerSec = 6_291_456L,   // 6 MB/s
                state = "TRANSFERRING",
            ),
            transferId = "abc-123",
            connectionLabel = "Local WiFi",
            onBack = {},
            onCancel = {},
        )
    }
}
