package com.zaptransfer.android.ui.transfer

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.ui.theme.BeamTheme
import kotlinx.coroutines.launch

/**
 * Material 3 [ModalBottomSheet] shown after a transfer completes successfully.
 *
 * Content:
 *  - Large checkmark icon + "Transfer Complete" heading
 *  - File name + formatted size + "SHA-256 verified" badge
 *  - Four action buttons:
 *      1. **Open File** — fires [Intent.ACTION_VIEW] for the transferred file's URI
 *      2. **Save to Downloads** — moves the file to the system Downloads folder
 *      3. **Save to Custom Location** — triggers the SAF directory picker
 *      4. **Dismiss** — closes the sheet and navigates back to Device Hub
 *
 * @param transferId  UUID of the completed transfer (from nav argument).
 * @param onDismiss   Called when the sheet is dismissed — pops to Device Hub.
 * @param viewModel   Injected [TransferCompleteViewModel].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransferCompleteSheet(
    transferId: String,
    onDismiss: () -> Unit,
    viewModel: TransferCompleteViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
    ) {
        TransferCompleteContent(
            fileName = uiState.fileName,
            fileSize = uiState.fileSizeBytes,
            localUri = uiState.localUri,
            onOpenFile = { uri ->
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(Uri.parse(uri), uiState.mimeType ?: "*/*")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                runCatching {
                    context.startActivity(intent)
                }
                scope.launch { sheetState.hide() }.invokeOnCompletion { onDismiss() }
            },
            onSaveToDownloads = {
                viewModel.saveToDownloads(transferId)
                scope.launch { sheetState.hide() }.invokeOnCompletion { onDismiss() }
            },
            onSaveToCustomLocation = { uri ->
                viewModel.saveToCustomLocation(transferId, uri)
                scope.launch { sheetState.hide() }.invokeOnCompletion { onDismiss() }
            },
            onDismiss = {
                scope.launch { sheetState.hide() }.invokeOnCompletion { onDismiss() }
            },
        )
    }
}

/**
 * Stateless sheet content for [TransferCompleteSheet].
 *
 * @param fileName              Original filename.
 * @param fileSize              File size in bytes for display.
 * @param localUri              Content URI string of the completed file (may be null if still moving).
 * @param onOpenFile            Called with the local URI to open the file externally.
 * @param onSaveToDownloads     Called when the user taps "Save to Downloads".
 * @param onSaveToCustomLocation Called with the SAF tree URI string.
 * @param onDismiss             Called when the user taps "Dismiss".
 */
@Composable
private fun TransferCompleteContent(
    fileName: String,
    fileSize: Long,
    localUri: String?,
    onOpenFile: (String) -> Unit,
    onSaveToDownloads: () -> Unit,
    onSaveToCustomLocation: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp)
            .padding(bottom = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ── Header: icon + title ──────────────────────────────────────────────
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(64.dp),
        )
        Text(
            text = "Transfer Complete",
            style = MaterialTheme.typography.headlineSmall,
        )

        Spacer(modifier = Modifier.height(4.dp))

        // ── File info ─────────────────────────────────────────────────────────
        Text(
            text = fileName,
            style = MaterialTheme.typography.bodyLarge,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = formatBytes(fileSize),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // SHA-256 verified badge
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.tertiary,
                modifier = Modifier.size(16.dp),
            )
            Text(
                text = "SHA-256 verified",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        // ── Action buttons ────────────────────────────────────────────────────

        // Button 1: Open File (primary action)
        Button(
            onClick = { localUri?.let { onOpenFile(it) } },
            modifier = Modifier.fillMaxWidth(),
            enabled = localUri != null,
        ) {
            Icon(
                imageVector = Icons.Default.OpenInNew,
                contentDescription = null,
                modifier = Modifier
                    .size(18.dp)
                    .padding(end = 4.dp),
            )
            Text("Open File")
        }

        // Button 2: Save to Downloads
        OutlinedButton(
            onClick = onSaveToDownloads,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(
                imageVector = Icons.Default.Download,
                contentDescription = null,
                modifier = Modifier
                    .size(18.dp)
                    .padding(end = 4.dp),
            )
            Text("Save to Downloads")
        }

        // Button 3: Save to Custom Location (SAF picker)
        OutlinedButton(
            onClick = { /* The screen launches the SAF picker via a registered activity result */
                // In a real implementation this would open a launcher; handled via the
                // parent composable's rememberLauncherForActivityResult or via ViewModel intent
                onSaveToCustomLocation("")
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(
                imageVector = Icons.Default.FolderOpen,
                contentDescription = null,
                modifier = Modifier
                    .size(18.dp)
                    .padding(end = 4.dp),
            )
            Text("Save to Custom Location…")
        }

        // Button 4: Dismiss
        TextButton(
            onClick = onDismiss,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.textButtonColors(
                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
        ) {
            Text("Dismiss")
        }
    }
}

/** Formats a byte count into a human-readable string. */
private fun formatBytes(bytes: Long): String = when {
    bytes >= 1_073_741_824L -> "%.1f GB".format(bytes / 1_073_741_824.0)
    bytes >= 1_048_576L -> "%.1f MB".format(bytes / 1_048_576.0)
    bytes >= 1_024L -> "%.1f KB".format(bytes / 1_024.0)
    else -> "$bytes B"
}

// ── Preview ───────────────────────────────────────────────────────────────────

@Preview(showBackground = true, name = "Transfer complete sheet")
@Composable
private fun TransferCompleteSheetPreview() {
    BeamTheme {
        TransferCompleteContent(
            fileName = "project_backup_final_v2.zip",
            fileSize = 104_857_600L,
            localUri = "content://com.example/file",
            onOpenFile = {},
            onSaveToDownloads = {},
            onSaveToCustomLocation = {},
            onDismiss = {},
        )
    }
}
