package com.zaptransfer.android.ui.clipboard

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Patterns
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.TextSnippet
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.zaptransfer.android.data.db.entity.ClipboardEntryEntity
import com.zaptransfer.android.ui.theme.BeamTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private const val MAX_PREVIEW_CHARS = 200

/**
 * Screen displaying the last 20 clipboard items received from paired devices.
 *
 * Each item shows:
 *  - Content preview (truncated to [MAX_PREVIEW_CHARS] characters)
 *  - Source device name and timestamp
 *  - "Copy" icon button — copies the full content to the system clipboard
 *  - "Open in Browser" button — only shown when the content matches [Patterns.WEB_URL]
 *
 * Navigation: [onBack] pops this screen.
 *
 * @param onBack    Called when the user taps the back arrow.
 * @param viewModel Injected [ClipboardHistoryViewModel].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ClipboardHistoryScreen(
    onBack: () -> Unit,
    viewModel: ClipboardHistoryViewModel = hiltViewModel(),
) {
    val items by viewModel.items.collectAsState()

    ClipboardHistoryContent(
        items = items,
        onBack = onBack,
        deviceNameForId = { deviceId -> viewModel.deviceNameFor(deviceId) },
    )
}

/**
 * Stateless content layer for [ClipboardHistoryScreen].
 *
 * @param items            List of clipboard entries (up to 20), newest first.
 * @param onBack           Back navigation callback.
 * @param deviceNameForId  Lookup function: device ID → human-readable device name.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ClipboardHistoryContent(
    items: List<ClipboardEntryEntity>,
    onBack: () -> Unit,
    deviceNameForId: (String) -> String,
) {
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Clipboard History") },
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
        if (items.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center,
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.TextSnippet,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "No clipboard history yet",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "Copied text and links from paired devices will appear here",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item { Spacer(modifier = Modifier.height(8.dp)) }

            items(
                items = items,
                key = { it.entryId },
            ) { entry ->
                ClipboardItemCard(
                    entry = entry,
                    deviceName = deviceNameForId(entry.deviceId),
                    onCopy = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                            as ClipboardManager
                        val clip = ClipData.newPlainText("Beam clipboard", entry.content)
                        clipboard.setPrimaryClip(clip)
                        Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    onOpenInBrowser = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(entry.content))
                        runCatching { context.startActivity(intent) }
                    },
                )
            }

            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }
}

/**
 * Card displaying a single clipboard history item.
 *
 * URL detection uses [Patterns.WEB_URL] (the same matcher used in Android's
 * Linkify implementation). Only the first match is used — if the content starts
 * with a valid URL scheme, "Open in Browser" is shown.
 *
 * @param entry          The [ClipboardEntryEntity] to display.
 * @param deviceName     Human-readable name of the source device.
 * @param onCopy         Called when the user taps the copy icon.
 * @param onOpenInBrowser Called when the user taps "Open in Browser" (URL items only).
 */
@Composable
private fun ClipboardItemCard(
    entry: ClipboardEntryEntity,
    deviceName: String,
    onCopy: () -> Unit,
    onOpenInBrowser: () -> Unit,
) {
    // Determine if the content is a URL using Android's built-in pattern matcher.
    // isUrl comes from the DB (sender-set hint), but we re-verify client-side
    // as a defence-in-depth measure.
    val isUrl = entry.isUrl ||
        Patterns.WEB_URL.matcher(entry.content.trim()).matches()

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            // ── Content preview ───────────────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
            ) {
                Icon(
                    imageVector = if (isUrl) Icons.Default.Link else Icons.Default.TextSnippet,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(end = 8.dp, top = 2.dp),
                )
                Text(
                    text = entry.content.take(MAX_PREVIEW_CHARS).let {
                        if (entry.content.length > MAX_PREVIEW_CHARS) "$it…" else it
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                    maxLines = 5,
                    overflow = TextOverflow.Ellipsis,
                )
                // Copy button
                IconButton(onClick = onCopy) {
                    Icon(
                        imageVector = Icons.Default.ContentCopy,
                        contentDescription = "Copy to clipboard",
                    )
                }
            }

            // ── Source device + timestamp ─────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = deviceName,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = formatTimestamp(entry.receivedAt),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // ── "Open in Browser" button — URLs only ──────────────────────────
            if (isUrl) {
                OutlinedButton(
                    onClick = onOpenInBrowser,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(
                        imageVector = Icons.Default.Link,
                        contentDescription = null,
                        modifier = Modifier.padding(end = 4.dp),
                    )
                    Text("Open in Browser")
                }
            }
        }
    }
}

/**
 * Formats a Unix epoch millisecond timestamp into a readable string.
 *
 * Uses the device's locale for number formatting. Shows date+time for items
 * received more than 24 hours ago, or just the time for items from today.
 *
 * @param epochMs Unix epoch milliseconds.
 * @return Human-readable timestamp string.
 */
private fun formatTimestamp(epochMs: Long): String {
    val now = System.currentTimeMillis()
    val date = Date(epochMs)
    return if (now - epochMs < 24L * 60L * 60L * 1_000L) {
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
    } else {
        SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(date)
    }
}

// ── Previews ─────────────────────────────────────────────────────────────────

@Preview(showBackground = true, name = "Clipboard history — items")
@Composable
private fun ClipboardHistoryPreview() {
    BeamTheme {
        ClipboardHistoryContent(
            items = listOf(
                ClipboardEntryEntity(
                    entryId = 1,
                    deviceId = "device1",
                    content = "https://www.google.com/search?q=android+development",
                    isUrl = true,
                    receivedAt = System.currentTimeMillis() - 3_600_000,
                ),
                ClipboardEntryEntity(
                    entryId = 2,
                    deviceId = "device2",
                    content = "Don't forget to pick up milk on the way home. " +
                        "Also call the dentist about Thursday's appointment.",
                    isUrl = false,
                    receivedAt = System.currentTimeMillis() - 7_200_000,
                ),
            ),
            onBack = {},
            deviceNameForId = { id -> if (id == "device1") "Alice's MacBook" else "Bob's Phone" },
        )
    }
}

@Preview(showBackground = true, name = "Clipboard history — empty")
@Composable
private fun ClipboardHistoryEmptyPreview() {
    BeamTheme {
        ClipboardHistoryContent(
            items = emptyList(),
            onBack = {},
            deviceNameForId = { "Unknown" },
        )
    }
}
