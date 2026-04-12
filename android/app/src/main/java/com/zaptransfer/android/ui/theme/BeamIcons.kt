package com.zaptransfer.android.ui.theme

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.DesktopWindows
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Laptop
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Tablet
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * Beam icon system — semantic icon map for the entire Android app.
 *
 * Every composable that displays an icon should reference `BeamIcons.*`
 * instead of `Icons.Default.*` or `Icons.Filled.*` directly. This
 * indirection lets us swap the backing implementation (Material → Lucide
 * vector drawables or custom `ImageVector` definitions) in a single file
 * without touching composable code.
 *
 * Current backing: Material Icons Outlined where available (closest to
 * Lucide's 1.5 px stroke, no fill). Filled variants used only where
 * Outlined doesn't exist or looks wrong at 24 dp.
 *
 * Phase 2+ will progressively replace these with native Lucide
 * `ImageVector` paths for full visual parity with the Chrome extension.
 */
object BeamIcons {
    // ── Navigation ──────────────────────────────────────────────────────
    val back: ImageVector = Icons.AutoMirrored.Filled.ArrowBack
    val close: ImageVector = Icons.Filled.Close

    // ── Actions ─────────────────────────────────────────────────────────
    val plus: ImageVector = Icons.Filled.Add
    val settings: ImageVector = Icons.Filled.Settings
    val edit: ImageVector = Icons.Filled.Edit
    val delete: ImageVector = Icons.Filled.Delete
    val copy: ImageVector = Icons.Filled.ContentCopy

    // ── Device types ────────────────────────────────────────────────────
    val laptop: ImageVector = Icons.Outlined.Laptop
    val desktop: ImageVector = Icons.Outlined.DesktopWindows
    val phone: ImageVector = Icons.Outlined.PhoneAndroid
    val tablet: ImageVector = Icons.Outlined.Tablet

    // ── Transfer direction ──────────────────────────────────────────────
    val transferIn: ImageVector = Icons.Filled.ArrowDownward
    val transferOut: ImageVector = Icons.Filled.ArrowUpward

    // ── Status ──────────────────────────────────────────────────────────
    val checkCircle: ImageVector = Icons.Filled.CheckCircle
    val shield: ImageVector = Icons.Outlined.Shield
    val link: ImageVector = Icons.Outlined.Link
    val folderOpen: ImageVector = Icons.Outlined.FolderOpen

    /**
     * Resolve a device-type icon slug (stored on PairedDeviceEntity) to
     * the corresponding ImageVector. Matches the Chrome ICON_MAP keys.
     */
    fun forDeviceType(slug: String?): ImageVector = when (slug) {
        "laptop"  -> laptop
        "desktop" -> desktop
        "phone"   -> phone
        "tablet"  -> tablet
        else      -> laptop // sensible default
    }
}
