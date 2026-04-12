package com.zaptransfer.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ─── Beam v1 Dark Colour Scheme ──────────────────────────────────────────────
//
// Maps Material 3 colorScheme slots to BeamPalette values so every composable
// that reads `MaterialTheme.colorScheme.*` automatically resolves to the Beam
// design system tokens. This is the minimally-invasive migration strategy:
// composable code stays untouched; only the theme mapping changes.
//
// Dark-only in v1 (design decision: no light mode shipped in v1). The light
// color scheme is removed. Dynamic color (Material You) is removed — Beam
// uses a fixed brand palette.
//
// Authoritative source: docs/design/2026-04-11-design-direction-v1.md §6
// Token definitions: android/.../ui/theme/BeamTokens.kt (BeamPalette)
//
private val BeamDarkColorScheme = darkColorScheme(
    // Accent — Signal Cyan #5BE4E4 (was Indigo #6366F1)
    primary = BeamPalette.accent,
    onPrimary = Color.White,
    primaryContainer = BeamPalette.bg2,
    onPrimaryContainer = BeamPalette.textHi,

    // Secondary — mapped to accent for v1 (no distinct secondary hue)
    secondary = BeamPalette.accent,
    onSecondary = Color.White,
    secondaryContainer = BeamPalette.bg2,

    // Canvas and surfaces — stepped depth, zero shadows
    background = BeamPalette.bg0,
    onBackground = BeamPalette.textHi,

    surface = BeamPalette.bg1,
    onSurface = BeamPalette.textHi,
    surfaceVariant = BeamPalette.bg2,
    onSurfaceVariant = BeamPalette.textMid,
    surfaceTint = BeamPalette.accent,

    // Borders
    outline = BeamPalette.borderStrong,
    outlineVariant = BeamPalette.borderSubtle,

    // Error — muted danger
    error = BeamPalette.danger,
    onError = Color.White,
    errorContainer = BeamPalette.danger12,
    onErrorContainer = BeamPalette.textHi,
)

/**
 * Top-level theme composable wrapping the entire Beam application.
 *
 * Dark-only in v1. No dynamic color. No light scheme.
 *
 * @param content The Compose content tree to theme.
 */
@Composable
fun BeamTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = BeamDarkColorScheme,
        typography = BeamTypography,
        content = content,
    )
}
