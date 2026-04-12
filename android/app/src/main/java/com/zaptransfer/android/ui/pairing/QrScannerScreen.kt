package com.zaptransfer.android.ui.pairing

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import android.view.ViewGroup
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.zaptransfer.android.ui.theme.BeamCorner
import com.zaptransfer.android.ui.theme.BeamIcons
import com.zaptransfer.android.ui.theme.BeamPalette
import com.zaptransfer.android.ui.theme.BeamSpace
import com.zaptransfer.android.ui.theme.BeamTextStyle
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

private const val TAG = "QrScannerScreen"

/**
 * QR code scanning screen — Phase D, Task 11.
 *
 * Responsibilities:
 *  1. Request [Manifest.permission.CAMERA] at runtime with a rationale dialog.
 *  2. Start a CameraX preview bound to the current [LocalLifecycleOwner].
 *  3. Run ML Kit [BarcodeScanning] on every camera frame.
 *  4. On the first FORMAT_QR_CODE decode, call [viewModel.onQrDecoded].
 *  5. React to [PairingUiState] transitions and navigate accordingly.
 *
 * The viewfinder overlay draws a dark scrim with a transparent rounded-rectangle
 * cut-out to visually guide the user to align the QR code.
 *
 * Permission strategy: uses [ActivityResultContracts.RequestPermission] (Jetpack
 * Activity 1.2+) — no accompanist dependency required.
 *
 * Navigation triggers:
 *  - QR decoded + key exchange complete → [PairingUiState.Verifying] → [onNavigateToVerify]
 *  - "Can't scan? Enter PIN" button → [onNavigateToPin]
 *  - Back arrow → [onBack]
 *
 * @param viewModel          Shared [PairingViewModel].
 * @param onNavigateToVerify Callback to push the SAS verification screen.
 * @param onNavigateToPin    Callback to push the PIN entry screen.
 * @param onBack             Pop back to the previous screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScannerScreen(
    viewModel: PairingViewModel,
    onNavigateToVerify: () -> Unit,
    onNavigateToPin: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val uiState by viewModel.uiState.collectAsState()

    // Navigate when ViewModel transitions to Verifying state
    LaunchedEffect(uiState) {
        if (uiState is PairingUiState.Verifying) {
            onNavigateToVerify()
        }
    }

    // ── Camera permission state ───────────────────────────────────────────────
    var cameraPermissionGranted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED
        )
    }
    var permissionDeniedPermanently by remember { mutableStateOf(false) }
    var showRationale by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        when {
            granted -> {
                cameraPermissionGranted = true
                showRationale = false
            }
            else -> {
                // On Android 11+ the system sets shouldShowRationale=false after two denials,
                // indicating a permanent denial. We approximate this with a flag.
                permissionDeniedPermanently = true
            }
        }
    }

    // Launch permission request on first composition if not yet granted
    LaunchedEffect(Unit) {
        if (!cameraPermissionGranted) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Scan QR Code",
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
        containerColor = Color.Black,
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
        ) {
            when {
                cameraPermissionGranted -> {
                    // ── Live camera viewfinder ────────────────────────────────
                    CameraPreviewWithScanner(
                        onQrDecoded = { rawJson -> viewModel.onQrDecoded(rawJson) },
                        modifier = Modifier.fillMaxSize(),
                    )
                    // Semi-transparent scrim + rounded-rectangle cut-out
                    ViewfinderOverlay(modifier = Modifier.fillMaxSize())

                    // Error banner when decode + JSON parse fails
                    if (uiState is PairingUiState.Error) {
                        val errorMsg = (uiState as PairingUiState.Error).message
                        Box(
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .padding(horizontal = BeamSpace.s6, vertical = 120.dp)
                                .clip(RoundedCornerShape(BeamCorner.lg))
                                .background(BeamPalette.bg1)
                                .border(
                                    width = 1.dp,
                                    color = BeamPalette.borderSubtle,
                                    shape = RoundedCornerShape(BeamCorner.lg),
                                )
                                .padding(horizontal = BeamSpace.s4, vertical = BeamSpace.s3),
                        ) {
                            Text(
                                text = errorMsg,
                                color = BeamPalette.danger,
                                style = BeamTextStyle.baseRegular,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                }

                showRationale -> {
                    // ── Permission rationale ──────────────────────────────────
                    CameraPermissionRationale(
                        onRequestPermission = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(BeamSpace.s6),
                    )
                }

                permissionDeniedPermanently -> {
                    // ── Permanent denial — direct user to Settings ────────────
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(BeamSpace.s6),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text(
                            text = "Camera access was denied.",
                            style = BeamTextStyle.lgSemibold,
                            color = BeamPalette.textHi,
                        )
                        Spacer(modifier = Modifier.height(BeamSpace.s3))
                        Text(
                            text = "Enable camera access in Settings, or use the PIN option below.",
                            style = BeamTextStyle.baseRegular,
                            color = BeamPalette.textMid,
                            textAlign = TextAlign.Center,
                        )
                    }
                }

                else -> {
                    // Waiting for the system dialog — show a brief placeholder
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "Requesting camera access…",
                            color = BeamPalette.textMid,
                            style = BeamTextStyle.baseRegular,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
            }

            // "Can't scan? Enter PIN" — always visible
            TextButton(
                onClick = {
                    viewModel.onPinEntryRequested()
                    onNavigateToPin()
                },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 48.dp),
            ) {
                Text(
                    text = "Can't scan? Enter PIN",
                    color = BeamPalette.textMid,
                    style = BeamTextStyle.smRegular,
                )
            }
        }
    }
}

// ── Camera preview + ML Kit ───────────────────────────────────────────────────

/**
 * CameraX [PreviewView] bound to a single-thread [ImageAnalysis] use case that
 * runs ML Kit barcode scanning on every frame.
 *
 * After the first successful QR decode [onQrDecoded] is called once; subsequent
 * frames are dropped until the screen recomposes (prevents duplicate callbacks).
 *
 * @param onQrDecoded Main-thread callback with the decoded QR string value.
 * @param modifier    Applied to the [AndroidView] container.
 */
@Composable
private fun CameraPreviewWithScanner(
    onQrDecoded: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    // Single-thread executor for image analysis — avoids main thread overhead
    val analysisExecutor: ExecutorService = remember { Executors.newSingleThreadExecutor() }

    // Prevent multiple decode callbacks per scan session
    var decoded by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        onDispose { analysisExecutor.shutdown() }
    }

    AndroidView(
        factory = { ctx ->
            PreviewView(ctx).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT,
                )
                scaleType = PreviewView.ScaleType.FILL_CENTER
            }
        },
        modifier = modifier,
        update = { previewView ->
            val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
            cameraProviderFuture.addListener(
                {
                    val cameraProvider = cameraProviderFuture.get()

                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }

                    val barcodeScanner = BarcodeScanning.getClient()

                    val imageAnalysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                        .also { analysis ->
                            analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                                if (decoded) {
                                    imageProxy.close()
                                    return@setAnalyzer
                                }
                                val mediaImage = imageProxy.image
                                if (mediaImage != null) {
                                    val image = InputImage.fromMediaImage(
                                        mediaImage,
                                        imageProxy.imageInfo.rotationDegrees,
                                    )
                                    barcodeScanner.process(image)
                                        .addOnSuccessListener { barcodes ->
                                            barcodes
                                                .firstOrNull { it.format == Barcode.FORMAT_QR_CODE }
                                                ?.rawValue
                                                ?.let { raw ->
                                                    if (!decoded) {
                                                        decoded = true
                                                        Log.d(TAG, "QR decoded")
                                                        onQrDecoded(raw)
                                                    }
                                                }
                                        }
                                        .addOnFailureListener { e ->
                                            Log.w(TAG, "Barcode scan error: ${e.message}")
                                        }
                                        .addOnCompleteListener { imageProxy.close() }
                                } else {
                                    imageProxy.close()
                                }
                            }
                        }

                    try {
                        cameraProvider.unbindAll()
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            imageAnalysis,
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Camera bind failed: ${e.message}", e)
                    }
                },
                ContextCompat.getMainExecutor(context),
            )
        },
    )
}

// ── Viewfinder overlay ────────────────────────────────────────────────────────

/**
 * Full-screen Canvas overlay that draws a semi-transparent scrim with a
 * transparent rounded-rectangle window cut-out in the centre.
 *
 * Uses [BlendMode.Clear] to "erase" the scrim pixels inside the viewfinder frame,
 * creating a true transparency effect that reveals the live camera feed below.
 *
 * @param modifier Applied to the Canvas (should be [Modifier.fillMaxSize]).
 */
@Composable
private fun ViewfinderOverlay(modifier: Modifier = Modifier) {
    val cornerRadiusDp = BeamCorner.lg
    Canvas(modifier = modifier) {
        val scrimColor = Color.Black.copy(alpha = 0.60f)
        val windowSize = minOf(size.width, size.height) * 0.70f
        val windowLeft = (size.width - windowSize) / 2f
        val windowTop = (size.height - windowSize) / 2f
        val cornerRadius = cornerRadiusDp.toPx()

        // Full-screen dark scrim
        drawRect(color = scrimColor)

        // Transparent cut-out via BlendMode.Clear
        drawRoundRect(
            color = Color.Transparent,
            topLeft = Offset(windowLeft, windowTop),
            size = Size(windowSize, windowSize),
            cornerRadius = CornerRadius(cornerRadius),
            blendMode = BlendMode.Clear,
        )

        // White outline border around the cut-out
        drawRoundRect(
            color = Color.White,
            topLeft = Offset(windowLeft, windowTop),
            size = Size(windowSize, windowSize),
            cornerRadius = CornerRadius(cornerRadius),
            style = Stroke(width = 3.dp.toPx()),
        )
    }
}

// ── Permission rationale ──────────────────────────────────────────────────────

/**
 * Rationale UI shown before re-requesting the camera permission.
 *
 * @param onRequestPermission Callback to re-launch the system permission dialog.
 * @param modifier            Layout modifier.
 */
@Composable
private fun CameraPermissionRationale(
    onRequestPermission: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "Camera Access Required",
            style = BeamTextStyle.lgSemibold,
            color = BeamPalette.textHi,
        )
        Spacer(modifier = Modifier.height(BeamSpace.s4))
        Text(
            text = "ZapTransfer uses the camera to scan the QR code on your computer. " +
                "Your camera feed is never stored or transmitted.",
            style = BeamTextStyle.baseRegular,
            color = BeamPalette.textMid,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(BeamSpace.s7))
        Button(
            onClick = onRequestPermission,
            colors = ButtonDefaults.buttonColors(
                containerColor = BeamPalette.accent,
                contentColor = Color.White,
            ),
            shape = RoundedCornerShape(BeamCorner.md),
        ) {
            Text(
                text = "Grant Camera Access",
                style = BeamTextStyle.baseMedium,
            )
        }
    }
}
