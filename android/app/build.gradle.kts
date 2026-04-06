// app/build.gradle.kts
// Full dependency manifest for the Beam Android application.
//
// Key decisions:
//  • Kotlin 2.0 + kotlin("plugin.compose") replaces the old composeOptions block.
//  • KSP (not kapt) for all annotation processors — faster incremental compilation.
//  • Compose BOM pins all compose-* artifact versions from a single source of truth.
//  • lazysodium-android + JNA both use @aar classifier (Android-only native AARs).
//  • stream-webrtc-android bundles libwebrtc.so (~8 MB per ABI) — ABI splits in release.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    // Kotlin 2.0 Compose compiler plugin — supersedes composeOptions.kotlinCompilerExtensionVersion
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.zaptransfer.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.zaptransfer.android"
        minSdk = 26          // Android 8.0 — required for EncryptedSharedPreferences + modern crypto APIs
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Room schema export — kept in source control for migration auditing
        ksp {
            arg("room.schemaLocation", "$projectDir/schemas")
            arg("room.incremental", "true")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    // ABI splits reduce download size from ~50 MB to ~17 MB per architecture
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = false
        }
    }

    buildFeatures {
        compose = true      // Enables Jetpack Compose
        buildConfig = true  // Needed for BuildConfig.DEBUG guards
    }

    // Kotlin 2.0: composeOptions block is NOT used; the kotlin("plugin.compose") plugin
    // handles the Compose compiler automatically. composeOptions {} would cause a build error.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.foundation.ExperimentalFoundationApi",
            "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi"
        )
    }

    packaging {
        resources {
            // JNA ships duplicate license files across its AARs — exclude to avoid merge conflicts
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/DEPENDENCIES"
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }
}

dependencies {
    // ─── Compose BOM ──────────────────────────────────────────────────────────
    // Single version string pins all androidx.compose.* artifacts consistently.
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    // Core Compose UI toolkit
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // Material 3 design system
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // ─── Activity + Lifecycle ──────────────────────────────────────────────────
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-service:2.7.0")  // LifecycleService for foreground service

    // ─── Navigation ───────────────────────────────────────────────────────────
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // ─── Hilt (Dependency Injection) ──────────────────────────────────────────
    implementation("com.google.dagger:hilt-android:2.51")
    ksp("com.google.dagger:hilt-compiler:2.51")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")
    // Hilt ViewModel integration (brings @HiltViewModel support)
    ksp("androidx.hilt:hilt-compiler:1.2.0")

    // ─── Room (Local Database) ────────────────────────────────────────────────
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")   // Coroutine + Flow extensions
    ksp("androidx.room:room-compiler:2.6.1")

    // ─── Crypto: lazysodium-android + JNA ────────────────────────────────────
    // lazysodium wraps libsodium with identical wire format to libsodium.js (Chrome extension).
    // Both @aar classifiers required — these are Android-specific native AARs, not JVM JARs.
    implementation("com.goterl:lazysodium-android:5.1.0@aar")
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    // ─── WebRTC ───────────────────────────────────────────────────────────────
    // stream-webrtc-android: pre-built libwebrtc.so + Kotlin API, ~8 MB/ABI
    implementation("io.getstream:stream-webrtc-android:1.1.1")

    // ─── Networking ───────────────────────────────────────────────────────────
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")  // Debug WS logging

    // ─── ML Kit Barcode Scanning ──────────────────────────────────────────────
    // Unbundled variant — downloads model on first use. Use "barcode-scanning" (not "-bundled")
    // to keep APK size small (~2 MB). Model downloads over Play Services.
    implementation("com.google.mlkit:barcode-scanning:17.2.0")

    // ─── CameraX ─────────────────────────────────────────────────────────────
    implementation("androidx.camera:camera-camera2:1.3.1")
    implementation("androidx.camera:camera-lifecycle:1.3.1")
    implementation("androidx.camera:camera-view:1.3.1")

    // ─── Security ─────────────────────────────────────────────────────────────
    // EncryptedSharedPreferences — stores X25519 private key at rest
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // ─── DataStore ────────────────────────────────────────────────────────────
    // Typed key-value store for user preferences (replaces SharedPreferences)
    implementation("androidx.datastore:datastore-preferences:1.0.0")

    // ─── Coroutines ───────────────────────────────────────────────────────────
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")

    // ─── DocumentFile (SAF custom save location in TransferCompleteViewModel) ──
    implementation("androidx.documentfile:documentfile:1.0.1")

    // ─── Core KTX ─────────────────────────────────────────────────────────────
    implementation("androidx.core:core-ktx:1.12.0")

    // ─── Testing ──────────────────────────────────────────────────────────────
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.0")
    testImplementation("io.mockk:mockk:1.13.9")
    testImplementation("androidx.test:core-ktx:1.5.0")
    testImplementation("androidx.room:room-testing:2.6.1")  // In-memory Room for unit tests

    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
