plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.sentinel.security"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.sentinel.security"
        minSdk = 24
        targetSdk = 35
        versionCode = 3
        versionName = "0.3.0-alpha"

        buildConfigField("String", "COPYRIGHT_OWNER", "\"Kyle T.\"")
        buildConfigField("String", "COPYRIGHT_NOTICE", "\"Copyright © 2026 Kyle T. All Rights Reserved.\"")
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
}
