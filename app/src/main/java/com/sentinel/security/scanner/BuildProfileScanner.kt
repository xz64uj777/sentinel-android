/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.scanner

import android.os.Build
import java.security.MessageDigest

data class BuildProfile(
    val id: String,
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val apiLevel: Int,
    val securityPatch: String
)

object BuildProfileScanner {
    fun read(): BuildProfile {
        val raw = listOf(
            Build.BRAND,
            Build.DEVICE,
            Build.MODEL,
            Build.HARDWARE,
            Build.FINGERPRINT
        ).joinToString("|")

        val digest = MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
            .take(16)

        return BuildProfile(
            id = digest,
            manufacturer = Build.MANUFACTURER.orEmpty().ifBlank { "Unknown" },
            model = Build.MODEL.orEmpty().ifBlank { "Unknown" },
            androidVersion = Build.VERSION.RELEASE.orEmpty().ifBlank { "Unknown" },
            apiLevel = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty().ifBlank { "Unknown" }
        )
    }
}
