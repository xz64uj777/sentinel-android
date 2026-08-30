/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.scanner

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.provider.Settings
import com.sentinel.security.model.SecurityFinding
import com.sentinel.security.model.Severity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

data class DeviceIntegrityResult(
    val developerOptions: Boolean,
    val adbEnabled: Boolean,
    val secureLockScreen: Boolean,
    val securityPatch: String,
    val patchAgeDays: Long?,
    val legacyUnknownSources: Boolean,
    val sentinelDebuggable: Boolean,
    val findings: List<SecurityFinding>
)

object DeviceIntegrityScanner {

    fun scan(context: Context): DeviceIntegrityResult {
        val resolver = context.contentResolver
        val developerOptions = runCatching {
            Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }.getOrDefault(false)
        val adbEnabled = runCatching {
            Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1
        }.getOrDefault(false)
        val secureLock = (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
        val patch = Build.VERSION.SECURITY_PATCH.orEmpty().ifBlank { "Unknown" }
        val patchAge = patchAgeDays(patch)
        val legacyUnknownSources = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            runCatching {
                Settings.Secure.getInt(resolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            }.getOrDefault(false)
        } else {
            false
        }
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

        val findings = mutableListOf<SecurityFinding>()

        if (developerOptions) {
            findings += SecurityFinding(
                title = "Developer options enabled",
                description = "Developer options are enabled on this device.",
                severity = Severity.LOW,
                category = "Device integrity",
                recommendation = "Disable Developer options when you are not actively using them."
            )
        }
        if (adbEnabled) {
            findings += SecurityFinding(
                title = "USB debugging / ADB enabled",
                description = "Android Debug Bridge is enabled.",
                severity = Severity.MEDIUM,
                category = "Device integrity",
                recommendation = "Disable USB debugging when development or troubleshooting is finished."
            )
        }
        if (!secureLock) {
            findings += SecurityFinding(
                title = "No secure screen lock",
                description = "The device does not report a secure PIN, password, or biometric-backed lock screen.",
                severity = Severity.HIGH,
                category = "Device integrity",
                recommendation = "Configure a secure screen lock in Android Settings."
            )
        }
        if (legacyUnknownSources) {
            findings += SecurityFinding(
                title = "Unknown-source installs enabled",
                description = "This older Android version allows installation from non-market sources globally.",
                severity = Severity.MEDIUM,
                category = "App installation",
                recommendation = "Disable installation from unknown sources unless you are actively sideloading a trusted APK."
            )
        }
        if (patchAge != null && patchAge > 365) {
            findings += SecurityFinding(
                title = "Security patch is over a year old",
                description = "Android security patch $patch is approximately $patchAge days old.",
                severity = Severity.HIGH,
                category = "Updates",
                recommendation = "Install the newest system/security update available for the device."
            )
        } else if (patchAge != null && patchAge > 180) {
            findings += SecurityFinding(
                title = "Security patch is aging",
                description = "Android security patch $patch is approximately $patchAge days old.",
                severity = Severity.MEDIUM,
                category = "Updates",
                recommendation = "Check for a newer Android security update."
            )
        }
        if (debuggable) {
            findings += SecurityFinding(
                title = "Sentinel debug build",
                description = "This installed Sentinel APK is debuggable, which is expected for Alpha test builds.",
                severity = Severity.INFO,
                category = "Sentinel build",
                recommendation = "Use a signed non-debuggable release build for public distribution."
            )
        }

        return DeviceIntegrityResult(
            developerOptions = developerOptions,
            adbEnabled = adbEnabled,
            secureLockScreen = secureLock,
            securityPatch = patch,
            patchAgeDays = patchAge,
            legacyUnknownSources = legacyUnknownSources,
            sentinelDebuggable = debuggable,
            findings = findings
        )
    }

    private fun patchAgeDays(patch: String): Long? {
        if (patch == "Unknown") return null
        return runCatching {
            val formatter = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply { isLenient = false }
            val patchDate: Date = formatter.parse(patch) ?: return null
            val diff = System.currentTimeMillis() - patchDate.time
            if (diff < 0) 0 else TimeUnit.MILLISECONDS.toDays(diff)
        }.getOrNull()
    }
}
