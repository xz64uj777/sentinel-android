/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.sentinel.security.model.SecurityFinding
import com.sentinel.security.model.Severity

data class InstalledAppScanResult(
    val appsScanned: Int,
    val userAppsScanned: Int,
    val riskyApps: Int,
    val findings: List<SecurityFinding>
)

object InstalledAppScanner {

    fun scan(context: Context, specialAccess: SpecialAccessResult): InstalledAppScanResult {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val findings = mutableListOf<SecurityFinding>()
        var userApps = 0
        var riskyApps = 0

        for (pkg in packages) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = appInfo.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem) continue
            userApps++

            val requested = pkg.requestedPermissions?.toSet().orEmpty()
            val packageName = pkg.packageName
            val reasons = mutableListOf<String>()
            var risk = 0

            val hasAccessibility = packageName in specialAccess.accessibilityPackages
            val hasNotificationAccess = packageName in specialAccess.notificationListenerPackages
            val hasDeviceAdmin = packageName in specialAccess.deviceAdminPackages
            val overlayRequested = Manifest.permission.SYSTEM_ALERT_WINDOW in requested
            val installerRequested = Manifest.permission.REQUEST_INSTALL_PACKAGES in requested
            val bootRequested = Manifest.permission.RECEIVE_BOOT_COMPLETED in requested
            val usageRequested = Manifest.permission.PACKAGE_USAGE_STATS in requested

            if (hasAccessibility) {
                risk += 20
                reasons += "enabled accessibility service"
            }
            if (hasNotificationAccess) {
                risk += 12
                reasons += "notification access"
            }
            if (hasDeviceAdmin) {
                risk += 30
                reasons += "device administrator"
            }
            if (overlayRequested) {
                risk += 10
                reasons += "requests overlay capability"
            }
            if (installerRequested) {
                risk += 12
                reasons += "can request package installs"
            }
            if (bootRequested) {
                risk += 4
                reasons += "starts after boot"
            }
            if (usageRequested) {
                risk += 6
                reasons += "requests usage access"
            }

            val grantedSensitive = mutableListOf<String>()
            fun granted(permission: String, shortName: String, weight: Int) {
                if (pm.checkPermission(permission, packageName) == PackageManager.PERMISSION_GRANTED) {
                    risk += weight
                    grantedSensitive += shortName
                }
            }

            granted(Manifest.permission.READ_SMS, "read SMS", 16)
            granted(Manifest.permission.RECEIVE_SMS, "receive SMS", 10)
            granted(Manifest.permission.SEND_SMS, "send SMS", 14)
            granted(Manifest.permission.READ_CALL_LOG, "read call log", 12)
            granted(Manifest.permission.WRITE_CALL_LOG, "write call log", 12)
            granted(Manifest.permission.RECORD_AUDIO, "microphone", 8)
            granted(Manifest.permission.CAMERA, "camera", 6)
            granted(Manifest.permission.READ_CONTACTS, "contacts", 6)

            if (grantedSensitive.isNotEmpty()) {
                reasons += "granted: ${grantedSensitive.joinToString()}"
            }

            if (hasAccessibility && overlayRequested) risk += 20
            if (hasAccessibility && grantedSensitive.any { it.contains("SMS") }) risk += 20
            if (hasDeviceAdmin && installerRequested) risk += 15

            val severity = when {
                risk >= 70 -> Severity.CRITICAL
                risk >= 50 -> Severity.HIGH
                risk >= 28 -> Severity.MEDIUM
                else -> null
            }

            if (severity != null) {
                riskyApps++
                val label = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(packageName)
                findings += SecurityFinding(
                    title = "App capability combination requires review",
                    description = "$label ($packageName): ${reasons.joinToString()}",
                    severity = severity,
                    category = "Installed apps",
                    recommendation = "Open the app's Android settings page, verify the permissions/special access are expected, and uninstall it if you do not recognize or trust it."
                )
            }
        }

        return InstalledAppScanResult(
            appsScanned = packages.size,
            userAppsScanned = userApps,
            riskyApps = riskyApps,
            findings = findings.sortedByDescending { it.severity.ordinal }
        )
    }
}
