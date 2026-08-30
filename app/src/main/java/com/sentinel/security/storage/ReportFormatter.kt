/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.storage

import android.content.Context
import com.sentinel.security.BuildConfig
import com.sentinel.security.scanner.ScanResult
import com.sentinel.security.vpn.CustomBlocklist
import com.sentinel.security.vpn.VpnMode
import com.sentinel.security.vpn.VpnPreferences
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ReportFormatter {
    fun build(context: Context, result: ScanResult): String {
        val date = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(result.timestamp))
        val mode = if (VpnPreferences.mode(context) == VpnMode.FIREWALL) "FIREWALL" else "MONITOR"
        val posture = when {
            result.score >= 90 -> "STRONG"
            result.score >= 75 -> "GOOD"
            result.score >= 55 -> "REVIEW"
            else -> "HIGH RISK"
        }

        return buildString {
            appendLine("SENTINEL ANDROID v2 SECURITY REPORT")
            appendLine("Version: ${BuildConfig.VERSION_NAME}")
            appendLine(BuildConfig.COPYRIGHT_NOTICE)
            appendLine("Generated: $date")
            appendLine()
            appendLine("SECURITY POSTURE")
            appendLine("Score: ${result.score}/100 ($posture)")
            appendLine("Findings: ${result.findings.size} | Critical: ${result.criticalCount} | High: ${result.highCount} | Medium: ${result.mediumCount}")
            appendLine()
            appendLine("DEVICE")
            appendLine("Manufacturer: ${result.buildProfile.manufacturer}")
            appendLine("Model: ${result.buildProfile.model}")
            appendLine("Android: ${result.buildProfile.androidVersion} (API ${result.buildProfile.apiLevel})")
            appendLine("Security patch: ${result.buildProfile.securityPatch}")
            appendLine("Build profile ID: ${result.buildProfile.id}")
            appendLine("Root indicators: ${result.rooted}")
            appendLine("Debugger attached: ${result.debugger}")
            appendLine("Emulator indicators: ${result.emulator}")
            appendLine("Developer options: ${result.integrity.developerOptions}")
            appendLine("ADB enabled: ${result.integrity.adbEnabled}")
            appendLine("Secure screen lock: ${result.integrity.secureLockScreen}")
            appendLine()
            appendLine("APP REVIEW")
            appendLine("Installed packages scanned: ${result.appScan.appsScanned}")
            appendLine("User apps scanned: ${result.appScan.userAppsScanned}")
            appendLine("Apps with capability combinations requiring review: ${result.appScan.riskyApps}")
            appendLine("Third-party accessibility packages: ${result.specialAccess.accessibilityPackages.size}")
            appendLine("Notification listener packages: ${result.specialAccess.notificationListenerPackages.size}")
            appendLine("Device admin packages: ${result.specialAccess.deviceAdminPackages.size}")
            appendLine()
            appendLine("LOCAL VPN / FIREWALL")
            appendLine("Mode: $mode")
            appendLine("VPN active: ${VpnPreferences.isRunning(context)}")
            appendLine("DNS queries this session: ${VpnPreferences.dnsQueries(context)}")
            appendLine("Blocked this session: ${VpnPreferences.blocked(context)}")
            appendLine("Custom blocked domains: ${CustomBlocklist.all(context).size}")
            appendLine()
            appendLine("FINDINGS")
            if (result.findings.isEmpty()) {
                appendLine("No elevated signals detected by this Sentinel build.")
            } else {
                result.findings.forEachIndexed { index, finding ->
                    appendLine("${index + 1}. [${finding.severity}] ${finding.title}")
                    appendLine("   Category: ${finding.category}")
                    appendLine("   Signal: ${finding.description}")
                    appendLine("   Recommended action: ${finding.recommendation}")
                }
            }
            appendLine()
            appendLine("NOTES")
            appendLine("Sentinel reports security signals and risky capability combinations; a finding is not by itself proof that an app is malicious.")
            appendLine("All checks in this Alpha build run on-device. No scan report is uploaded by Sentinel.")
        }
    }
}
