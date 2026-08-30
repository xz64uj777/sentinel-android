/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.scanner

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.provider.Settings
import com.sentinel.security.model.SecurityFinding
import com.sentinel.security.model.Severity

data class SpecialAccessResult(
    val accessibilityPackages: Set<String>,
    val notificationListenerPackages: Set<String>,
    val deviceAdminPackages: Set<String>,
    val findings: List<SecurityFinding>
)

object SpecialAccessScanner {

    fun scan(context: Context): SpecialAccessResult {
        val accessibility = componentPackages(
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
        )
        val notificationListeners = componentPackages(
            Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            )
        )
        val admins = runCatching {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.activeAdmins.orEmpty().map { it.packageName }.toSet()
        }.getOrDefault(emptySet())

        val findings = mutableListOf<SecurityFinding>()

        accessibility.filterNot { isSystemPackage(context, it) }.forEach { pkg ->
            findings += SecurityFinding(
                title = "Third-party accessibility service enabled",
                description = displayPackage(context, pkg),
                severity = Severity.MEDIUM,
                category = "Special access",
                recommendation = "Review Accessibility settings and disable services you do not recognize or actively use."
            )
        }

        notificationListeners.filterNot { isSystemPackage(context, it) }.forEach { pkg ->
            findings += SecurityFinding(
                title = "Third-party notification access enabled",
                description = displayPackage(context, pkg),
                severity = Severity.MEDIUM,
                category = "Special access",
                recommendation = "Review Notification access and remove apps that do not need to read notifications."
            )
        }

        admins.filterNot { isSystemPackage(context, it) }.forEach { pkg ->
            findings += SecurityFinding(
                title = "Third-party device administrator active",
                description = displayPackage(context, pkg),
                severity = Severity.HIGH,
                category = "Special access",
                recommendation = "Review Device admin apps and remove administrator access from apps you do not fully trust."
            )
        }

        return SpecialAccessResult(
            accessibilityPackages = accessibility,
            notificationListenerPackages = notificationListeners,
            deviceAdminPackages = admins,
            findings = findings
        )
    }

    private fun componentPackages(raw: String?): Set<String> {
        if (raw.isNullOrBlank()) return emptySet()
        return raw.split(':')
            .mapNotNull { ComponentName.unflattenFromString(it)?.packageName }
            .toSet()
    }

    private fun isSystemPackage(context: Context, packageName: String): Boolean {
        return runCatching {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        }.getOrDefault(false)
    }

    private fun displayPackage(context: Context, packageName: String): String {
        return runCatching {
            val pm = context.packageManager
            val info = pm.getApplicationInfo(packageName, 0)
            "${pm.getApplicationLabel(info)} ($packageName)"
        }.getOrDefault(packageName)
    }
}
