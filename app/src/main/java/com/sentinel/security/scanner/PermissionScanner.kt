/* Sentinel Android v2 | Copyright (c) 2026 Kyle T. | All Rights Reserved. */
package com.sentinel.security.scanner

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager

class PermissionScanner {
    private val riskyPermissions = setOf(
        Manifest.permission.READ_SMS,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.SEND_SMS,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.CAMERA,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.WRITE_CALL_LOG,
        Manifest.permission.SYSTEM_ALERT_WINDOW
    )

    fun scan(context: Context): List<String> {
        val pm = context.packageManager
        val findings = mutableListOf<String>()
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            val requested = pkg.requestedPermissions ?: continue
            val risky = requested.filter { it in riskyPermissions }
            if (risky.size >= 3) {
                findings += "Risky permission combination: ${pkg.packageName} (${risky.size})"
            }
        }
        return findings
    }
}
