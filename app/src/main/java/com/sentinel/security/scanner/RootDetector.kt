/* Sentinel Android v2 | Copyright (c) 2026 Kyle T. | All Rights Reserved. */
package com.sentinel.security.scanner

import java.io.File

object RootDetector {
    fun isRooted(): Boolean {
        val paths = arrayOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/system/bin/.ext/su"
        )
        return paths.any { File(it).exists() }
    }
}
