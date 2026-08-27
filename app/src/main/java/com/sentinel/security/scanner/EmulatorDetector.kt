/* Sentinel Android v2 | Copyright (c) 2026 Kyle T. | All Rights Reserved. */
package com.sentinel.security.scanner

import android.os.Build

object EmulatorDetector {
    fun isEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val hardware = Build.HARDWARE.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        return fingerprint.contains("generic") ||
            fingerprint.contains("emulator") ||
            model.contains("emulator") ||
            model.contains("sdk") ||
            manufacturer.contains("genymotion") ||
            hardware.contains("goldfish") ||
            hardware.contains("ranchu")
    }
}
