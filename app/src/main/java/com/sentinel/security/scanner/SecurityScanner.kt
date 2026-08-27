/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.scanner

import android.content.Context

data class ScanResult(
    val rooted: Boolean,
    val debugger: Boolean,
    val emulator: Boolean,
    val score: Int,
    val findings: List<String>
)

class SecurityScanner {
    fun runScan(context: Context): ScanResult {
        val rooted = RootDetector.isRooted()
        val debugger = DebugDetector.isDebuggerAttached()
        val emulator = EmulatorDetector.isEmulator()

        val findings = mutableListOf<String>()
        if (rooted) findings += "Root access detected"
        if (debugger) findings += "Debugger connected"
        if (emulator) findings += "Emulated environment detected"
        findings += PermissionScanner().scan(context)

        var score = 100
        if (rooted) score -= 35
        if (debugger) score -= 20
        if (emulator) score -= 10
        score -= findings.count { it.startsWith("Risky permission") } * 3

        return ScanResult(rooted, debugger, emulator, score.coerceIn(0, 100), findings)
    }
}
