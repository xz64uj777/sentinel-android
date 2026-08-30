/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.scanner

import android.content.Context
import com.sentinel.security.model.SecurityFinding
import com.sentinel.security.model.Severity

data class ScanResult(
    val timestamp: Long,
    val rooted: Boolean,
    val debugger: Boolean,
    val emulator: Boolean,
    val score: Int,
    val integrity: DeviceIntegrityResult,
    val specialAccess: SpecialAccessResult,
    val appScan: InstalledAppScanResult,
    val buildProfile: BuildProfile,
    val findings: List<SecurityFinding>
) {
    val criticalCount: Int get() = findings.count { it.severity == Severity.CRITICAL }
    val highCount: Int get() = findings.count { it.severity == Severity.HIGH }
    val mediumCount: Int get() = findings.count { it.severity == Severity.MEDIUM }
}

class SecurityScanner {
    fun runScan(context: Context): ScanResult {
        val rooted = RootDetector.isRooted()
        val debugger = DebugDetector.isDebuggerAttached()
        val emulator = EmulatorDetector.isEmulator()
        val integrity = DeviceIntegrityScanner.scan(context)
        val specialAccess = SpecialAccessScanner.scan(context)
        val appScan = InstalledAppScanner.scan(context, specialAccess)
        val buildProfile = BuildProfileScanner.read()

        val findings = mutableListOf<SecurityFinding>()

        if (rooted) {
            findings += SecurityFinding(
                title = "Root indicators detected",
                description = "Sentinel found common root/su indicators on the device.",
                severity = Severity.HIGH,
                category = "Device integrity",
                recommendation = "If you did not intentionally root this device, investigate before using it for sensitive accounts."
            )
        }
        if (debugger) {
            findings += SecurityFinding(
                title = "Debugger currently attached",
                description = "A debugger is attached to the Sentinel process.",
                severity = Severity.MEDIUM,
                category = "Runtime",
                recommendation = "Disconnect debugging tools when normal testing is complete."
            )
        }
        if (emulator) {
            findings += SecurityFinding(
                title = "Emulated environment indicators",
                description = "Build properties resemble an emulator or virtual Android device.",
                severity = Severity.INFO,
                category = "Environment",
                recommendation = "No action is needed when you intentionally run Sentinel in an emulator."
            )
        }

        findings += integrity.findings
        findings += specialAccess.findings
        findings += appScan.findings

        val ordered = findings.sortedWith(
            compareByDescending<SecurityFinding> { it.severity.ordinal }
                .thenBy { it.category }
                .thenBy { it.title }
        )
        val penalty = ordered.sumOf { it.severity.scorePenalty }.coerceAtMost(100)
        val score = (100 - penalty).coerceIn(0, 100)

        return ScanResult(
            timestamp = System.currentTimeMillis(),
            rooted = rooted,
            debugger = debugger,
            emulator = emulator,
            score = score,
            integrity = integrity,
            specialAccess = specialAccess,
            appScan = appScan,
            buildProfile = buildProfile,
            findings = ordered
        )
    }
}
