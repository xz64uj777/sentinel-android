/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.sentinel.security.databinding.ActivityMainBinding
import com.sentinel.security.scanner.ScanResult
import com.sentinel.security.scanner.SecurityScanner
import com.sentinel.security.storage.ReportFormatter
import com.sentinel.security.storage.ScanHistory
import com.sentinel.security.vpn.CustomBlocklist
import com.sentinel.security.vpn.SentinelVpnService
import com.sentinel.security.vpn.VpnMode
import com.sentinel.security.vpn.VpnPreferences
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val uiHandler = Handler(Looper.getMainLooper())
    private var latestScan: ScanResult? = null
    private var latestReport: String = ""

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startSentinelVpn()
        } else {
            binding.txtVpn.text = "VPN: PERMISSION NOT GRANTED"
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        prepareVpnPermission()
    }

    private val exportReportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        if (uri == null || latestReport.isBlank()) return@registerForActivityResult
        runCatching {
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { writer ->
                writer.write(latestReport)
            } ?: error("Unable to open report destination")
        }.onSuccess {
            toast("Sentinel report saved")
        }.onFailure {
            toast("Could not save report: ${it.message ?: "unknown error"}")
        }
    }

    private val refreshVpnUi = object : Runnable {
        override fun run() {
            renderVpnState()
            uiHandler.postDelayed(this, 750)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.txtVersion.text = "Android Security Monitor • ${BuildConfig.VERSION_NAME}"
        binding.txtCopyright.text = BuildConfig.COPYRIGHT_NOTICE
        binding.btnCopyReport.isEnabled = false
        binding.btnExportReport.isEnabled = false

        binding.switchFirewall.isChecked = VpnPreferences.mode(this) == VpnMode.FIREWALL
        binding.switchFirewall.setOnCheckedChangeListener { _, enabled ->
            VpnPreferences.setMode(this, if (enabled) VpnMode.FIREWALL else VpnMode.MONITOR)
            if (VpnPreferences.isRunning(this)) {
                startService(
                    Intent(this, SentinelVpnService::class.java)
                        .setAction(SentinelVpnService.ACTION_REFRESH)
                )
            }
            renderVpnState()
        }

        binding.btnScan.setOnClickListener { runSecurityScan() }
        binding.btnVpn.setOnClickListener {
            if (VpnPreferences.isRunning(this)) stopSentinelVpn() else requestNotificationThenVpn()
        }
        binding.btnCopyReport.setOnClickListener { copyLatestReport() }
        binding.btnExportReport.setOnClickListener { exportLatestReport() }

        binding.btnAddDomain.setOnClickListener {
            val entered = binding.inputBlockDomain.text?.toString().orEmpty()
            if (CustomBlocklist.add(this, entered)) {
                binding.inputBlockDomain.setText("")
                toast("Domain added to local firewall")
                renderVpnState()
            } else {
                toast("Enter a valid domain, for example example.com")
            }
        }
        binding.btnClearDomains.setOnClickListener {
            CustomBlocklist.clear(this)
            toast("Custom firewall domains cleared")
            renderVpnState()
        }

        renderScanHistory()
        renderVpnState()
    }

    override fun onResume() {
        super.onResume()
        uiHandler.removeCallbacks(refreshVpnUi)
        uiHandler.post(refreshVpnUi)
    }

    override fun onPause() {
        uiHandler.removeCallbacks(refreshVpnUi)
        super.onPause()
    }

    private fun runSecurityScan() {
        binding.btnScan.isEnabled = false
        binding.btnScan.text = "SCANNING…"
        binding.txtFindingsDetails.text = "Inspecting device integrity, special access, and installed-app capability combinations…"

        Thread {
            val result = SecurityScanner().runScan(applicationContext)
            ScanHistory.record(applicationContext, result)
            val report = ReportFormatter.build(applicationContext, result)

            runOnUiThread {
                latestScan = result
                latestReport = report
                renderScanResult(result)
                renderScanHistory()
                binding.btnScan.isEnabled = true
                binding.btnScan.text = "RUN SECURITY SCAN"
                binding.btnCopyReport.isEnabled = true
                binding.btnExportReport.isEnabled = true
            }
        }.start()
    }

    private fun renderScanResult(result: ScanResult) {
        binding.txtScore.text = "${result.score}/100"
        binding.txtPosture.text = when {
            result.score >= 90 -> "STRONG POSTURE"
            result.score >= 75 -> "GOOD POSTURE"
            result.score >= 55 -> "REVIEW RECOMMENDED"
            else -> "HIGH-RISK POSTURE"
        }
        binding.txtThreats.text = "${result.findings.size} findings • ${result.criticalCount} critical • ${result.highCount} high"
        binding.txtRoot.text = "Root: ${if (result.rooted) "INDICATORS FOUND" else "CLEAR"}"
        binding.txtDebug.text = "Debugger: ${if (result.debugger) "ATTACHED" else "CLEAR"}"
        binding.txtEmulator.text = "Environment: ${if (result.emulator) "EMULATOR-LIKE" else "PHYSICAL-LIKE"}"

        val integrity = result.integrity
        binding.txtIntegrity.text = buildString {
            append("Developer options: ${onOff(integrity.developerOptions)}")
            append("  •  ADB: ${onOff(integrity.adbEnabled)}")
            append("\nSecure lock: ${if (integrity.secureLockScreen) "YES" else "NO"}")
            append("  •  Security patch: ${integrity.securityPatch}")
        }
        binding.txtAppsScanned.text =
            "Apps scanned: ${result.appScan.appsScanned} • User apps: ${result.appScan.userAppsScanned} • Review: ${result.appScan.riskyApps}"
        binding.txtBuildProfile.text =
            "${result.buildProfile.manufacturer} ${result.buildProfile.model} • Android ${result.buildProfile.androidVersion} / API ${result.buildProfile.apiLevel}\nBuild profile ID: ${result.buildProfile.id}"

        binding.txtFindingsDetails.text = if (result.findings.isEmpty()) {
            "No elevated signals found by this Sentinel build."
        } else {
            result.findings.take(12).joinToString(separator = "\n\n") { finding ->
                "[${finding.severity}] ${finding.title}\n${finding.description}\nFix: ${finding.recommendation}"
            } + if (result.findings.size > 12) "\n\n+ ${result.findings.size - 12} more in exported report" else ""
        }
    }

    private fun renderScanHistory() {
        val history = ScanHistory.snapshot(this)
        if (history.lastScanTime == 0L) {
            binding.txtScanHistory.text = "Last scan: Never"
            return
        }
        val whenText = SimpleDateFormat("MMM d, yyyy h:mm a", Locale.US).format(Date(history.lastScanTime))
        val trend = history.recentScores.joinToString(" → ")
        binding.txtScanHistory.text = "Last scan: $whenText • ${history.lastScore}/100\nRecent scores: $trend"
    }

    private fun requestNotificationThenVpn() {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            prepareVpnPermission()
        }
    }

    private fun prepareVpnPermission() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) vpnPermissionLauncher.launch(prepareIntent) else startSentinelVpn()
    }

    private fun startSentinelVpn() {
        VpnPreferences.setMode(this, if (binding.switchFirewall.isChecked) VpnMode.FIREWALL else VpnMode.MONITOR)
        val intent = Intent(this, SentinelVpnService::class.java).setAction(SentinelVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
        binding.txtVpn.text = "VPN: STARTING…"
    }

    private fun stopSentinelVpn() {
        stopService(Intent(this, SentinelVpnService::class.java))
        VpnPreferences.setRunning(this, false)
        renderVpnState()
    }

    private fun renderVpnState() {
        val running = VpnPreferences.isRunning(this)
        val mode = VpnPreferences.mode(this)
        val custom = CustomBlocklist.all(this)
        val recentBlocks = VpnPreferences.recentBlocked(this)

        binding.txtVpn.text = if (running) "VPN: ACTIVE" else "VPN: INACTIVE"
        binding.txtVpnMode.text = "Mode: ${if (mode == VpnMode.FIREWALL) "FIREWALL" else "MONITOR"}"
        binding.txtDnsQueries.text = "DNS queries observed: ${VpnPreferences.dnsQueries(this)}"
        binding.txtBlocked.text = "Blocked this session: ${VpnPreferences.blocked(this)}"
        binding.txtLastDomain.text = "Last domain: ${VpnPreferences.lastDomain(this).ifBlank { "—" }}"
        binding.txtCustomBlocks.text = if (custom.isEmpty()) {
            "Custom blocklist: none"
        } else {
            "Custom blocklist (${custom.size}): ${custom.take(6).joinToString()}${if (custom.size > 6) "…" else ""}"
        }
        binding.txtRecentBlocks.text = if (recentBlocks.isEmpty()) {
            "Recent blocks: —"
        } else {
            "Recent blocks: ${recentBlocks.take(4).joinToString()}"
        }
        binding.btnVpn.text = if (running) "STOP SENTINEL VPN" else "START SENTINEL VPN"
    }

    private fun copyLatestReport() {
        if (latestReport.isBlank()) return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Sentinel security report", latestReport))
        toast("Report copied")
    }

    private fun exportLatestReport() {
        if (latestReport.isBlank()) return
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
        exportReportLauncher.launch("Sentinel-Security-Report-$stamp.txt")
    }

    private fun onOff(value: Boolean): String = if (value) "ON" else "OFF"

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
