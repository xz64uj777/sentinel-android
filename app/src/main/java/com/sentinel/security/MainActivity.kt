/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.sentinel.security.databinding.ActivityMainBinding
import com.sentinel.security.scanner.SecurityScanner
import com.sentinel.security.vpn.SentinelVpnService
import com.sentinel.security.vpn.VpnMode
import com.sentinel.security.vpn.VpnPreferences

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val uiHandler = Handler(Looper.getMainLooper())

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
        // Android allows the VPN foreground service even if notifications are denied.
        // Continue to the system VPN consent screen either way.
        prepareVpnPermission()
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

        binding.txtCopyright.text = BuildConfig.COPYRIGHT_NOTICE

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
            if (VpnPreferences.isRunning(this)) {
                stopSentinelVpn()
            } else {
                requestNotificationThenVpn()
            }
        }

        renderVpnState()
    }

    override fun onResume() {
        super.onResume()
        uiHandler.post(refreshVpnUi)
    }

    override fun onPause() {
        uiHandler.removeCallbacks(refreshVpnUi)
        super.onPause()
    }

    private fun runSecurityScan() {
        binding.btnScan.isEnabled = false
        binding.btnScan.text = "SCANNING…"
        binding.txtFindingsDetails.text = "Inspecting device and installed-app signals…"

        Thread {
            val result = SecurityScanner().runScan(this)
            runOnUiThread {
                binding.txtRoot.text = "Root: ${if (result.rooted) "DETECTED" else "CLEAR"}"
                binding.txtDebug.text = "Debugger: ${if (result.debugger) "DETECTED" else "CLEAR"}"
                binding.txtEmulator.text = "Emulator: ${if (result.emulator) "DETECTED" else "CLEAR"}"
                binding.txtScore.text = "Security Score: ${result.score}/100"
                binding.txtThreats.text = "Findings: ${result.findings.size}"
                binding.txtFindingsDetails.text = if (result.findings.isEmpty()) {
                    "No high-risk signals found by the Alpha scanner."
                } else {
                    result.findings.take(6).joinToString(separator = "\n") { "• $it" }
                }
                binding.btnScan.isEnabled = true
                binding.btnScan.text = "RUN SECURITY SCAN"
            }
        }.start()
    }

    private fun requestNotificationThenVpn() {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            prepareVpnPermission()
        }
    }

    private fun prepareVpnPermission() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startSentinelVpn()
        }
    }

    private fun startSentinelVpn() {
        VpnPreferences.setMode(
            this,
            if (binding.switchFirewall.isChecked) VpnMode.FIREWALL else VpnMode.MONITOR
        )
        val intent = Intent(this, SentinelVpnService::class.java)
            .setAction(SentinelVpnService.ACTION_START)
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
        val dnsQueries = VpnPreferences.dnsQueries(this)
        val blocked = VpnPreferences.blocked(this)
        val lastDomain = VpnPreferences.lastDomain(this)

        binding.txtVpn.text = if (running) "VPN: ACTIVE" else "VPN: INACTIVE"
        binding.txtVpnMode.text = "Mode: ${if (mode == VpnMode.FIREWALL) "FIREWALL" else "MONITOR"}"
        binding.txtDnsQueries.text = "DNS queries observed: $dnsQueries"
        binding.txtBlocked.text = "Blocked this session: $blocked"
        binding.txtLastDomain.text = "Last domain: ${lastDomain.ifBlank { "—" }}"
        binding.btnVpn.text = if (running) "STOP SENTINEL VPN" else "START SENTINEL VPN"
    }
}
