/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.sentinel.security.databinding.ActivityMainBinding
import com.sentinel.security.scanner.SecurityScanner
import com.sentinel.security.vpn.SentinelVpnService

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        startSentinelVpn()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.txtCopyright.text = BuildConfig.COPYRIGHT_NOTICE

        binding.btnScan.setOnClickListener {
            val result = SecurityScanner().runScan(this)
            binding.txtRoot.text = "Root: ${if (result.rooted) "DETECTED" else "CLEAR"}"
            binding.txtDebug.text = "Debugger: ${if (result.debugger) "DETECTED" else "CLEAR"}"
            binding.txtEmulator.text = "Emulator: ${if (result.emulator) "DETECTED" else "CLEAR"}"
            binding.txtScore.text = "Security Score: ${result.score}/100"
            binding.txtThreats.text = "Findings: ${result.findings.size}"
        }

        binding.btnVpn.setOnClickListener {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) vpnPermissionLauncher.launch(prepareIntent)
            else startSentinelVpn()
        }
    }

    private fun startSentinelVpn() {
        startForegroundService(Intent(this, SentinelVpnService::class.java))
        binding.txtVpn.text = "VPN: STARTING"
    }
}
