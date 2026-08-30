/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.firewall

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
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
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import com.sentinel.security.databinding.ActivityAppFirewallBinding
import com.sentinel.security.vpn.SentinelVpnService
import com.sentinel.security.vpn.VpnMode
import com.sentinel.security.vpn.VpnPreferences

class AppFirewallActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAppFirewallBinding
    private val adapter = AppFirewallAdapter { packageName, blocked ->
        AppFirewallStore.setBlocked(this, packageName, blocked)
        renderState()
    }
    private val uiHandler = Handler(Looper.getMainLooper())
    private var installedApps: List<FirewallApp> = emptyList()
    private val labelCache = mutableMapOf<String, String>()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startOrReconfigureFirewall()
        } else {
            toast("VPN permission is required for app blocking")
        }
    }

    private val refreshUi = object : Runnable {
        override fun run() {
            renderState()
            uiHandler.postDelayed(this, 900L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAppFirewallBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.listApps.layoutManager = LinearLayoutManager(this)
        binding.listApps.adapter = adapter

        binding.inputSearch.doAfterTextChanged {
            adapter.filter(it?.toString().orEmpty())
        }

        binding.btnApplyFirewall.setOnClickListener { prepareAndApplyFirewall() }
        binding.btnStopFirewall.setOnClickListener { stopAppFirewall() }
        binding.btnClearSelection.setOnClickListener {
            AppFirewallStore.clear(this)
            adapter.submit(installedApps, emptySet())
            renderState()
            toast("App firewall selection cleared")
        }

        loadInstalledApps()
        renderState()
    }

    override fun onResume() {
        super.onResume()
        uiHandler.removeCallbacks(refreshUi)
        uiHandler.post(refreshUi)
    }

    override fun onPause() {
        uiHandler.removeCallbacks(refreshUi)
        super.onPause()
    }

    private fun loadInstalledApps() {
        binding.txtAppListStatus.text = "Loading apps…"
        Thread {
            val pm = packageManager
            val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }

            val items = applications.asSequence()
                .filter { it.packageName != packageName }
                .filter { pm.checkPermission(Manifest.permission.INTERNET, it.packageName) == PackageManager.PERMISSION_GRANTED }
                .filter { isUserVisibleApp(pm, it) }
                .map { info ->
                    FirewallApp(
                        label = runCatching { info.loadLabel(pm).toString() }
                            .getOrDefault(info.packageName),
                        packageName = info.packageName
                    )
                }
                .distinctBy { it.packageName }
                .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
                .toList()

            runOnUiThread {
                installedApps = items
                adapter.submit(items, AppFirewallStore.blockedPackages(this))
                binding.txtAppListStatus.text = "${items.size} network-capable apps"
                renderState()
            }
        }.start()
    }

    private fun isUserVisibleApp(pm: PackageManager, info: ApplicationInfo): Boolean {
        if (pm.getLaunchIntentForPackage(info.packageName) != null) return true
        val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val isUpdatedSystem = (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return !isSystem || isUpdatedSystem
    }

    private fun prepareAndApplyFirewall() {
        val selected = AppFirewallStore.blockedPackages(this)
        if (selected.isEmpty()) {
            toast("Select at least one app to block")
            return
        }

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startOrReconfigureFirewall()
        }
    }

    private fun startOrReconfigureFirewall() {
        VpnPreferences.setMode(this, VpnMode.APP_BLOCK)
        val intent = Intent(this, SentinelVpnService::class.java)
            .setAction(
                if (VpnPreferences.isRunning(this)) {
                    SentinelVpnService.ACTION_RESTART
                } else {
                    SentinelVpnService.ACTION_START
                }
            )

        if (VpnPreferences.isRunning(this)) {
            startService(intent)
        } else {
            ContextCompat.startForegroundService(this, intent)
        }
        toast("App firewall applying…")
        renderState()
    }

    private fun stopAppFirewall() {
        val active = VpnPreferences.isRunning(this) && VpnPreferences.mode(this) == VpnMode.APP_BLOCK
        if (!active) return
        stopService(Intent(this, SentinelVpnService::class.java))
        VpnPreferences.setRunning(this, false)
        renderState()
    }

    private fun renderState() {
        val selected = AppFirewallStore.blockedPackages(this)
        val appFirewallActive = VpnPreferences.isRunning(this) && VpnPreferences.mode(this) == VpnMode.APP_BLOCK
        val snapshot = AppFirewallStats.snapshot()

        binding.txtSelectedCount.text = "Selected to block: ${selected.size}"
        binding.txtFirewallState.text = if (appFirewallActive) {
            "APP FIREWALL: ACTIVE"
        } else {
            "APP FIREWALL: INACTIVE"
        }
        binding.txtFirewallStats.text =
            "Blocked packets: ${snapshot.packetsBlocked} • Dropped: ${formatBytes(snapshot.bytesBlocked)}"

        binding.txtRecentAttempts.text = if (snapshot.recentAttempts.isEmpty()) {
            "Recent blocked connections: —"
        } else {
            snapshot.recentAttempts.take(10).joinToString("\n") { attempt ->
                val app = appLabel(attempt.packageName)
                val port = attempt.destinationPort?.let { ":$it" }.orEmpty()
                "$app • ${attempt.protocol} • ${attempt.destination}$port"
            }
        }

        binding.btnApplyFirewall.text = if (appFirewallActive) "APPLY CHANGES" else "START APP FIREWALL"
        binding.btnStopFirewall.isEnabled = appFirewallActive
    }

    private fun appLabel(packageName: String): String = labelCache.getOrPut(packageName) {
        if (packageName == "Selected apps" || packageName == "Unknown app") return@getOrPut packageName
        runCatching {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getApplicationInfo(
                    packageName,
                    PackageManager.ApplicationInfoFlags.of(0L)
                )
            } else {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(packageName, 0)
            }
            info.loadLabel(packageManager).toString()
        }.getOrDefault(packageName)
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1024L * 1024L -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
        bytes >= 1024L -> String.format("%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
