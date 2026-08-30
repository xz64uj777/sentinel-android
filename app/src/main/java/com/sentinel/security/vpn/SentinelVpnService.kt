/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.sentinel.security.MainActivity
import com.sentinel.security.R
import com.sentinel.security.firewall.AppBlockPacketLoop
import com.sentinel.security.firewall.AppFirewallStats
import com.sentinel.security.firewall.AppFirewallStore

class SentinelVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var dnsProxyLoop: DnsProxyLoop? = null
    private var appBlockLoop: AppBlockPacketLoop? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Starting protection…"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopSelf()
                return START_NOT_STICKY
            }

            ACTION_REFRESH -> {
                updateNotification()
                return START_STICKY
            }

            ACTION_RESTART -> {
                restartTunnel()
                return START_STICKY
            }
        }

        if (vpnInterface == null) startTunnelForMode() else updateNotification()
        return START_STICKY
    }

    override fun onDestroy() {
        stopTunnel()
        VpnPreferences.setRunning(this, false)
        super.onDestroy()
    }

    override fun onRevoke() {
        VpnPreferences.setRunning(this, false)
        stopSelf()
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun restartTunnel() {
        stopTunnel()
        startTunnelForMode()
    }

    private fun startTunnelForMode() {
        when (VpnPreferences.mode(this)) {
            VpnMode.MONITOR,
            VpnMode.FIREWALL -> startDnsVpn()

            VpnMode.APP_BLOCK -> startAppBlockVpn()
        }
    }

    private fun startDnsVpn() {
        VpnPreferences.resetSessionCounters(this)

        val builder = Builder()
            .setSession("Sentinel DNS Security")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(DNS_VPN_ADDRESS, 32)
            .addDnsServer(VIRTUAL_DNS)
            .addRoute(VIRTUAL_DNS, 32)

        val established = runCatching { builder.establish() }.getOrNull()
        if (established == null) {
            VpnPreferences.setRunning(this, false)
            stopSelf()
            return
        }

        vpnInterface = established
        dnsProxyLoop = DnsProxyLoop(this, established).also { it.start() }
        VpnPreferences.setRunning(this, true)
        updateNotification()
    }

    private fun startAppBlockVpn() {
        val selected = AppFirewallStore.blockedPackages(this)
        if (selected.isEmpty()) {
            VpnPreferences.setRunning(this, false)
            stopSelf()
            return
        }

        AppFirewallStats.reset()
        val builder = Builder()
            .setSession("Sentinel App Firewall")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(APP_BLOCK_ADDRESS_V4, 32)
            .addRoute("0.0.0.0", 0)
            .addAddress(APP_BLOCK_ADDRESS_V6, 128)
            .addRoute("::", 0)

        var routedApps = 0
        selected.forEach { packageName ->
            runCatching {
                builder.addAllowedApplication(packageName)
                routedApps++
            }
        }

        if (routedApps == 0) {
            VpnPreferences.setRunning(this, false)
            stopSelf()
            return
        }

        val established = runCatching { builder.establish() }.getOrNull()
        if (established == null) {
            VpnPreferences.setRunning(this, false)
            stopSelf()
            return
        }

        vpnInterface = established
        appBlockLoop = AppBlockPacketLoop(this, established).also { it.start() }
        VpnPreferences.setRunning(this, true)
        updateNotification()
    }

    private fun stopTunnel() {
        dnsProxyLoop?.stop()
        dnsProxyLoop = null
        appBlockLoop?.stop()
        appBlockLoop = null
        runCatching { vpnInterface?.close() }
        vpnInterface = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Sentinel VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Sentinel on-device DNS and app firewall protection"
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun updateNotification() {
        val text = when (VpnPreferences.mode(this)) {
            VpnMode.MONITOR -> "Monitor mode • DNS protection active"
            VpnMode.FIREWALL -> {
                val blocked = VpnPreferences.blocked(this)
                if (blocked > 0) "DNS firewall • $blocked blocked" else "DNS firewall active"
            }
            VpnMode.APP_BLOCK -> {
                val count = AppFirewallStore.blockedPackages(this).size
                val packets = AppFirewallStats.snapshot().packetsBlocked
                "App firewall • $count apps • $packets packets dropped"
            }
        }

        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(status: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("Sentinel Android v2")
        .setContentText(status)
        .setSmallIcon(R.drawable.ic_sentinel_notification)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setCategory(NotificationCompat.CATEGORY_SERVICE)
        .setContentIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        )
        .build()

    companion object {
        const val ACTION_START = "com.sentinel.security.vpn.START"
        const val ACTION_STOP = "com.sentinel.security.vpn.STOP"
        const val ACTION_REFRESH = "com.sentinel.security.vpn.REFRESH"
        const val ACTION_RESTART = "com.sentinel.security.vpn.RESTART"

        private const val CHANNEL_ID = "sentinel_vpn"
        private const val NOTIFICATION_ID = 1001
        private const val DNS_VPN_ADDRESS = "10.10.10.2"
        private const val VIRTUAL_DNS = "10.10.10.1"
        private const val APP_BLOCK_ADDRESS_V4 = "10.20.0.2"
        private const val APP_BLOCK_ADDRESS_V6 = "fd00:5345:4e54:494e::2"
    }
}
