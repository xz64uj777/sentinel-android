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

class SentinelVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var dnsProxyLoop: DnsProxyLoop? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Starting DNS protection…"))
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
        }

        if (vpnInterface == null) {
            startDnsVpn()
        } else {
            updateNotification()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        dnsProxyLoop?.stop()
        dnsProxyLoop = null
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        VpnPreferences.setRunning(this, false)
        super.onDestroy()
    }

    override fun onRevoke() {
        VpnPreferences.setRunning(this, false)
        stopSelf()
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun startDnsVpn() {
        VpnPreferences.resetSessionCounters(this)

        val builder = Builder()
            .setSession("Sentinel DNS Security")
            .setMtu(1500)
            .addAddress(VPN_ADDRESS, 32)
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

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Sentinel VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Sentinel on-device DNS security monitoring"
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun updateNotification() {
        val mode = when (VpnPreferences.mode(this)) {
            VpnMode.MONITOR -> "Monitor mode"
            VpnMode.FIREWALL -> "Firewall mode"
        }
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification("$mode • DNS protection active"))
    }

    private fun buildNotification(status: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("Sentinel Android v2")
        .setContentText(status)
        .setSmallIcon(android.R.drawable.ic_lock_lock)
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

        private const val CHANNEL_ID = "sentinel_vpn"
        private const val NOTIFICATION_ID = 1001
        private const val VPN_ADDRESS = "10.10.10.2"
        private const val VIRTUAL_DNS = "10.10.10.1"
    }
}
