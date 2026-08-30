/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.FileInputStream
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

class AppBlockPacketLoop(
    private val service: VpnService,
    private val vpnInterface: ParcelFileDescriptor
) {
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null
    private val selectedPackages = AppFirewallStore.blockedPackages(service)
    private val connectivityManager =
        service.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun start() {
        if (!running.compareAndSet(false, true)) return
        worker = Thread({ runLoop() }, "SentinelAppBlock").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running.set(false)
        worker?.interrupt()
        worker = null
    }

    private fun runLoop() {
        val input = FileInputStream(vpnInterface.fileDescriptor)
        val buffer = ByteArray(32_767)

        try {
            while (running.get()) {
                val length = input.read(buffer)
                if (length <= 0) continue

                val metadata = PacketMetadataParser.parse(buffer, length)
                val packageName = resolvePackage(metadata)
                AppFirewallStats.record(length, packageName, metadata)

                // Intentionally do not write the packet back to the TUN interface.
                // Apps selected for APP_BLOCK are routed into this local sink, so
                // their network traffic is denied while unselected apps bypass it.
            }
        } catch (_: Exception) {
            // Closing the VPN descriptor is the normal shutdown path.
        } finally {
            runCatching { input.close() }
        }
    }

    private fun resolvePackage(metadata: PacketMetadata?): String {
        if (metadata == null) return fallbackPackage()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return fallbackPackage()
        val sourcePort = metadata.sourcePort ?: return fallbackPackage()
        val destinationPort = metadata.destinationPort ?: return fallbackPackage()
        if (metadata.protocol != 6 && metadata.protocol != 17) return fallbackPackage()

        val uid = runCatching {
            connectivityManager.getConnectionOwnerUid(
                metadata.protocol,
                InetSocketAddress(metadata.source, sourcePort),
                InetSocketAddress(metadata.destination, destinationPort)
            )
        }.getOrDefault(Process.INVALID_UID)

        if (uid == Process.INVALID_UID) return fallbackPackage()
        val packages = service.packageManager.getPackagesForUid(uid).orEmpty().toList()
        return packages.firstOrNull { it in selectedPackages }
            ?: packages.firstOrNull()
            ?: fallbackPackage()
    }

    private fun fallbackPackage(): String = when (selectedPackages.size) {
        0 -> "Unknown app"
        1 -> selectedPackages.first()
        else -> "Selected apps"
    }
}
