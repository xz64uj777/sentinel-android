/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

class DnsProxyLoop(
    private val service: VpnService,
    private val vpnInterface: ParcelFileDescriptor
) {
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null
    private var upstreamSocket: DatagramSocket? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        worker = Thread({ runLoop() }, "SentinelDnsProxy").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running.set(false)
        runCatching { upstreamSocket?.close() }
        upstreamSocket = null
        worker?.interrupt()
        worker = null
    }

    private fun runLoop() {
        val input = FileInputStream(vpnInterface.fileDescriptor)
        val output = FileOutputStream(vpnInterface.fileDescriptor)
        val readBuffer = ByteArray(32_767)

        try {
            while (running.get()) {
                val length = input.read(readBuffer)
                if (length <= 0) continue

                val parsed = DnsPacketParser.parse(readBuffer, length) ?: continue
                val firewallMode = VpnPreferences.mode(service) == VpnMode.FIREWALL
                val blocked = firewallMode && LocalBlocklist.shouldBlock(service, parsed.domain)

                val dnsResponse = if (blocked) {
                    DnsResponseFactory.nxDomain(parsed.dnsPayload)
                } else {
                    forwardToUpstream(parsed.dnsPayload)
                        ?: DnsResponseFactory.serverFailure(parsed.dnsPayload)
                }

                VpnPreferences.recordDns(service, parsed.domain, blocked)
                val responsePacket = DnsPacketBuilder.buildResponse(parsed, dnsResponse)
                output.write(responsePacket)
                output.flush()
            }
        } catch (error: Exception) {
            if (running.get()) Log.e(TAG, "DNS proxy stopped unexpectedly", error)
        } finally {
            runCatching { upstreamSocket?.close() }
            upstreamSocket = null
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? {
        val socket = getOrCreateSocket() ?: return null
        for (server in UPSTREAM_DNS) {
            try {
                val request = DatagramPacket(query, query.size, InetAddress.getByName(server), 53)
                socket.send(request)
                val responseBuffer = ByteArray(4096)
                val response = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(response)
                return response.data.copyOfRange(response.offset, response.offset + response.length)
            } catch (_: SocketTimeoutException) {
                // Try the next upstream resolver.
            } catch (error: Exception) {
                Log.w(TAG, "DNS upstream $server failed: ${error.message}")
            }
        }
        return null
    }

    private fun getOrCreateSocket(): DatagramSocket? {
        upstreamSocket?.let { if (!it.isClosed) return it }
        return runCatching {
            DatagramSocket().also { socket ->
                socket.soTimeout = 2_500
                if (!service.protect(socket)) {
                    socket.close()
                    error("Unable to protect DNS socket from VPN routing")
                }
                upstreamSocket = socket
            }
        }.onFailure {
            Log.e(TAG, "Unable to create protected DNS socket", it)
        }.getOrNull()
    }

    companion object {
        private const val TAG = "SentinelDnsProxy"
        private val UPSTREAM_DNS = listOf("1.1.1.1", "8.8.8.8")
    }
}
