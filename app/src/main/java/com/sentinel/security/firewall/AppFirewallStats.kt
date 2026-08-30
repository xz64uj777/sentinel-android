/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.firewall

import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicLong

data class BlockedAttempt(
    val timestamp: Long,
    val packageName: String,
    val protocol: String,
    val destination: String,
    val destinationPort: Int?
)

data class AppFirewallSnapshot(
    val packetsBlocked: Long,
    val bytesBlocked: Long,
    val recentAttempts: List<BlockedAttempt>
)

object AppFirewallStats {
    private val packets = AtomicLong(0)
    private val bytes = AtomicLong(0)
    private val recent = ArrayDeque<BlockedAttempt>()
    private val lastSeen = LinkedHashMap<String, Long>()

    @Synchronized
    fun reset() {
        packets.set(0)
        bytes.set(0)
        recent.clear()
        lastSeen.clear()
    }

    @Synchronized
    fun record(packetBytes: Int, packageName: String, metadata: PacketMetadata?) {
        packets.incrementAndGet()
        bytes.addAndGet(packetBytes.toLong())
        if (metadata == null) return

        val destinationPort = metadata.destinationPort
        val key = buildString {
            append(packageName)
            append('|')
            append(metadata.protocolName)
            append('|')
            append(metadata.destination.hostAddress ?: metadata.destination.hostName)
            append('|')
            append(destinationPort ?: -1)
        }
        val now = System.currentTimeMillis()
        val previous = lastSeen[key]
        if (previous != null && now - previous < 2_000L) return

        lastSeen[key] = now
        if (lastSeen.size > 200) {
            val oldest = lastSeen.entries.firstOrNull()?.key
            if (oldest != null) lastSeen.remove(oldest)
        }

        recent.addFirst(
            BlockedAttempt(
                timestamp = now,
                packageName = packageName,
                protocol = metadata.protocolName,
                destination = metadata.destination.hostAddress ?: metadata.destination.hostName,
                destinationPort = destinationPort
            )
        )
        while (recent.size > 30) recent.removeLast()
    }

    @Synchronized
    fun snapshot(): AppFirewallSnapshot = AppFirewallSnapshot(
        packetsBlocked = packets.get(),
        bytesBlocked = bytes.get(),
        recentAttempts = recent.toList()
    )
}
