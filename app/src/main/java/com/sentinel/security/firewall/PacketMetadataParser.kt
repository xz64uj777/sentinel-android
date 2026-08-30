/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.firewall

import java.net.InetAddress

data class PacketMetadata(
    val ipVersion: Int,
    val protocol: Int,
    val protocolName: String,
    val source: InetAddress,
    val destination: InetAddress,
    val sourcePort: Int?,
    val destinationPort: Int?
)

object PacketMetadataParser {
    private const val IPPROTO_TCP = 6
    private const val IPPROTO_UDP = 17

    fun parse(packet: ByteArray, length: Int): PacketMetadata? {
        if (length < 1) return null
        return when ((packet[0].toInt() ushr 4) and 0x0F) {
            4 -> parseIpv4(packet, length)
            6 -> parseIpv6(packet, length)
            else -> null
        }
    }

    private fun parseIpv4(packet: ByteArray, length: Int): PacketMetadata? {
        if (length < 20) return null
        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (headerLength < 20 || length < headerLength) return null

        val protocol = packet[9].toInt() and 0xFF
        val source = InetAddress.getByAddress(packet.copyOfRange(12, 16))
        val destination = InetAddress.getByAddress(packet.copyOfRange(16, 20))
        val ports = parsePorts(packet, length, headerLength, protocol)

        return PacketMetadata(
            ipVersion = 4,
            protocol = protocol,
            protocolName = protocolName(protocol),
            source = source,
            destination = destination,
            sourcePort = ports?.first,
            destinationPort = ports?.second
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int): PacketMetadata? {
        if (length < 40) return null
        val protocol = packet[6].toInt() and 0xFF
        val source = InetAddress.getByAddress(packet.copyOfRange(8, 24))
        val destination = InetAddress.getByAddress(packet.copyOfRange(24, 40))
        val ports = parsePorts(packet, length, 40, protocol)

        return PacketMetadata(
            ipVersion = 6,
            protocol = protocol,
            protocolName = protocolName(protocol),
            source = source,
            destination = destination,
            sourcePort = ports?.first,
            destinationPort = ports?.second
        )
    }

    private fun parsePorts(
        packet: ByteArray,
        length: Int,
        transportOffset: Int,
        protocol: Int
    ): Pair<Int, Int>? {
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return null
        if (length < transportOffset + 4) return null
        val sourcePort = unsignedShort(packet, transportOffset)
        val destinationPort = unsignedShort(packet, transportOffset + 2)
        return sourcePort to destinationPort
    }

    private fun unsignedShort(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or
            (packet[offset + 1].toInt() and 0xFF)

    private fun protocolName(protocol: Int): String = when (protocol) {
        IPPROTO_TCP -> "TCP"
        IPPROTO_UDP -> "UDP"
        1 -> "ICMP"
        58 -> "ICMPv6"
        else -> "IP/$protocol"
    }
}
