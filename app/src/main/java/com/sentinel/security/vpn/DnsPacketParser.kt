/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

data class ParsedDnsPacket(
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val dnsPayload: ByteArray,
    val domain: String
)

object DnsPacketParser {
    fun parse(packet: ByteArray, length: Int): ParsedDnsPacket? {
        if (length < 40) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (ipHeaderLength < 20 || length < ipHeaderLength + 8) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null // UDP only in Alpha DNS proxy.

        val udpOffset = ipHeaderLength
        val sourcePort = readU16(packet, udpOffset)
        val destinationPort = readU16(packet, udpOffset + 2)
        if (destinationPort != 53) return null

        val udpLength = readU16(packet, udpOffset + 4)
        if (udpLength < 8) return null

        val dnsOffset = udpOffset + 8
        val availableDnsLength = length - dnsOffset
        val declaredDnsLength = udpLength - 8
        val dnsLength = minOf(availableDnsLength, declaredDnsLength)
        if (dnsLength < 12) return null

        val dnsPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val domain = parseQuestionName(dnsPayload) ?: return null

        return ParsedDnsPacket(
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsPayload = dnsPayload,
            domain = domain
        )
    }

    private fun parseQuestionName(dns: ByteArray): String? {
        if (dns.size < 13) return null
        val labels = mutableListOf<String>()
        var index = 12
        var safety = 0

        while (index < dns.size && safety++ < 128) {
            val labelLength = dns[index].toInt() and 0xFF
            index += 1
            if (labelLength == 0) break
            if ((labelLength and 0xC0) != 0) return null // Compression is not expected in client questions.
            if (labelLength > 63 || index + labelLength > dns.size) return null

            val label = dns.copyOfRange(index, index + labelLength)
                .toString(Charsets.UTF_8)
            if (label.isBlank()) return null
            labels += label
            index += labelLength
        }

        return labels.takeIf { it.isNotEmpty() }?.joinToString(".")
    }

    private fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
}
