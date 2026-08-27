/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

object DnsPacketBuilder {
    fun buildResponse(request: ParsedDnsPacket, dnsResponse: ByteArray): ByteArray {
        val ipHeaderLength = 20
        val udpHeaderLength = 8
        val udpLength = udpHeaderLength + dnsResponse.size
        val totalLength = ipHeaderLength + udpLength
        val packet = ByteArray(totalLength)

        // IPv4 header.
        packet[0] = 0x45
        packet[1] = 0
        writeU16(packet, 2, totalLength)
        writeU16(packet, 4, 0)
        writeU16(packet, 6, 0)
        packet[8] = 64
        packet[9] = 17 // UDP
        packet[10] = 0
        packet[11] = 0

        request.destinationAddress.copyInto(packet, destinationOffset = 12)
        request.sourceAddress.copyInto(packet, destinationOffset = 16)

        val ipChecksum = checksum(packet, 0, ipHeaderLength)
        writeU16(packet, 10, ipChecksum)

        // UDP header.
        val udpOffset = ipHeaderLength
        writeU16(packet, udpOffset, request.destinationPort)
        writeU16(packet, udpOffset + 2, request.sourcePort)
        writeU16(packet, udpOffset + 4, udpLength)
        writeU16(packet, udpOffset + 6, 0)
        dnsResponse.copyInto(packet, destinationOffset = udpOffset + udpHeaderLength)

        var udpChecksum = udpChecksum(
            sourceAddress = request.destinationAddress,
            destinationAddress = request.sourceAddress,
            udpPacket = packet,
            udpOffset = udpOffset,
            udpLength = udpLength
        )
        if (udpChecksum == 0) udpChecksum = 0xFFFF
        writeU16(packet, udpOffset + 6, udpChecksum)

        return packet
    }

    private fun udpChecksum(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        udpPacket: ByteArray,
        udpOffset: Int,
        udpLength: Int
    ): Int {
        var sum = 0L

        sum += word(sourceAddress, 0)
        sum += word(sourceAddress, 2)
        sum += word(destinationAddress, 0)
        sum += word(destinationAddress, 2)
        sum += 17 // Protocol.
        sum += udpLength

        var index = 0
        while (index + 1 < udpLength) {
            sum += word(udpPacket, udpOffset + index)
            index += 2
        }
        if (index < udpLength) {
            sum += (udpPacket[udpOffset + index].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv().toInt() and 0xFFFF
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = 0
        while (index + 1 < length) {
            sum += word(data, offset + index)
            index += 2
        }
        if (index < length) {
            sum += (data[offset + index].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv().toInt() and 0xFFFF
    }

    private fun word(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun writeU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }
}
