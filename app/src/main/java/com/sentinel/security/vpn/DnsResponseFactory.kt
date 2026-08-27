/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

object DnsResponseFactory {
    fun nxDomain(query: ByteArray): ByteArray = errorResponse(query, rcode = 3)

    fun serverFailure(query: ByteArray): ByteArray = errorResponse(query, rcode = 2)

    private fun errorResponse(query: ByteArray, rcode: Int): ByteArray {
        if (query.size < 12) return query.copyOf()

        val questionEnd = findQuestionEnd(query)
        val response = query.copyOfRange(0, questionEnd)

        val requestFlags = ((query[2].toInt() and 0xFF) shl 8) or (query[3].toInt() and 0xFF)
        val responseFlags = 0x8000 or // QR = response
            (requestFlags and 0x0100) or // Preserve recursion desired.
            0x0080 or // Recursion available.
            (rcode and 0x000F)

        response[2] = ((responseFlags ushr 8) and 0xFF).toByte()
        response[3] = (responseFlags and 0xFF).toByte()

        // Keep QDCOUNT. Clear answer, authority, and additional counts.
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0

        return response
    }

    private fun findQuestionEnd(query: ByteArray): Int {
        var index = 12
        var safety = 0
        while (index < query.size && safety++ < 128) {
            val size = query[index].toInt() and 0xFF
            index += 1
            if (size == 0) {
                // QTYPE (2) + QCLASS (2), when available.
                return minOf(query.size, index + 4)
            }
            if ((size and 0xC0) != 0) {
                return minOf(query.size, index + 1 + 4)
            }
            if (size > 63 || index + size > query.size) return query.size
            index += size
        }
        return query.size
    }
}
