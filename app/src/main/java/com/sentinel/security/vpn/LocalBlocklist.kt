/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

object LocalBlocklist {
    // Reserved .test domains are intentionally used so Alpha testing never blocks a real site.
    private val blockedDomains = setOf(
        "malware.test",
        "phishing.test",
        "spyware.test",
        "tracker.test"
    )

    fun shouldBlock(domain: String): Boolean {
        val normalized = domain.trimEnd('.').lowercase()
        return blockedDomains.any { blocked ->
            normalized == blocked || normalized.endsWith(".$blocked")
        }
    }
}
