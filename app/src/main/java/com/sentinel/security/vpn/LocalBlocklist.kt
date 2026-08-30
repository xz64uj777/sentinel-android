/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

import android.content.Context

object LocalBlocklist {
    // Reserved .test domains are included so firewall behavior can be verified safely.
    private val builtInTestDomains = setOf(
        "malware.test",
        "phishing.test",
        "spyware.test",
        "tracker.test"
    )

    fun shouldBlock(context: Context, domain: String): Boolean {
        val normalized = domain.trimEnd('.').lowercase()
        val builtInMatch = builtInTestDomains.any { blocked ->
            normalized == blocked || normalized.endsWith(".$blocked")
        }
        return builtInMatch || CustomBlocklist.contains(context, normalized)
    }
}
