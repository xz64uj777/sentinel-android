/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.model

enum class Severity(val scorePenalty: Int) {
    INFO(0),
    LOW(2),
    MEDIUM(6),
    HIGH(12),
    CRITICAL(25)
}

data class SecurityFinding(
    val title: String,
    val description: String,
    val severity: Severity,
    val category: String,
    val recommendation: String
) {
    fun displayLine(): String = "[${severity.name}] $title — $description"
}
