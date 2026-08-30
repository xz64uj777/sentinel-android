/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

import android.content.Context

object CustomBlocklist {
    private const val PREFS = "sentinel_custom_blocklist"
    private const val KEY_DOMAINS = "domains"

    fun all(context: Context): List<String> =
        prefs(context).getStringSet(KEY_DOMAINS, emptySet())
            .orEmpty()
            .map { normalize(it) }
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()

    @Synchronized
    fun add(context: Context, domain: String): Boolean {
        val normalized = normalize(domain)
        if (!isValidDomain(normalized)) return false
        val domains = all(context).toMutableSet()
        domains += normalized
        prefs(context).edit().putStringSet(KEY_DOMAINS, domains).apply()
        return true
    }

    @Synchronized
    fun remove(context: Context, domain: String) {
        val normalized = normalize(domain)
        val domains = all(context).toMutableSet()
        domains.remove(normalized)
        prefs(context).edit().putStringSet(KEY_DOMAINS, domains).apply()
    }

    fun clear(context: Context) {
        prefs(context).edit().remove(KEY_DOMAINS).apply()
    }

    fun contains(context: Context, domain: String): Boolean {
        val normalized = normalize(domain)
        return all(context).any { blocked ->
            normalized == blocked || normalized.endsWith(".$blocked")
        }
    }

    fun normalize(input: String): String = input
        .trim()
        .lowercase()
        .removePrefix("https://")
        .removePrefix("http://")
        .substringBefore('/')
        .substringBefore(':')
        .trim('.')

    fun isValidDomain(domain: String): Boolean {
        if (domain.length !in 3..253) return false
        if (!domain.contains('.')) return false
        val labels = domain.split('.')
        return labels.all { label ->
            label.isNotEmpty() &&
                label.length <= 63 &&
                label.first() != '-' &&
                label.last() != '-' &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
