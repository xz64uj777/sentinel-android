/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.vpn

import android.content.Context

object VpnPreferences {
    private const val PREFS = "sentinel_vpn_state"
    private const val KEY_RUNNING = "running"
    private const val KEY_MODE = "mode"
    private const val KEY_DNS_QUERIES = "dns_queries"
    private const val KEY_BLOCKED = "blocked"
    private const val KEY_LAST_DOMAIN = "last_domain"
    private const val KEY_RECENT_BLOCKS = "recent_blocks"

    fun isRunning(context: Context): Boolean = prefs(context).getBoolean(KEY_RUNNING, false)

    fun setRunning(context: Context, running: Boolean) {
        prefs(context).edit().putBoolean(KEY_RUNNING, running).apply()
    }

    fun mode(context: Context): VpnMode {
        val stored = prefs(context).getString(KEY_MODE, VpnMode.MONITOR.name)
        return runCatching { VpnMode.valueOf(stored ?: VpnMode.MONITOR.name) }
            .getOrDefault(VpnMode.MONITOR)
    }

    fun setMode(context: Context, mode: VpnMode) {
        prefs(context).edit().putString(KEY_MODE, mode.name).apply()
    }

    fun resetSessionCounters(context: Context) {
        prefs(context).edit()
            .putLong(KEY_DNS_QUERIES, 0)
            .putLong(KEY_BLOCKED, 0)
            .putString(KEY_LAST_DOMAIN, "")
            .putString(KEY_RECENT_BLOCKS, "")
            .apply()
    }

    @Synchronized
    fun recordDns(context: Context, domain: String, blocked: Boolean) {
        val p = prefs(context)
        val dnsCount = p.getLong(KEY_DNS_QUERIES, 0) + 1
        val blockedCount = p.getLong(KEY_BLOCKED, 0) + if (blocked) 1 else 0
        val editor = p.edit()
            .putLong(KEY_DNS_QUERIES, dnsCount)
            .putLong(KEY_BLOCKED, blockedCount)
            .putString(KEY_LAST_DOMAIN, domain)

        if (blocked) {
            val recent = recentBlocked(context).toMutableList()
            recent.remove(domain)
            recent.add(0, domain)
            editor.putString(KEY_RECENT_BLOCKS, recent.take(8).joinToString("|||"))
        }
        editor.apply()
    }

    fun dnsQueries(context: Context): Long = prefs(context).getLong(KEY_DNS_QUERIES, 0)

    fun blocked(context: Context): Long = prefs(context).getLong(KEY_BLOCKED, 0)

    fun lastDomain(context: Context): String = prefs(context).getString(KEY_LAST_DOMAIN, "") ?: ""

    fun recentBlocked(context: Context): List<String> = prefs(context)
        .getString(KEY_RECENT_BLOCKS, "")
        .orEmpty()
        .split("|||")
        .map { it.trim() }
        .filter { it.isNotEmpty() }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
