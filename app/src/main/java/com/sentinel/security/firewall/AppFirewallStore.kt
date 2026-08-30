/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.firewall

import android.content.Context

object AppFirewallStore {
    private const val PREFS = "sentinel_app_firewall"
    private const val KEY_BLOCKED_PACKAGES = "blocked_packages"

    fun blockedPackages(context: Context): Set<String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(KEY_BLOCKED_PACKAGES, emptySet())
            ?.toSet()
            .orEmpty()

    fun setBlocked(context: Context, packageName: String, blocked: Boolean) {
        val updated = blockedPackages(context).toMutableSet()
        if (blocked) updated += packageName else updated -= packageName
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_BLOCKED_PACKAGES, updated)
            .apply()
    }

    fun replace(context: Context, packages: Set<String>) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_BLOCKED_PACKAGES, packages.toSet())
            .apply()
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_BLOCKED_PACKAGES)
            .apply()
    }
}
