/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.storage

import android.content.Context
import com.sentinel.security.scanner.ScanResult

data class ScanHistorySnapshot(
    val lastScanTime: Long,
    val lastScore: Int,
    val lastFindingCount: Int,
    val recentScores: List<Int>
)

object ScanHistory {
    private const val PREFS = "sentinel_scan_history"
    private const val KEY_LAST_TIME = "last_time"
    private const val KEY_LAST_SCORE = "last_score"
    private const val KEY_LAST_FINDINGS = "last_findings"
    private const val KEY_SCORES = "recent_scores"

    @Synchronized
    fun record(context: Context, result: ScanResult) {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val scores = p.getString(KEY_SCORES, "")
            .orEmpty()
            .split(',')
            .mapNotNull { it.toIntOrNull() }
            .toMutableList()
        scores.add(0, result.score)
        val recent = scores.take(7)

        p.edit()
            .putLong(KEY_LAST_TIME, result.timestamp)
            .putInt(KEY_LAST_SCORE, result.score)
            .putInt(KEY_LAST_FINDINGS, result.findings.size)
            .putString(KEY_SCORES, recent.joinToString(","))
            .apply()
    }

    fun snapshot(context: Context): ScanHistorySnapshot {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return ScanHistorySnapshot(
            lastScanTime = p.getLong(KEY_LAST_TIME, 0L),
            lastScore = p.getInt(KEY_LAST_SCORE, -1),
            lastFindingCount = p.getInt(KEY_LAST_FINDINGS, 0),
            recentScores = p.getString(KEY_SCORES, "")
                .orEmpty()
                .split(',')
                .mapNotNull { it.toIntOrNull() }
        )
    }
}
