/* Sentinel Android v2 | Copyright (c) 2026 Kyle T. | All Rights Reserved. */
package com.sentinel.security.scanner

import android.os.Debug

object DebugDetector {
    fun isDebuggerAttached(): Boolean = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
}
