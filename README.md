# Sentinel Android v2

Native Android security/privacy monitoring app.

**Copyright © 2026 Kyle T. All Rights Reserved.**

This repository contains proprietary software. Unauthorized copying, modification, distribution, sublicensing, sale, reverse engineering, or commercial use is prohibited without the express written permission of the copyright owner.

## Alpha 0.3

Sentinel Alpha 0.3 combines the previously separate scanner and VPN prototypes into one installable Android app.

### On-device security scan

- Root indicator checks
- Debugger and emulator/environment checks
- Developer options and ADB status
- Secure lock-screen check
- Android security-patch age review
- Third-party accessibility-service review
- Notification-listener review
- Device-administrator review
- Installed user-app capability/permission combination scoring
- Build-profile fingerprint (SHA-256-derived build profile, not a hardware identifier)
- Severity-ranked findings and recommended actions
- Last-scan history and recent score trend
- Copy/export plain-text security report

### Local VPN / DNS firewall

- Android `VpnService` foreground service
- DNS-only tunnel for Alpha stability
- Monitor mode: observe DNS domains locally
- Firewall mode: block local rules using NXDOMAIN responses
- Reserved `.test` domains for safe firewall verification
- User-defined custom blocked domains stored locally
- Session DNS/blocked counters and recent-block history
- Protected upstream DNS socket to prevent VPN recursion

### Privacy / cost

- No Sentinel account required
- No cloud backend required
- No paid API required
- Scan findings and custom firewall rules are stored/processed on-device

## Important Alpha limitations

- The VPN currently routes DNS only. It is not yet a full TCP/UDP packet firewall.
- DNS traffic that bypasses the Android resolver (for example some app-controlled encrypted DNS/DoH implementations) may not be visible to this Alpha.
- App capability findings are risk signals, not proof that an app is malware.
- `QUERY_ALL_PACKAGES` is used because Sentinel is a security scanner; Play distribution will require the appropriate policy declaration/review.
- The GitHub Actions APK is a debug-signed test build, not a production release build.

## Build

```bash
./gradlew assembleDebug
```

Debug APK output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Package: `com.sentinel.security`
