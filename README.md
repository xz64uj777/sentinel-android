# Sentinel Android v2

Native Android security and privacy monitoring application.

Copyright © 2026 Kyle T. All Rights Reserved.

This repository contains proprietary software. Unauthorized copying, modification, distribution, sublicensing, sale, reverse engineering, or commercial use is prohibited without the express written permission of the copyright owner.

## Alpha 0.2 Test Build

- Root, debugger, and emulator checks
- Installed-app dangerous-permission scan
- Local security score
- Android `VpnService` permission and foreground service
- DNS-only local VPN that does not route normal app traffic into an unfinished tunnel
- Monitor mode with live DNS query counters
- Firewall mode with a local reserved-domain test blocklist
- On-device DNS forwarding to protected upstream resolvers
- Start/stop VPN controls and foreground notification
- No server, account, subscription, or paid API required

### Safe firewall test domains

The Alpha firewall only blocks reserved `.test` domains so development cannot accidentally block a real website:

- `malware.test`
- `phishing.test`
- `spyware.test`
- `tracker.test`

## Build requirements

- Android Studio with JDK 17 or newer configured for Gradle
- Android SDK 35
- Android Gradle Plugin 8.10.1
- Gradle 8.11.1

Package: `com.sentinel.security`

The GitHub Actions workflow builds `app-debug.apk` and bootstraps the Gradle 8.11.1 wrapper if the wrapper is missing.
