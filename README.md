# Sentinel Android v2

Native Android security and privacy control center.

Copyright © 2026 Kyle T. All Rights Reserved.

This repository contains proprietary software. Unauthorized copying, modification, distribution, sublicensing, sale, reverse engineering, or commercial use is prohibited without the express written permission of the copyright owner.

## Current build

`0.4.0-alpha`

Package: `com.sentinel.security`

## Alpha features

- Root, debugger, emulator/environment checks
- Developer options, ADB, secure-lock and security-patch review
- Installed-app capability/permission risk scoring
- Accessibility, overlay, notification-listener and device-admin review
- Local security score, scan history and text report export
- Device/build profile fingerprint
- DNS-only local VPN monitor
- Local DNS firewall with built-in safe `.test` rules
- User-defined local domain blocklist
- Per-app network firewall screen
- Hard IPv4/IPv6 network blocking for selected apps using Android `VpnService`
- Local blocked-packet/byte counters
- Recent blocked destination attempts with app attribution on Android 10+ when Android exposes the connection owner

## VPN modes

Sentinel currently has three local-VPN modes:

1. **Monitor** — observes DNS queries while ordinary app traffic stays outside the tunnel.
2. **DNS Firewall** — observes DNS and blocks matching domains.
3. **App Firewall** — routes only selected apps into a blocking TUN interface. Selected apps lose network access; unselected apps use the network normally.

Android permits only one active VPN per user, so selecting a different Sentinel VPN mode replaces the current one.

## Important Alpha limitation

The app firewall in 0.4 is a real hard network deny, but Sentinel does not yet contain a user-space TCP/UDP forwarding stack. That means it cannot yet transparently pass allowed full-tunnel traffic while inspecting every connection. Full-flow forwarding and richer per-app connection monitoring are the next networking milestone.

## Build

The project includes the Gradle wrapper. From Android Studio or a terminal:

```text
./gradlew :app:assembleDebug
```

GitHub Actions also builds and uploads a debug APK on every push to `main`.

## Privacy

Alpha scans, firewall rules, DNS counters, blocked-traffic counters, and reports are stored/processed on-device. No cloud account or paid API is required.
