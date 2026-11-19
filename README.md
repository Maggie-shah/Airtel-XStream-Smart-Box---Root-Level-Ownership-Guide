# Airtel XStream Smart Box — Root-Level Ownership Guide

**Target:** Skyworth HY00A ("Airtel XStream Smart Box"), MediaTek MT5751, Android 10 (kernel 4.19.84), user build `C10.5.0-20250818`, locked bootloader, `ro.adb.secure=1`, `ro.debuggable=0`

**Outcome:** Complete operator-control removal without warranty-breaking unlock:
network ADB (permanent, auto-auth), custom TV launcher as default HOME,
13 vendor/subscription packages removed, OTA updaters disabled, and a
system-uid (uid-1000) command-execution lane for anything deeper.

> Everything here works with the bootloader still **locked** and verified boot
> **green**. No flashing. No factory reset. Fully reversible.

---

## Table of Contents

1. [Discovery Summary](#1-discovery-summary)
2. [Hardware / Software Identified](#2-hardware--software-identified)
3. [Access Chain Overview](#3-access-chain-overview)
4. [Step-by-Step Reproduction](#4-step-by-step-reproduction)
   - [Step 1 — Physical / Serial Setup](#step-1--physical--serial-setup)
   - [Step 2 — Enable Network ADB via Vendor Broadcast](#step-2--enable-network-adb-via-vendor-broadcast)
   - [Step 3 — Stable ADB Control from Host](#step-3--stable-adb-control-from-host)
   - [Step 4 — Seed ADB Public Key (no-dialog auth)](#step-4--seed-adb-public-key-no-dialog-auth)
   - [Step 5 — Build & Install the Privilege App](#step-5--build--install-the-privilege-app)
   - [Step 6 — Debloat: Remove Operator Packages](#step-6--debloat-remove-operator-packages)
   - [Step 7 — Custom TV Launcher (HOME role)](#step-7--custom-tv-launcher-home-role)
   - [Step 8 — Disable OTA Updaters](#step-8--disable-ota-updaters)
   - [Step 9 — ProductTest USB Command Lane (uid-1000)](#step-9--producttest-usb-command-lane-uid-1000)
5. [Reverse-Engineering Notes](#5-reverse-engineering-notes)
   - [File-by-File Artifact Reference](#file-by-file-artifact-reference)
   - [Skyworth SysCTL Surface](#skyworth-sysctl-surface)
   - [ProductTest Autotest Grammar](#producttest-autotest-grammar)
   - [ISysCtl HAL Transactions](#isysctl-hal-transactions)
6. [Verification Matrix](#6-verification-matrix)
7. [Troubleshooting](#7-troubleshooting)
8. [Safety & Recovery](#8-safety--recovery)
9. [Credits](#9-credits)

---

## 1. Discovery Summary

| Technique | Result |
|---|---|
| Vendor broadcast abuse | Skyworth exposes `com.skyworth.sysctl.action.ENABLE_ADB` — any app holding `com.skyworth.sysctl.permission.broadcast` can trigger system-side ADB enable |
| Hand-crafted APK | Built a minimal APK with **no Android SDK toolchain** (pure-Python AXML encoder, hand-packed dex 035, JAR/v1 signing with `openssl cms`), because aapt/apksigner weren't available |
| Network ADB persistence | Persisted via `persist.sys.adb.enabled=true` + `persist.sys.usb.config=adb` + re-broadcasting receiver at BOOT_COMPLETED |
| Debloat | `pm uninstall --user 0` against operator/subscription packages |
| Custom launcher | Sideloaded open-source launchers, set via `cmd role add-role-holder android.app.role.HOME` |
| OTA freeze | `pm disable-user` on both updater apps |
| uid-1000 escape hatch | Reverse-engineered Skyworth's **SkyProductTest** factory app and its USB-stick command file format (`skyworth/autotest_command`) |
| Dead ends (documented for future researchers) | ISysCtl HAL `run(id,…)` is getters-only (transactions 1–9); `iperf` service referenced but never defined; `/proc/utopia*` system-only; no fastboot binary on device |

## 2. Hardware / Software Identified

```
Model:        XStream-Smart-Box-002
Device:       HY00A (Skyworth)
SoC:          MediaTek MT5751 (MStar-derived platform)
Android:      10 (API 29), kernel 4.19.84
Build:        C10.5.0-20250818 (user, release-keys)
Security:     SELinux enforcing; patchlevel 2025-07-01
Slots:        A/B (active: _b)
Partitions:   MBOOT, MBOOTBAK, boot_a/b, dtbo_a/b, vbmeta_a/b,
              super, tvconfig_a/b, tvservice_a/b, upgrade_a/b,
              optee(+bak), tvcertificate, metadata, misc, userdata
Bootloader:   MBOOT (MStar U-Boot derivative), locked, verified boot green
Outputs:      HDMI (with ARC), optical S/PDIF, AV, Ethernet (10/100)
UART:         3.3V TTL, 115200 8N1, accessible via bottom vents
```

## 3. Access Chain Overview

```
[Serial UART]  (or blind initial state)
     │  console:/ $ prompt
     ▼
[Fire vendor broadcast] am start / am broadcast
     │  SysCtlBroadcastReceiver (uid 1000)
     ▼
[Sysctl flag + props]
     │  /vendor/tvcertificate/skflag + persist.sys.adb.enabled
     ▼
[adbd on TCP :5555]
     │  auto-auth via adb_keys seeded in settings
     ▼
[FULL NETWORK ADB] ◄────────────┐
     │                          │
     ├─ pm uninstall/disable    │  (loop: any drift
     ├─ cmd role (HOME)         │   re-fired by
     ├─ am start / am broadcast │   PwnReceiver at
     └─ sideload launchers/APKs ┘   every boot)
          
[Optional deeper lane]
     USB stick (FAT32) → skyworth/autotest_command
     → SkyProductTest (uid 1000) parses + executes
     → install / runApp / startHttpServer / etc.
```

## 4. Step-by-Step Reproduction

### Step 1 — Physical / Serial Setup

Open the enclosure (Torx screws under rubber feet), locate the 4-pad UART header
near the PSU shield, and connect a 3.3V USB-UART bridge:

| Pad | Signal |
|---|---|
| 1 | GND |
| 2 | RX (to your FTDI TX) |
| 3 | TX (to your FTDI RX) |
| 4 | 3.3V (optional; untested pinouts vary) |

```
picocom -b 115200 /dev/ttyUSB0
# Press Enter — expect: console:/ $
```

**Serial troubleshooting:**
- If the shell goes silent, send a burst of `\n` characters — this almost always
  unwedges the `mksh` prompt.
- Do **not** use DTR ioctl from Python's `pyserial` on this adaptor — it throws
  `errno 5 (EIO)`. Use `os.open('/dev/ttyUSB0', os.O_RDWR|os.O_NOCTTY)` with raw
  `termios` if scripting.
- Avoid running serial + ADB concurrently for long stretches — adbd connection
  churn can re-trigger on-screen pairing dialogs.

### Step 2 — Enable Network ADB via Vendor Broadcast

Skyworth ships a helper broadcast receiver owned by system:

```bash
# from serial shell (or adb shell once auth'd)
am broadcast -a com.skyworth.sysctl.action.ENABLE_ADB \
             --es status true \
             -p com.skyworth.sysctl.provider
```

Effect:
1. Creates `/vendor/tvcertificate/skflag/` + `enable_adb_flag`
2. Sets `persist.sys.adb.enabled=true` and `persist.sys.usb.config=adb`
3. Starts `adbd` listening on **all interfaces:5555**

> The receiver holds `com.skyworth.sysctl.permission.broadcast`
> (`protectionLevel=normal`), so **any** third-party app can declare that
> permission and fire this same broadcast — this becomes important in Step 5.

Network prerequisite: the box's Ethernet must be on the same subnet as the host
(the box DHCPs; host side was served by dnsmasq on `10.42.0.0/24` for this test).

### Step 3 — Stable ADB Control from Host

Wi-Fi pairing dialogs pop on every new connection. The author uses the
`adb_shell` Python library, which connects + auths cleanly, on a persistent
single connection to avoid popup spam:

```python
# acmd2.py — resilient one-shot ADB runner
from adb_shell.adb_device import AdbDeviceTcp
import adb_shell.auth.sign_pythonrsa as signmod

signer = signmod.PythonRSASigner(
    open('/home/user/.android/adbkey.pub').read().strip(),
    open('/home/user/.android/adbkey.pk8').read())
d = AdbDeviceTcp('10.42.0.55', 5555)     # <-- your box IP
d.connect(rsa_keys=[signer], auth_timeout_s=20)
d.shell('id')
```

**Handshake pitfall (cost hours):** when crafting raw `CNXN` frames, the wire
command is the **ASCII of the literal string, little-endian u32** — i.e.,
`CNXN = 0x4E584E43` (not the byte-string `'CNXY'` style guesses used by some
snippets circulating online). Magic is `command ^ 0xFFFFFFFF`; checksum is a
simple byte-sum of the payload; payload must be NUL-terminated
(`host::<name>\x00`).

### Step 4 — Seed ADB Public Key (no-dialog auth)

Rather than clicking the on-screen "Allow USB debugging?" (annoying on a box
whose dialogs eat themselves), the framework exposes:

```bash
# Read your existing ~/.android/adbkey.pub, strip the trailing user@host comment,
# and inject it via the settings table:
settings put global adb_keys "$(cat ~/.android/adbkey.pub)"
```

Thereafter `AdbDeviceTcp` connects silently. Android *also* pops the dialog on
some vendor builds — clicking "Always allow" once reduces noise; not strictly
needed for `adb_shell` to succeed once the key is in the settings table.

### Step 5 — Build & Install the Privilege App

`com.omp.pwn` is a **~3 KB APK with zero Android SDK tooling**, built by:

| Artifact | Role |
|---|---|
| `axml2.py` | Pure-Python **binary AXML encoder**. Emits a valid compiled `AndroidManifest.xml`. String-pool header `<HHIIIIII` (6 I-fields incl. `stylesStart`); UTF-16 pool strings with u16 length prefixes; attribute records `<iii ns/name/raw` + `<HBBI (size=8,res0=0,type,data)`. Validated roundtrip through androguard. |
| `dexgen.py` | Hand-packs a **dex 035** containing `com.omp.pwn.MainActivity` with a tiny `onCreate(B)` that allocates an `Intent(action)`, sets package `com.skyworth.sysctl.provider`, adds `status=true` extra, and calls `sendBroadcast`. Two-pass layout: `build_class_data(code_base)` must run after `layout()` because uleb code offsets embed **absolute file offsets**. |
| `dexgen_bridge.py` | Extended generator producing two classes: `MainActivity` + `PwnReceiver` (a `BroadcastReceiver` listening on `BOOT_COMPLETED` and `ENABLE_ADB` to keep ADB re-enabled after every boot). |
| `build_apk.py` / `build_bridge.py` | Zips `AndroidManifest.xml` + `classes.dex` and applies **v1 (JAR) signing**. PKCS7 notes: current `cryptography` emits `SMIMECapability` in authenticated attrs which Android's JarVerifier rejects (`toDerInputStream rejects tag type -96`). Building through **`openssl cms -sign -binary -nodetach -noattr`** produces an accepted signature; CERT.SF must contain **per-entry `Name:` sections** plus the whole-manifest digest. |

Install & fire:

```bash
adb install bridge.apk
adb shell am start -n com.omp.pwn/.MainActivity      # fires ENABLE_ADB as uid-1000
```

Post-reboot behavior: `PwnReceiver` catches `BOOT_COMPLETED` and re-fires
`ENABLE_ADB`, restoring ADB even if the vendor drifts the property.

### Step 6 — Debloat: Remove Operator Packages

Confirmed-safe removals (`adb shell`):

```bash
PM_UNINSTALL=(
  com.irdeto.tvinput                     # conditional access / DRM
  com.tataelxsi.icx                      # operator middleware client
  com.airtel.tv                          # operator TV app
  tv.airtel.xstream.tvapp                # XStream subscription hub
  com.glance.tv.screensaver              # ad-driven screensaver
  com.uei.uas.airtel                     # remote-telemetry agent
  com.airtel.fti                         # factory telemetry
  com.skyworthdigital.frontpanelledsservice
  com.skyworthdigital.airtelbtservice
  com.skyworth.udiskreceiver
  com.mstar.nfxservice
  in.startv.hotstar
  com.shemaroo.shemarootv
  com.eros.now
  com.esaba.downloader
)
for p in "${PM_UNINSTALL[@]}"; do
  adb shell "pm uninstall --user 0 $p"
done
```

**Do NOT remove:**

| Package | Why to keep |
|---|---|
| `com.skyworth.sysctl.provider` | Owns the `ENABLE_ADB` receiver we depend on |
| `com.skyworthdigital.airtel.producttest` | Future root bridge — see Step 9 |
| `com.mstar.stbsetting` | Your on-screen Settings UI (audio modes, HDMI-CEC, etc.) |
| `com.android.tv.settings` | AOSP TV settings; complements Mstar one |
| `com.google.android.*` core + `com.android.systemui` | Platform plumbing |

Result: package count **107 → 94**.

### Step 7 — Custom TV Launcher (HOME role)

The box ships **no stock launcher at all** (that's why `resolve-activity -c
HOME` returns nothing — its "home" is a vendor framework stub).

Pick your flavour:

| Launcher | Package | Comment |
|---|---|---|
| **Arc Launcher** | `com.omeda.arc` | Modern UI, rich customization |
| **FLauncher** | `me.efesser.flauncher` | Lightweight FOSS |

```bash
adb install arc-launcher-1.2.2.apk        # or FLauncher apk
# Grant HOME role:
adb shell cmd role add-role-holder android.app.role.HOME com.omeda.arc
# Verify:
adb shell "dumpsys role | grep -A3 'android.app.role.HOME'"
# Force to foreground:
adb shell am start -a android.intent.action.MAIN -c android.intent.category.HOME
```

Swap back anytime by re-running `add-role-holder` with the other package.

### Step 8 — Disable OTA Updaters

Protects your work from vendor push-back:

```bash
adb shell pm disable-user --user 0 com.skw.ota.update
adb shell pm disable-user --user 0 com.apps.updater
# Re-enable later (undo):
adb shell pm enable com.skw.ota.update
```

Verified via `enabled=3` (`DISABLED_USER`) in `dumpsys package`.

### Step 10 — QoL Hardening (Private DNS, ads, OTA fence)

```bash
# Box-wide ad/tracker filtering — no app required:
adb shell settings put global private_dns_mode hostname
adb shell settings put global private_dns_specifier dns.adguard.com

# Silence the recommendations/home-row ads service:
adb shell pm disable-user --user 0 com.google.android.tvrecommendations

# Bridge v2 (bridge.apk in this repo) declares WRITE_SECURE_SETTINGS;
# grant it after install so the receiver can self-heal settings:
adb shell pm grant com.omp.pwn android.permission.WRITE_SECURE_SETTINGS
```

Notes:
- `private_dns_mode=hostname` + specifier survives reboots; AdGuard DoT resolves
  ads away for **every** app including Netlix banners and launcher widgets.
- Signing key stability: `build_bridge.py` persists `pwn_testkey.pem` /
  `pwn_cert.der`; rebuilding no longer rotates the package signature (which
  would force `pm uninstall` before reinstall).
- The signing key files and the derived `.der` are gitignored — generate your
  own; don't ship keys.

### Step 11 — ProductTest USB Command Lane (uid-1000)

Skyworth's factory test app (`SkyProductTest`, uid **1000**, runs under
`android.uid.system` shared UID) processes a plaintext command file from any
mounted USB drive:

```
📁 USB stick (FAT32) root
└── 📁 skyworth
    └── 📄 autotest_command
```

Minimal `autotest_command` to pop the factory HTTP command server:

```
startHttpServer
```

Supported verbs (reverse-engineered from `classes.dex`):

| Verb | Args / Effect |
|---|---|
| `install [-s] <apk>` | Silent-installs any APK sitting in `skyworth/` as **uid 1000** |
| `runApp <component>` | Launches any activity, even non-exported ones |
| `startHttpServer` | Starts NanoHTTPD on **:8088**, exposing a JSON command runner |
| `update <-o\|-n\|-l\|-c>` | Triggers OTA |
| `ethernet static <ip> <netmask> ...` / `ethernet false` | Configure or DHCP ethernet |
| `wlan <ssid> <pwd>` | Join Wi-Fi |
| `iperf start\|stop` | Perf test |
| `logcat start\|stop [index]` | Dump logcat to file |
| `write <keyName> <content> [hash]` | Provision device keys (hdcp / widevine / attestation) |
| `provision <keyType> ...` | Bulk key provisioning |
| `showSN` / `showSystemInfo` / `showImage <img>` | On-screen panels |
| `rcuTest` / `checkKeyStatus` / `presetCerts` / `STBInfoReport` | Various diagnostics |
| `reset_system` | ☣ Factory reset — **do not fire casually** |

Lines beginning with `#` are comments. Errors and success print to `logcat`
(tag `SkwProductTest`).

**Caution:** `MEDIA_MOUNTED` is a protected broadcast — you can't trigger the
receiver manually without the stick. Once the stick is unplugged the HttpServer
goes down too. For a persistent, no-stick lane, use the stick once to
`install -s bridge.apk` and rely on `PwnReceiver` + adb to operate afterward.

## 5. Reverse-Engineering Notes

### File-by-File Artifact Reference

| File | Purpose | Format / Trivia |
|---|---|---|
| `axml2.py` | Binary AXML encoder | 6-field string-pool header; attribute records use `<HBBI`; validates via androguard roundtrip |
| `dexgen.py` | Single-class dex 035 builder | Hand-packed strings / types / protos / methods / code / map sections; two-pass layout required for uleb-abs-offsets |
| `dexgen_bridge.py` | Two-class dex builder | Adds `PwnReceiver` `BroadcastReceiver`; shares Intent-firing logic with `MainActivity` |
| `build_apk.py` | Builds `pwn.apk` (activity-only) | Pure-python ZIP + JAR v1 signing |
| `build_bridge.py` | Builds `bridge.apk` (activity + receiver) | Signs via `openssl cms -sign -binary -nodetach -noattr` because modern `cryptography` inserts a forbidden `SMIMECapability` attribute |
| `acmd2.py` | Resilient ADB one-shot runner | Wraps `adb_shell` with reconnect/backoff |
| `pwn.apk` | Stage-1 helper app | Fires `ENABLE_ADB` as uid-1000 on demand |
| `bridge.apk` | Stage-2 persistent helper | Above, plus BOOT_COMPLETED receiver; survives reboots |
| `SkyProductTest.apk` | Pulled from device | Source of the USB-command grammar + uid-1000 installation path |

### Skyworth SysCTL Surface

- `SysCtlBroadcastReceiver` accepts actions:
  `ENABLE_ADB`, `ENABLE_FORCESTOP`,
  `ENABLE_CLEARDATA_UNINSTALL`, `MASTER_RESET` ☣
- Shell exec via `SysCtl.runShellCommand(String)` is **hardcoded** —
  `mkdir/touch/rm` only on flags, no injection.
- Binder: `vendor.skyworth.hardware.sysctl@1.0::ISysCtl/default`
  (service runs as **user system**)
- Content provider: `content://com.skyworth.sysctl.provider.SysCtl` with
  cpu_temperature / cpu_load_average / cpu_usage / tuner_lock_status / adb_status …

### ProductTest Autotest Grammar

Dispatched from `CmdManager.readCommand` → keyword → `CmdBase` subclass `parse()`:

- `CmdInstall` scans `skyworth/` and feeds each `.apk` to `LogicApkManager.installAPK`
- `CmdHttpCmd` instantiates `LogicHttpCmd` → `AutomatedProduceManager` → NanoHTTPD `HttpServer(8088)`
- Logs are tagged `SkwProductTest` (`LogUtils.i/e`); the App's `<application>`
  uses `android.uid.system` shared UID; activities are non-exported but
  launchable via `runApp`-style factory chain.
- `MEDIA_MOUNTED` (protected) is the only stick trigger; you can't replay it
  manually from shell without the corresponding `system` uid.

### ISysCtl HAL Transactions

Probed via hand-crafted HIDL binder reflection (`HalProbe` concept in the
write-up; a reflection-based payload avoiding hidden APIs):

| Tx ID | Return | Notes |
|---|---|---|
| 1–7 | ✅ 24–152 B | Display caps, EDID dump, HDMI HDCP status |
| 8 | 0x35 = 53 °C | CPU sensor |
| 9 | 4 B | Tuner info |
| ≥ 10 | RET=1, LEN=0 | **Rejected** — no exec primitives |

Conclusion: this HAL is read-only and not a root vector; **escalation goes
through ProductTest's uid-1000 surface instead**.

## 6. Verification Matrix

| Check | Before | After | Proof |
|---|---|---|---|
| Package count | 107 | 94 | `pm list packages \| wc -l` |
| Subscription apps | installed | gone | `pm list packages \| grep airtel` → only `producttest` remains |
| HOME role | unset / stub | `com.omeda.arc` | `dumpsys role` |
| OTA updaters | enabled | `enabled=3` | `dumpsys package` |
| Private DNS | unset | `dns.adguard.com` (mode `hostname`) | `settings get global private_dns_*` |
| Home-row ads (`tvrecommendations`) | enabled | `disabled-user` | `pm list packages -d` |
| ADB on TCP | off | `:5555 LISTEN`, auto-auth | `netstat -tln` |
| Post-reboot ADB | n/a | auto-restored | `getprop init.svc.adbd` → `running` |
| Bridge permissions | base | `WRITE_SECURE_SETTINGS` granted | `dumpsys package com.omp.pwn` |
| uid-1000 exec | unused | stick-driven | `logcat` `SkwProductTest` entries |

## 7. Troubleshooting

- **Serial console wedge**: bursts of `\n` at 115200. Avoid DTR ioctl.
- **adbd hangs on `:5555` after long sessions**: cooldown 45 s or reboot; adbd
  recovers automatically.
- **Connection storms triggering on-screen dialog spam**: reuse a single
  `AdbDeviceTcp` for multiple commands; avoid churn from freshly spawned
  connections.
- **APK rejected — "PKCS9 SMIMECapability attribute not supported"**: your
  signing library emits a forbidden authenticated attribute. Sign with
  `openssl cms -sign -binary -nodetach -noattr` instead, and ensure your
  `CERT.SF` contains per-entry `Name:` blocks.
 - **APK rejected — "no certificates at entry AndroidManifest.xml"**: your
   `CERT.SF` per-entry digests are missing; regenerate with per-entry sections
   in addition to `SHA-256-Digest-Manifest`.
- **`pm uninstall` times out occasionally**: adbd gets flaky after heavy PM
  activity — wait ~45 s or reboot.

## 8. Safety & Recovery

- **Never fire `MASTER_RESET`** (factory reset) unless you intend to wipe.
- Never `pm uninstall` `com.skyworth.sysctl.provider` — it owns your ADB trigger.
- If HOME breaks after a vendor quirk, re-run:
  `adb shell cmd role add-role-holder android.app.role.HOME com.omeda.arc`.
- If ADB ever locks out, plug the UART lane and re-fire `ENABLE_ADB` manually
  (Step 2), or temporarily reinstall `pwn.apk` via the USB lane.

## 9. Credits

- **Arc Launcher** (`com.omeda.arc`) — a beautiful, actively developed TV
  launcher by **meddouribadis**.
  Repo: <https://github.com/meddouribadis/arclauncher> — used here as the
  default HOME after debloating.
- **FLauncher** (`me.efesser.flauncher`) — lightweight, privacy-friendly,
  FOSS alternative.
  Repo: <https://gitlab.com/flauncher/flauncher>
- **adb_shell** Python library — MIT-licensed ADB protocol implementation in
  pure Python: <https://github.com/adakar1/adb_shell>
- **androguard** — DEX/APK introspection toolkit used for all binary analysis:
  <https://github.com/androguard/androguard>
- **r8 / D8** — Google's dexer used for compiled bridge payloads:
  <https://r8.googlesource.com/r8>
- Community mirrors of operator-debloat knowledge, notably
  `sideload-jiostb` for Jio STB parity techniques.

---

*Written from a fully authenticated, confirmed-working session on 2026-11-19.*
*All commands verified on build `C10.5.0-20250818`, kernel `4.19.84`, HY00A.*

---

## 10. Appendix: MBOOT UART Hunt (negative results, documented)

Multiple controlled attempts were made to reach an interactive MBOOT shell:

- **Method:** 3.3V UART @115200 8N1; key-interrupt spraying at 500 ms cadence
  across `Enter`, `CR`, `ESC`, `Space`, `x`, `Ctrl-C`, `c`, `a`, started at
  power-plug and continuing 150 s
- **Result:** the boot ROM → CALDR → LZMA-U-Boot chain produces **no
  `Hit any key to stop autoboot` banner**; keystrokes appear only in the
  booted Android `sh` (`console:/ $`), i.e. autoboot delay is effectively **0**
  and no early-escape hook was found
- **Block device access:** `/dev/block/by-name/MBOOT` → `Permission denied`
  from `shell` uid; `run-as` unusable on non-debuggable packages
- **SELinux contexts:** `/vendor/tvcertificate/skflag/` is
  `system:system 0700 (tv_certificate_file)`; world-writable DAC bits on
  `/vendor/tvcertificate` are overridden by enforcement — no shell-uid write
  primitive available there

**Conclusion:** unlocking the bootloader on HY00A requires either a
hardware strap/test-point combo, an unlocked vendor firmware leak, or a
still-undiscovered MBOOT key sequence. UART remains invaluable for rescue
(OS console always answers). True uid-0 on this hardware is therefore parked
until one of the above surfaces.

**Boot animation:** `/system/media/bootanimation.zip` (9.8 MB) — replacement
requires `/system` write, i.e. the unlock above. Deferred until then.

---

*Rev 2 (2026-11-19): added QoL hardening step (Private DNS / ads / bridge
grant), stable signing keys, bootstrap.sh stick maker, MIT license, and the
MBOOT UART appendix. Verified end-to-end on build `C10.5.0-20250818`.*
