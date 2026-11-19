#!/usr/bin/env bash
# bootstrap.sh — stage a USB stick for Skyworth HY00A ProductTest command lane
#
# Creates a FAT32 partition labelled STICK containing:
#   skyworth/autotest_command   (ProductTest auto-runs this on MEDIA_MOUNTED)
#   skyworth/bridge.apk         (com.omp.pwn persistent ADB bridge)
#   skyworth/pwn.apk            (stage-1 adb enabler)
#
# Usage:
#   sudo ./bootstrap.sh --dry-run /dev/sdX     # show plan, touch nothing
#   sudo ./bootstrap.sh --real     /dev/sdX    # DESTRUCTIVE: wipes partition table!
#
# The device arg is the WHOLE DISK (e.g. /dev/sdb), not a partition.
set -euo pipefail

MODE="${1:-}"; DEV="${2:-}"
[[ "$MODE" == "--dry-run" || "$MODE" == "--real" ]] || { echo "usage: $0 --dry-run|--real /dev/sdX"; exit 1; }
[[ -b "$DEV" ]] || { echo "error: $DEV is not a block device"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

part="$(lsblk -nrpo NAME "$DEV" | sed -n 2p)"        # first partition
[[ -n "$part" ]] || part="${DEV}1"

echo "== Plan ========================================"
echo "  disk:        $DEV"
echo "  partition:   $part  (will be created if missing)"
echo "  filesystem:  FAT32, label STICK"
echo "  staging:     skyworth/{autotest_command,bridge.apk,pwn.apk}"
echo "================================================"
[[ "$MODE" == "--dry-run" ]] && { echo "dry-run: exiting without changes"; exit 0; }

read -rp "About to ERASE ALL DATA on $DEV. Continue? [y/N] " ans
[[ "$ans" == "y" ]] || exit 1

# 1. Wipe + repartition: single partition spanning disk
sgdisk --zap-all "$DEV" 2>/dev/null || true
- parted -s "$DEV" mklabel msdos mkpart primary fat32 1MiB 100%
sync

# 2. Format FAT32 with STICK label
mkfs.vfat -F 32 -n STICK "$part"
sync

# 3. Mount + stage
MNT=$(mktemp -d)
mount "$part" "$MNT"
trap 'umount "$MNT" && rmdir "$MNT"' EXIT

mkdir -p "$MNT/skyworth"
printf '# v2 staged by bootstrap.sh\ninstall -s bridge.apk\nshowSystemInfo\n' \
    > "$MNT/skyworth/autotest_command"
cp "$SCRIPT_DIR/bridge.apk" "$SCRIPT_DIR/pwn.apk" "$MNT/skyworth/"

sync
echo "done. Stick staged:"
ls -la "$MNT/skyworth/"
# trap unmounts safely

echo
echo "NEXT STEPS ON THE BOX:"
echo "  1. Plug stick into the box, wait for MEDIA_MOUNTED (~10s)"
echo "  2. Watch: adb logcat -s SkwProductTest"
echo "  3. bridge.apk silently installs as uid-1000 -> unplug stick"
echo "  4. adb shell am start -n com.omp.pwn/.MainActivity"
