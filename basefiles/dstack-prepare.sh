#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -e

CMDLINE=$(cat /proc/cmdline)

metadata_attr() {
	local key="$1"
	curl -fsS --connect-timeout 1 --max-time 2 \
		-H 'Metadata-Flavor: Google' \
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/${key}" \
		2>/dev/null || true
}

get_cmdline_value() {
	local key="$1"
	for param in $CMDLINE; do
		case "$param" in
			"$key="*)
				echo "${param#*=}"
				return 0
				;;
		esac
	done
	return 1
}

read_uevent_property() {
    local file="$1"
    local key="$2"
    while IFS='=' read -r name value; do
        if [ "$name" = "$key" ]; then
            printf "%s" "$value"
            return 0
        fi
    done < "$file"
    return 1
}

find_block_by_property() {
    local key="$1"
    local value="$2"
    for entry in /sys/class/block/*; do
        [ -e "$entry/uevent" ] || continue
        local current
        current=$(read_uevent_property "$entry/uevent" "$key" || true)
        if [ "$current" = "$value" ]; then
            printf "/dev/%s" "$(basename "$entry")"
            return 0
        fi
    done
    return 1
}

resolve_block_spec() {
    local spec="$1"
    local device=""
    case "$spec" in
    "")
        return 1
        ;;
    PARTLABEL=*)
        device=$(find_block_by_property PARTNAME "${spec#PARTLABEL=}" || true)
        if [ -z "$device" ]; then
            device=$(blkid -o device -l -t "$spec" 2>/dev/null | head -n1 || true)
        fi
        ;;
    PARTUUID=*)
        device=$(find_block_by_property PARTUUID "${spec#PARTUUID=}" || true)
        if [ -z "$device" ]; then
            device=$(blkid -o device -l -t "$spec" 2>/dev/null | head -n1 || true)
        fi
        ;;
    UUID=*|LABEL=*|ID=*)
        device=$(blkid -o device -l -t "$spec" 2>/dev/null | head -n1 || true)
        ;;
    /dev/*)
        device="$spec"
        ;;
    *)
        device="/dev/$spec"
        ;;
    esac
    if [ -n "$device" ] && [ -b "$device" ]; then
        printf "%s" "$device"
        return 0
    fi
    return 1
}

parent_block_device() {
	local path="$1"
	local name="${path#/dev/}"
	[ -n "$name" ] || return 1
	local sys_path
	sys_path=$(readlink -f "/sys/class/block/$name" 2>/dev/null || true)
	[ -n "$sys_path" ] || return 1
	local parent
	parent=$(basename "$(dirname "$sys_path")")
	if [ -n "$parent" ] && [ "$parent" != "$name" ] && [ -b "/dev/$parent" ]; then
		printf "/dev/%s" "$parent"
		return 0
	fi
	return 1
}

find_boot_disk() {
	local root_part
	root_part=$(resolve_block_spec "PARTLABEL=dstack-rootfs" || true)
	[ -n "$root_part" ] || return 1
	local parent
	parent=$(parent_block_device "$root_part" || true)
	if [ -n "$parent" ]; then
		echo "$parent"
		return 0
	fi
	case "$root_part" in
		/dev/nvme*)
			echo "${root_part%p*}"
			return 0
			;;
		/dev/*[0-9])
			echo "${root_part%[0-9]*}"
			return 0
			;;
	esac
	return 1
}

choose_data_device() {
	local override="$1"
	local dev=""
	if [ -n "$override" ]; then
		dev=$(resolve_block_spec "$override" || true)
		if [ -n "$dev" ]; then
			echo "$dev"
			return 0
		fi
		echo "Warning: dstack data device override '$override' not found" >&2
	fi
	local boot_disk
	boot_disk=$(find_boot_disk || true)
	for candidate in /dev/nvme*n[0-9] /dev/vd? /dev/sd?; do
		[ -b "$candidate" ] || continue
		if [ -n "$boot_disk" ] && [ "$candidate" = "$boot_disk" ]; then
			continue
		fi
		echo "$candidate"
		return 0
	done
	return 1
}

WORK_DIR="/var/volatile/dstack"
DATA_MNT="$WORK_DIR/persistent"

OVERLAY_TMP="/var/volatile/overlay"
OVERLAY_PERSIST="$DATA_MNT/overlay"

# Prepare volatile dirs
mount_overlay() {
    local src=$1
    local dst=$2/$1
    mkdir -p $dst/upper $dst/work
    mount -t overlay overlay -o lowerdir=$src,upperdir=$dst/upper,workdir=$dst/work $src
}
mount_overlay /etc/wireguard $OVERLAY_TMP
mount_overlay /etc/docker $OVERLAY_TMP
mount_overlay /usr/bin $OVERLAY_TMP
mount_overlay /home/root $OVERLAY_TMP

# Disable the containerd-shim-runc-v2 temporarily to prevent the containers from starting
# before docker compose removal orphans. It will be enabled in app-compose.sh
chmod -x /usr/bin/containerd-shim-runc-v2

# Make sure the system time is synchronized
echo "Syncing system time..."
# Let the chronyd correct the system time immediately
chronyc makestep

modprobe tdx-guest

# Setup dstack system
echo "Preparing dstack system..."
DATA_DEVICE_OVERRIDE=$(get_cmdline_value "dstack.data_dev" || true)
if [ -z "$DATA_DEVICE_OVERRIDE" ] && [ -n "$DSTACK_DATA_DEVICE" ]; then
	DATA_DEVICE_OVERRIDE="$DSTACK_DATA_DEVICE"
fi
DATA_DEVICE=$(choose_data_device "$DATA_DEVICE_OVERRIDE" || true)
if [ -z "$DATA_DEVICE" ]; then
	DATA_DEVICE=/dev/vdb
fi
if [ ! -b "$DATA_DEVICE" ]; then
	echo "Persistent data disk $DATA_DEVICE not found" >&2
	exit 1
fi
echo "Using persistent data disk $DATA_DEVICE"

if [ -z "${DSTACK_CONFIG_URL:-}" ]; then
	DSTACK_CONFIG_URL=$(metadata_attr "dstack-config-url")
fi
if [ -n "$DSTACK_CONFIG_URL" ]; then
	export DSTACK_CONFIG_URL
fi
if [ -z "${DSTACK_CONFIG_SHA256:-}" ]; then
	DSTACK_CONFIG_SHA256=$(metadata_attr "dstack-config-sha256")
fi
if [ -n "$DSTACK_CONFIG_SHA256" ]; then
	export DSTACK_CONFIG_SHA256
fi

dstack-util setup --work-dir $WORK_DIR --device "$DATA_DEVICE" --mount-point $DATA_MNT

echo "Mounting docker dirs to persistent storage"
# Mount docker dirs to DATA_MNT
mkdir -p $DATA_MNT/var/lib/docker
mount --rbind $DATA_MNT/var/lib/docker /var/lib/docker
mount --rbind $WORK_DIR /dstack
mount_overlay /etc/users $OVERLAY_PERSIST

cd /dstack

if [ $(jq 'has("init_script")' app-compose.json) == true ]; then
    echo "Running init script"
    dstack-util notify-host -e "boot.progress" -d "init-script" || true
    source <(jq -r '.init_script' app-compose.json)
fi
