#! /usr/bin/env sh
set -e

# Wrapper to ensure tracefs is mounted

# Mount tracefs if not already mounted
mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing

exec "$@"
