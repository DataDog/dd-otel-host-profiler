#! /usr/bin/env sh
set -e

# Wrapper to ensure tracefs is mounted

# Mount tracefs if not already mounted
if [ ! -d /sys/kernel/tracing ]; then
    mount -t tracefs tracefs /sys/kernel/tracing
fi

exec "$@"
