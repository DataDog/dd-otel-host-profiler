#! /usr/bin/env sh
set -e

# Wrapper to ensure debugfs is mounted

# Mount debugfs if not already mounted
if [ ! -d /sys/kernel/debug/tracing ]; then
    mount -t debugfs none /sys/kernel/debug
fi

exec "$@"
