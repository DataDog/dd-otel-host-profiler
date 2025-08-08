#! /usr/bin/env sh
set -e

DD_API_KEY="$(sudo cat /run/secrets/dd-api-key)"
DD_APP_KEY="$(sudo cat /run/secrets/dd-app-key)"
export DD_API_KEY DD_APP_KEY

if [ ! -d /sys/kernel/debug/tracing ]; then
    sudo mount -t debugfs none /sys/kernel/debug
fi

cd /app/dd-otel-host-profiler
exec "$@"
