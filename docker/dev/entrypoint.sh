#! /usr/bin/env sh

DD_API_KEY="$(sudo cat /run/secrets/dd-api-key)"
export DD_API_KEY

sudo mountpoint -q /sys/kernel/tracing || sudo mount -t tracefs tracefs /sys/kernel/tracing

cd /app/dd-otel-host-profiler
exec "$@"
