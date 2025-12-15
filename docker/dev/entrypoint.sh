#! /usr/bin/env sh

DD_API_KEY="$(sudo cat /run/secrets/dd-api-key)"
DD_APP_KEY="$(sudo cat /run/secrets/dd-app-key)"
export DD_API_KEY DD_APP_KEY

sudo test -d /sys/kernel/tracing || sudo mount -t tracefs tracefs /sys/kernel/tracing

cd /app/dd-otel-host-profiler
exec "$@"
