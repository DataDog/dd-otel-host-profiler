#! /usr/bin/env sh
set -e

DD_API_KEY="$(sudo cat /run/secrets/dd-api-key)"
DD_APP_KEY="$(sudo cat /run/secrets/dd-app-key)"
export DD_API_KEY DD_APP_KEY

sudo mount -t debugfs none /sys/kernel/debug

cd /app
make
sudo -E /app/dd-otel-host-profiler --agent-url "http://datadog-agent:8126" --sampling-rate 20
