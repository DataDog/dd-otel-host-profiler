#!/usr/bin/env bash
set -euo pipefail

DD_API_KEY="$(cat /run/secrets/dd-api-key)";
export DD_API_KEY;

DD_APP_KEY=$(cat /run/secrets/dd-app-key);
export DD_APP_KEY;

sudo mount -t debugfs none /sys/kernel/debug;

cd /app

# Build the host profiler
make

exec sudo -E "$@"
