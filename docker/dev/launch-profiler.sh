#! /usr/bin/env sh
set -e


if [ "${DO_NOT_START_PROFILER}" = "1" ]; then
    echo "Skipping profiler start"
    sleep infinity
else
    make
    sudo -E ./dd-otel-host-profiler
fi
