# syntax=docker.io/docker/dockerfile:1.7-labs
FROM ubuntu:24.04@sha256:d4f6f70979d0758d7a6f81e34a61195677f4f4fa576eaf808b79f17499fd93d1

RUN apt-get update && \
    apt-get install -y --no-install-recommends binutils ca-certificates

COPY docker/release/entrypoint.sh /entrypoint.sh
COPY --parents agent-** /tmp/

RUN mv /tmp/agent-$(uname -p)/dd-otel-host-profiler /usr/local/bin/dd-otel-host-profiler \
    && chmod +x /usr/local/bin/dd-otel-host-profiler \
    && rm -rf /tmp/agent*

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/dd-otel-host-profiler"]
