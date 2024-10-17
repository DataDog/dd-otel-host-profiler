# Running the profiler in Docker

This document is a guide to running the profiler in a Docker container.

## Prerequisites

The datadog-agent must be running and configured to collect APM data (this is enabled by default in the agent, unless you explicitly disabled it). See https://docs.datadoghq.com/containers/docker/apm/ for more information.

For the purposes of this guide, we assume that the datadog agent is accessible at a specific address from the docker container: `http://<agent_address>:8126`.

## Running the profiler

See https://github.com/DataDog/dd-otel-host-profiler/pkgs/container/dd-otel-host-profiler/ for a container image that can be used to run the profiler.

To run the profiler in Docker, you should ensure the following requirements are met (see example below):
1. The container has host PID enabled.
2. The container is running in privileged mode.
3. The container has the `SYS_ADMIN` capability.
4. The `DD_TRACE_AGENT_URL` environment variable is set to the address of the Datadog agent: `http://<agent_address>:8126`.

Additionally, to be able to resolve container names, the profiler needs access to the container runtime socket. This is done by mounting the container runtime socket into the profiler container.

### Example command to run the profiler in Docker

```bash
docker run \
  --pid=host \
  --privileged \
  --cap-add=SYS_ADMIN \
  -e DD_TRACE_AGENT_URL=http://<agent_address>:8126 \
  -e DD_SERVICE="$(hostname)" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/datadog/dd-otel-host-profiler:latest
```
