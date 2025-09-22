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
5. To enable the profiler to upload debug symbols when they're available locally (required to have function names for compiled languages like C/C++/Rust/Go/...), you must configure:
    - The `DD_SITE` environment variable to [your Datadog site](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site) (e.g. `datadoghq.com`, `datadoghq.eu`, `us5.datadoghq.com`, ...).
    - The `DD_API_KEY` environment variable to your Datadog API key.
    - The `DD_APP_KEY` environment variable to your Datadog APP key. The APP key needs the `continuous_profiler_read` permission, which is available by default for the Datadog Read Only role (see [here](https://docs.datadoghq.com/account_management/rbac/permissions/#apm) for more information).

### Example command to run the profiler in Docker

```bash
docker run \
  --pid=host \
  --privileged \
  --cap-add=SYS_ADMIN \
  -e DD_TRACE_AGENT_URL=http://<agent_address>:8126 \
  -e DD_SERVICE="dd-otel-host-profiler" \
  -e DD_SITE="YOUR_DATADOG_SITE" \
  -e DD_API_KEY="YOUR_DATADOG_API_KEY" \
  -e DD_APP_KEY="YOUR_DATADOG_APP_KEY" \
  ghcr.io/datadog/dd-otel-host-profiler:latest
```
