# dd-otel-host-profiler

<!-- [![Documentation](https://img.shields.io/badge/documentation-datadoghq.dev/orchestrion-blue.svg?style=flat)](https://datadoghq.dev/orchestrion) -->
![Latest Release](https://img.shields.io/github/v/release/DataDog/dd-otel-host-profiler?display_name=tag&label=Latest%20Release)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/datadog/dd-otel-host-profiler)

Datadog OTEL eBPF profiler.

> [!WARNING]
> This profiler is currently **experimental** and has not undergone thorough testing. Features and functionality may be unstable or incomplete.  
> For a more stable and tested alternative, we strongly recommend using [`otel-profiling-agent`](https://github.com/DataDog/otel-profiling-agent) in the meantime.  
> Use this repository at your own risk.

# Overview

dd-otel-host-profiler is based on [open-telemetry/opentelemetry-ebpf-profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler). Please refer to our [documentation](https://docs.datadoghq.com/profiler/) for a list of officially supported Datadog profilers.

This profiler has support for sending profiling data to the Datadog backend via the Datadog Agent. We are active members of the OpenTelemetry Profiling SIG that is working on the OpenTelemetry profiling signal. However, the signal is still under active development, so the Datadog Agent is required until we release our support for directly ingesting the data using OTLP.

## Requirements

dd-otel-host-profiler only runs on Linux, and requires the following Linux kernel versions:
* Kernel version 4.19 or newer for amd64/x86_64
* Kernel version 5.5 or newer for arm64/aarch64

## Running the profiler

If the host is running workloads inside containers, it is recommended to run the profiler inside a container as well. A container image is available at https://github.com/DataDog/dd-otel-host-profiler/pkgs/container/dd-otel-host-profiler/.

If you're using Kubernetes, please follow the documentation here: [Running in Kubernetes](doc/running-in-kubernetes.md). 

If you're directly using Docker, please follow the documentation here: [Running in Docker](doc/running-in-docker.md).

If you're not using a container runtime, please check this section to run the profiler directly on the host: [Running on the host](doc/running-on-host.md).

## Configuring the profiler

### Local symbol upload (Experimental)

For compiled languages (C/C++/Rust/Go), the profiler can upload local symbols (when available) to Datadog for symbolication. Symbols need to be available locally (unstripped binaries).

This feature requires being part of our private beta program for the OpenTelemetry profiler. Please reach out to Datadog support to get access.

To enable local symbol upload:
1. Set the `DD_PROFILING_EXPERIMENTAL_UPLOAD_SYMBOLS` environment variable to `true`.
2. Provide a Datadog API key through the `DD_API_KEY` environment variable.
3. Set the `DD_SITE` environment variable to [your Datadog site](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site) (e.g. `datadoghq.com`, `datadoghq.eu`, `us5.datadoghq.com`, ...).

## Development

A `docker-compose.yml` file is provided to help run the profiler in a container for local development.

First, create a `.env` file with the following content:

```
ARCH=amd64 # required
DD_API_KEY=your-api-key # required
DD_SITE=datadoghq.com # optional, defaults to "datadoghq.com"
DD_SERVICE=my-service # optional, defaults to "dd-otel-host-profiler"
DD_PROFILING_UPLOAD_PERIOD=10s # optional, defaults to 60s
DD_PROFILING_EXPERIMENTAL_UPLOAD_SYMBOLS=true # optional, defaults to false
```

Then, you can run the profiler with the following command:

```
docker-compose up
```

The profiler will submit profiling data to the Datadog Agent using the value of DD_OTEL_HOST_PROFILER_SERVICE as the service name.

# Legal

## Licensing Information

This project is licensed under the Apache License 2.0 (Apache-2.0).
[Apache License 2.0](LICENSE)

The eBPF source code is licensed under the GPL 2.0 license.
[GPL 2.0](support/ebpf/LICENSE)
