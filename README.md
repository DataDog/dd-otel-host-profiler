# dd-otel-host-profiler

![Latest Release](https://img.shields.io/github/v/release/DataDog/dd-otel-host-profiler?display_name=tag&label=Latest%20Release)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/datadog/dd-otel-host-profiler)

Datadog OTEL eBPF profiler.

# Overview

dd-otel-host-profiler is an experimental profiler based on [open-telemetry/opentelemetry-ebpf-profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler). Please refer to our [documentation](https://docs.datadoghq.com/profiler/) for a list of officially supported Datadog profilers.

This profiler has support for sending profiling data to the Datadog backend via the Datadog Agent. We are active members of the OpenTelemetry Profiling SIG that is working on the OpenTelemetry profiling signal. However, the signal is still under active development, so deploying the Datadog Agent in addition to the profiler is required until we release our support for directly ingesting the data using OTLP.

## Requirements

dd-otel-host-profiler only runs on Linux, and requires the following Linux kernel versions:
* Kernel version 5.4 or newer for amd64/x86_64
* Kernel version 5.5 or newer for arm64/aarch64

## Running the profiler

If the host is running workloads inside containers, it is recommended to run the profiler inside a container as well. A container image is available at https://github.com/DataDog/dd-otel-host-profiler/pkgs/container/dd-otel-host-profiler/.

If you're using Kubernetes, please follow the documentation here: [Running in Kubernetes](doc/running-in-kubernetes.md). 

If you're directly using Docker, please follow the documentation here: [Running in Docker](doc/running-in-docker.md).

If you're not using a container runtime, please check this section to run the profiler directly on the host: [Running on the host](doc/running-on-host.md).

## Configuring the profiler

### Local symbol upload

For compiled languages (such as Rust, C, C++, Go, etc.), the profiler uploads local symbols to Datadog for symbolication, ensuring that function names are available in profiles. For Rust, C, and C++, symbols need to be available locally (unstripped binaries).

This requires to configure:
1. The `DD_SITE` environment variable to [your Datadog site](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site) (e.g. `datadoghq.com`, `datadoghq.eu`, `us5.datadoghq.com`, ...).
2. The `DD_API_KEY` environment variable to your Datadog API key.
3. The `DD_APP_KEY` environment variable to your Datadog APP key. The APP key needs the `continuous_profiler_read` permission, which is available by default for the Datadog Read Only role (see [here](https://docs.datadoghq.com/account_management/rbac/permissions/#apm) for more information).

To disable local symbol upload, set the `DD_HOST_PROFILING_UPLOAD_SYMBOLS` environment variable to `false`.

See [here](https://docs.datadoghq.com/profiler/enabling/full_host/#debug-symbols) for more information about symbol upload, including how to upload them manually using Datadog CI.

## Build 

You must first ensure you have the correct version of go installed.
In order to build the profiler directly on your machine, you can simply run:

```
make
```

## Development

A `docker-compose.yml` file is provided to help run the profiler in a container for local development.

First, create a `.env` file with the following content:

```
DD_SITE=datad0g.com # optional (required on a Datadog workspace), defaults to "datadoghq.com"
DD_HOST_PROFILING_UPLOAD_PERIOD=10s # optional, defaults to 60s
DD_API_KEY=your-api-key # required (not needed on a Datadog workspace) 
DD_APP_KEY=your-app-key # required (not needed on a Datadog workspace) 
DD_HOST_PROFILING_TAGS="workspace:YOUR_WORKSPACE_NAME" # recommended on Datadog workspace
UID=1234 # required on Datadog workspace, set it to the output of `id -u` on the workspace
GID=1234 # required on Datadog workspace, set it to the output of `id -g` on the workspace
```

Then, you can run the profiler with the following command:

```
docker-compose up
```

Profiles matching your workspace tag (`workspace:YOUR_WORKSPACE_NAME`) will be available in the Datadog UI.

# Legal

## Licensing Information

This project is licensed under the Apache License 2.0 (Apache-2.0).
[Apache License 2.0](LICENSE)

The eBPF source code is licensed under the GPL 2.0 license.
[GPL 2.0](support/ebpf/LICENSE)
