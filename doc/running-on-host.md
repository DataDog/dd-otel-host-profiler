# Running the profiler directly on the host

## Prerequisites

The datadog-agent must be running on the host and configured to collect APM data (this is enabled by default in the agent, unless you explicitly disabled it). See agent installation instructions [here](https://docs.datadoghq.com/agent/) and the flag to enable APM [here](https://github.com/DataDog/datadog-agent/blob/8a80bcd1c1460ba9caa97d974568bd9d0c702f3f/pkg/config/config_template.yaml#L1036-L1042).

For the purposes of this guide, we assume that the datadog agent is accessible at a specific address from the docker container: `http://localhost:8126`.

## Installation

Download pre-built amd64 and arm64 binaries for our [latest release](https://github.com/DataDog/dd-otel-host-profiler/releases/latest).

Alternatively, you can build the profiler from source. The following instructions assume you have docker installed.

<details>
<summary>Manual build instructions</summary>
<br />

To build the profiler, you can use the following commands:

```
make profiler-in-docker
```

This will create a `dd-otel-host-profiler` binary in the current directory.

</details>

## Running the profiler

To run the profiler, you need to make sure that debugfs is mounted. If it's not, you can run:

```
sudo mount -t debugfs none /sys/kernel/debug
```

After that, you can start the profiler as shown below (make sure you run it as root):

```
sudo dd-otel-host-profiler --service "$(hostname)" --agent-url "http://localhost:8126"
```

If your Datadog agent is reachable under a different address, you can modify the `--agent-url` parameter accordingly.
