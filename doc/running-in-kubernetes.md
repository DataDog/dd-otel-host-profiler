# Running the profiler in Kubernetes

This document is a guide to running the profiler in a Kubernetes cluster.

## Prerequisites

The datadog-agent must be running in the cluster and configured to collect APM data (this is enabled by default in the agent, unless you explicitly disabled it). See https://docs.datadoghq.com/containers/kubernetes/apm/ for more information.

For the purposes of this guide, we assume that the datadog agent is accessible at a specific address: `http://<agent_address>:8126`.

## Running the profiler

See https://github.com/DataDog/dd-otel-host-profiler/pkgs/container/dd-otel-host-profiler/ for a container image that can be used to run the profiler.

To run the profiler in a Kubernetes cluster, you should ensure the following requirements are met (see example below):
1. The container has host PID enabled.
2. The container is running in privileged mode.
3. The container has the `SYS_ADMIN` capability.
4. The `DD_TRACE_AGENT_URL` environment variable is set to the address of the Datadog agent: `http://<agent_address>:8126`.
5. To enable the profiler to upload debug symbols when they're available locally (required to have function names for compiled languages like C/C++/Rust/Go/...), you must configure:
    - The `DD_SITE` environment variable to [your Datadog site](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site) (e.g. `datadoghq.com`, `datadoghq.eu`, `us5.datadoghq.com`, ...).
    - The `DD_API_KEY` environment variable to your Datadog API key.
    - The `DD_APP_KEY` environment variable to your Datadog APP key. The APP key needs the `continuous_profiler_read` permission, which is available by default for the Datadog Read Only role (see [here](https://docs.datadoghq.com/account_management/rbac/permissions/#apm) for more information).

### Example spec

The profiler pod spec excerpt:
```yaml
apiVersion: apps/v1
# ...
spec:
  # ...
  template:
  # ...
    spec:
      # ...
      hostPID: true # Setting hostPID to true (1.)
      containers:
      - name: dd-otel-host-profiler
        securityContext:
          runAsUser: 0
          privileged: true # Running in privileged mode (2.)
          capabilities:
            add:
            - SYS_ADMIN # Adding SYS_ADMIN capability (3.)
        env:
        - name: DD_TRACE_AGENT_URL # The address of the Datadog agent (4.)
          value: "http://<agent_address>:8126"
        - name: DD_SERVICE
          value: "dd-otel-host-profiler"
        - name: DD_SITE
          value: "YOUR_DATADOG_SITE" # The Datadog site (5.)
        - name: DD_API_KEY # The Datadog API Key (5.)
          valueFrom:
            # The example below uses a Kubernetes secret to store the API key.
            secretKeyRef:
              name: some-user
              key: dd-api-key
        - name: DD_APP_KEY # The Datadog APP Key (5.)
          valueFrom:
            # The example below uses a Kubernetes secret to store the APP key.
            secretKeyRef:
              name: some-user
              key: dd-app-key
        # ...
```
