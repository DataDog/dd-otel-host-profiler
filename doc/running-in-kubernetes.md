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
3. The `procMount` security context field is set to `Unmasked`.
4. The container has the `SYS_ADMIN` capability.
5. The `DD_OTEL_HOST_PROFILER_COLLECTION_AGENT` environment variable is set to the address of the Datadog agent: `http://<agent_address>:8126`.

Additionally, to be able to resolve pod names in Kubernetes, the profiler needs:
* The `KUBERNETES_NODE_NAME` environment variable set to the name of the node where the profiler is running.
* A ClusterRole and ClusterRoleBinding configured (see below).

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
      serviceAccountName: <my-service-account> # The service account used
      hostPID: true # Setting hostPID to true (1.)
      containers:
      - name: dd-otel-host-profiler
        securityContext:
          runAsUser: 0
          privileged: true # Running in privileged mode (2.)
          procMount: Unmasked # Setting procMount to Unmasked (3.)
          capabilities:
            add:
            - SYS_ADMIN # Adding SYS_ADMIN capability (4.)
        env:
        - name: DD_OTEL_HOST_PROFILER_COLLECTION_AGENT # The address of the Datadog agent (5.)
          value: "http://<agent_address>:8126"
        - name: KUBERNETES_NODE_NAME # this is needed to resolve pod names in Kubernetes
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: DD_OTEL_HOST_PROFILER_SERVICE
          value: "$(KUBERNETES_NODE_NAME)" # will inherit the variable set above
        # ...
        volumeMounts:
        - name: containerd # Or alternatively, docker if using docker. This is required to be able to resolve container names.
          mountPath: /run/containerd/containerd.sock # Or alternatively, /var/run/docker.sock
        # ...
      volumes:
      - name: containerd # Or alternatively, docker if using docker
        hostPath:
          path: /run/containerd/containerd.sock # Or alternatively, /var/run/docker.sock
          type: Socket
      # ...
```

You will also need to create a ServiceAccount, ClusterRole, and ClusterRoleBinding for the profiler to be able to list pods in the cluster. Here is an example:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: <my-service-account>
  namespace: <my-service-account-namespace>
  # ...
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: <my-cluster-role>
  # ...
rules:
  - apiGroups:
    - ""
    resources:
    - nodes
    - pods
    verbs:
    - get
    - list
    - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: <my-cluster-role-binding>
  # ...
subjects:
  - kind: ServiceAccount
    name: <my-service-account>
    namespace: <my-service-account-namespace>
roleRef:
  kind: ClusterRole
  name: <my-cluster-role>
  apiGroup: rbac.authorization.k8s.io
```
