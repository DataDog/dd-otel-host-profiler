/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// containermetadata provides functionality for retrieving the kubernetes pod and container
// metadata or the docker container metadata for a particular PID.
// For kubernetes it uses the shared informer from the k8s client-go API
// (https://github.com/kubernetes/client-go/blob/master/tools/cache/shared_informer.go). Through
// the shared informer we are notified of changes in the state of pods in the Kubernetes
// cluster and can add the pod container metadata to the cache.
// As a backup to the kubernetes shared informer and to find the docker container metadata for
// each pid received (if it is not already in the container caches), it will retrieve the container
// id from the /proc/PID/cgroup and retrieve the metadata for the containerID.
package containermetadata

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	dockerHost            = "DOCKER_HOST"
	kubernetesServiceHost = "KUBERNETES_SERVICE_HOST"
	kubernetesNodeName    = "KUBERNETES_NODE_NAME"
	genericNodeName       = "NODE_NAME"

	// There is a limit of 110 Pods per node (but can be overridden)
	kubernetesPodsPerNode = 110
	// From experience, usually there are no more than 10 containers (including sidecar
	// containers) in a single Pod.
	kubernetesContainersPerPod = 10
	// We're setting the default cache size according to Kubernetes best practices,
	// in order to reduce the number of Kubernetes API calls at runtime.
	containerMetadataCacheSize = kubernetesPodsPerNode * kubernetesContainersPerPod

	// containerIDCacheSize defines the size of the cache which maps a process to container ID
	// information. Its perfect size would be the number of processes running on the system.
	containerIDCacheSize = 1024
	// containerIDCacheTimeout decides how long we keep entries in the PID -> container ID cache.
	// The timeout exists to avoid collisions in case of PID reuse.
	containerIDCacheTimeout = 1 * time.Minute

	// deferredTimeout is the timeout to prevent busy loops.
	deferredTimeout = 1 * time.Minute

	// deferredLRUSize defines the size of LRUs deferring look ups.
	deferredLRUSize = 8192
)

var (
	kubePattern       = regexp.MustCompile(`\d+:.*:/.*/*kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	dockerKubePattern = regexp.MustCompile(`\d+:.*:/.*/*docker/pod[^/]+/([0-9a-f]{64})`)
	altKubePattern    = regexp.MustCompile(
		`\d+:.*:/.*/*kubepods.*?/[^/]+/docker-([0-9a-f]{64})`)
	// The systemd cgroupDriver needs a different regex pattern:
	systemdKubePattern    = regexp.MustCompile(`\d+:.*:/.*/*kubepods-.*([0-9a-f]{64})`)
	dockerPattern         = regexp.MustCompile(`\d+:.*:/.*?/*docker[-|/]([0-9a-f]{64})`)
	dockerBuildkitPattern = regexp.MustCompile(`\d+:.*:/.*/*docker/buildkit/([0-9a-z]+)`)
	lxcPattern            = regexp.MustCompile(`\d+::/lxc\.(monitor|payload)\.([a-zA-Z]+)/`)
	containerdPattern     = regexp.MustCompile(`\d+:.+:/([a-zA-Z0-9_-]+)/+([a-zA-Z0-9_-]+)`)
	// The inner container ID pattern is extracted from:
	// https://github.com/DataDog/datadog-agent/blob/6e43db2/pkg/util/cgroups/reader.go#L24C24-L24C90
	defaultPattern = regexp.MustCompile(`^.*/(?:.*[-:])?([0-9a-f]{64})|([0-9a-f]{32}-\\d+)|([0-9a-f]{8}(-[0-9a-f]{4}){4}$)(?:\.|\s*$)`)

	containerIDPattern = regexp.MustCompile(`.+://([0-9a-f]{64})`)

	ErrDeferred = errors.New("lookup deferred due to previous failure")
)

// Provider implementations support retrieving container metadata for a particular PID.
type Provider interface {
	GetContainerMetadata(pid libpf.PID) (ContainerMetadata, error)
}

// containerMetadataProvider does the retrieval of container metadata for a particular pid.
type containerMetadataProvider struct {
	// Counters to keep track how often external APIs are called.
	kubernetesClientQueryCount atomic.Uint64
	dockerClientQueryCount     atomic.Uint64
	containerdClientQueryCount atomic.Uint64

	// the kubernetes node name used to retrieve the pod information.
	nodeName string
	// containerMetadataCache provides a cache to quickly retrieve the pod metadata for a
	// particular container id. It caches the pod name and container name metadata. Locked LRU.
	containerMetadataCache *lru.SyncedLRU[string, ContainerMetadata]

	// containerIDCache stores per process container ID information.
	containerIDCache *lru.SyncedLRU[libpf.PID, containerIDEntry]

	kubeClientSet kubernetes.Interface
	dockerClient  *client.Client

	containerdClient *containerd.Client

	// deferredPID prevents busy loops for PIDs where the cgroup extraction fails.
	deferredPID *lru.SyncedLRU[libpf.PID, libpf.Void]

	// file pattern to extract container ID from cgroup file
	// only used for testing
	cgroupPattern string
}

// ContainerMetadata contains the container and/or pod metadata.
type ContainerMetadata struct {
	ContainerID   string
	EntityID      string
	PodName       string
	ContainerName string
}

// hashString is a helper function for containerMetadataCache
// xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// containerEnvironment specifies a used container technology.
type containerEnvironment uint16

// List of known container technologies we can handle.
const (
	envUndefined  containerEnvironment = 0
	envKubernetes containerEnvironment = 1 << iota
	envDocker
	envLxc
	envContainerd
	envDockerBuildkit
)

// isContainerEnvironment tests if env is target.
func isContainerEnvironment(env, target containerEnvironment) bool {
	return target&env == target
}

// containerIDEntry stores the information we fetch from the cgroup information of the process.
type containerIDEntry struct {
	containerID string
	env         containerEnvironment
}

// NewContainerMetadataProvider returns a new ContainerMetadataProvider instance used for retrieving container metadata.
func NewContainerMetadataProvider(ctx context.Context, nodeName string) (
	Provider, error) {
	containerIDCache, err := lru.NewSynced[libpf.PID, containerIDEntry](
		containerIDCacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to create container id cache: %w", err)
	}
	containerIDCache.SetLifetime(containerIDCacheTimeout)

	p := &containerMetadataProvider{
		containerIDCache: containerIDCache,
		dockerClient:     getDockerClient(),
		containerdClient: getContainerdClient(),
		nodeName:         nodeName,
		cgroupPattern:    "/proc/%d/cgroup",
	}

	p.deferredPID, err = lru.NewSynced[libpf.PID, libpf.Void](deferredLRUSize,
		libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}
	p.deferredPID.SetLifetime(deferredTimeout)

	if os.Getenv(kubernetesServiceHost) != "" {
		err = createKubernetesClient(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client %w", err)
		}
	} else {
		log.Infof("Environment variable %s not set", kubernetesServiceHost)
		p.containerMetadataCache, err = lru.NewSynced[string, ContainerMetadata](
			containerMetadataCacheSize, hashString)
		if err != nil {
			return nil, fmt.Errorf("unable to create container metadata cache: %w", err)
		}
	}

	log.Debugf("Container metadata handler: %v", p)

	return p, nil
}

// getPodsPerNode returns the number of pods per node.
// Depending on the configuration of the kubernetes environment, we may not be allowed to query
// for the allocatable information of the nodes.
func getPodsPerNode(ctx context.Context, h *containerMetadataProvider) (int, error) {
	h.kubernetesClientQueryCount.Add(1)
	node, err := h.kubeClientSet.CoreV1().Nodes().Get(ctx, h.nodeName, v1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to get kubernetes node '%s': %w",
			h.nodeName, err)
	}

	quantity, ok := node.Status.Allocatable[corev1.ResourcePods]
	if !ok {
		return 0, fmt.Errorf("failed to get allocatable information from %s",
			node.Name)
	}

	return int(quantity.Value()), nil
}

func getContainerMetadataCache(ctx context.Context, h *containerMetadataProvider) (
	*lru.SyncedLRU[string, ContainerMetadata], error) {
	cacheSize := containerMetadataCacheSize

	podsPerNode, err := getPodsPerNode(ctx, h)
	if err != nil {
		log.Infof("Failed to size cache based on pods per node: %v", err)
	} else {
		cacheSize *= podsPerNode
	}

	return lru.NewSynced[string, ContainerMetadata](
		uint32(cacheSize), hashString)
}

func createKubernetesClient(ctx context.Context, p *containerMetadataProvider) error {
	log.Debugf("Create Kubernetes client")

	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in cluster configuration for Kubernetes: %w", err)
	}
	p.kubeClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	k, ok := p.kubeClientSet.(*kubernetes.Clientset)
	if !ok {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	if p.nodeName == "" {
		p.nodeName, err = getNodeName()
		if err != nil {
			return fmt.Errorf("failed to get kubernetes node name; %w", err)
		}
	}

	p.containerMetadataCache, err = getContainerMetadataCache(ctx, p)
	if err != nil {
		return fmt.Errorf("failed to create container metadata cache: %w", err)
	}

	// Create the shared informer factory and use the client to connect to
	// Kubernetes and get notified of new pods that are created in the specified node.
	factory := informers.NewSharedInformerFactoryWithOptions(k, 0,
		informers.WithTweakListOptions(func(options *v1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + p.nodeName
		}))
	informer := factory.Core().V1().Pods().Informer()

	// Kubernetes serves a utility to handle API crashes
	defer runtime.HandleCrash()

	handle, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("Received unknown object in AddFunc handler: %#v", obj)
				return
			}
			p.putCache(pod)
		},
		UpdateFunc: func(_ any, newObj any) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				log.Errorf("Received unknown object in UpdateFunc handler: %#v",
					newObj)
				return
			}
			p.putCache(pod)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to attach event handler: %w", err)
	}

	// Shutdown the informer when the context attached to this handler expires
	stopper := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopper)
		if err := informer.RemoveEventHandler(handle); err != nil {
			log.Errorf("Failed to remove event handler: %v", err)
		}
	}()
	// Run the informer
	go informer.Run(stopper)

	return nil
}

func getContainerdClient() *containerd.Client {
	knownContainerdSockets := []string{"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/docker/containerd/containerd.sock"}

	for _, socket := range knownContainerdSockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		opt := containerd.WithTimeout(3 * time.Second)
		if c, err := containerd.New(socket, opt); err == nil {
			return c
		}
	}
	log.Infof("Can't connect Containerd client to %v", knownContainerdSockets)
	return nil
}

func getDockerClient() *client.Client {
	// /var/run/docker.sock is the default socket used by client.NewEnvClient().
	knownDockerSockets := []string{"/var/run/docker.sock"}

	// If the default socket is not available check if DOCKER_HOST is set to a different socket.
	envDockerSocket := os.Getenv(dockerHost)
	if envDockerSocket != "" {
		knownDockerSockets = append(knownDockerSockets, envDockerSocket)
	}

	for _, socket := range knownDockerSockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		if c, err := client.NewClientWithOpts(
			client.FromEnv,
			client.WithAPIVersionNegotiation(),
		); err == nil {
			return c
		}
	}
	log.Infof("Can't connect Docker client to %v", knownDockerSockets)
	return nil
}

// GetContainerMetadata implements the Handler interface.
func (p *containerMetadataProvider) GetContainerMetadata(pid libpf.PID) (ContainerMetadata, error) {
	// Fast path, check container metadata has been cached
	// For kubernetes pods, the shared informer may have updated
	// the container id to container metadata cache, so retrieve the container ID for this pid.
	pidContainerID, env, err := p.lookupContainerID(pid)
	if err != nil {
		return ContainerMetadata{}, fmt.Errorf("failed to get container id for pid %d", pid)
	}
	if envUndefined == env {
		// We were not able to identify a container technology for the given PID.
		return ContainerMetadata{
			ContainerID: pidContainerID,
		}, nil
	}

	// Fast path, check if the containerID metadata has been cached
	if data, ok := p.containerMetadataCache.Get(pidContainerID); ok {
		return data, nil
	}

	var data ContainerMetadata

	// For kubernetes pods this route should happen rarely, this means that we are processing a
	// trace but the shared informer has been delayed in updating the container id metadata cache.
	// If it is not a kubernetes pod then we need to look up the container id in the configured
	// client.
	switch {
	case isContainerEnvironment(env, envKubernetes) && p.kubeClientSet != nil:
		data, err = p.getKubernetesPodMetadata(pidContainerID)
	case isContainerEnvironment(env, envDocker) && p.dockerClient != nil:
		data, err = p.getDockerContainerMetadata(pidContainerID)
	case isContainerEnvironment(env, envContainerd) && p.containerdClient != nil:
		data, err = p.getContainerdContainerMetadata(pidContainerID)
	case isContainerEnvironment(env, envDockerBuildkit):
		// If DOCKER_BUILDKIT is set we can not retrieve information about this container
		// from the docker socket. Therefore, we populate container ID and container name
		// with the information we have.
		data = ContainerMetadata{
			ContainerID:   pidContainerID,
			ContainerName: pidContainerID,
		}
	case isContainerEnvironment(env, envLxc):
		// As lxc does not use different identifiers we populate container ID and container
		// name of metadata with the same information.
		data = ContainerMetadata{
			ContainerID:   pidContainerID,
			ContainerName: pidContainerID,
		}
	default:
		err = fmt.Errorf("failed to handle unknown container technology %d", env)
	}

	if err != nil {
		log.Debugf("Failed to get container metadata for container id %v: %v", pidContainerID, err)

		// If we failed to get the container metadata, still return the container ID
		data = ContainerMetadata{
			ContainerID: pidContainerID,
		}
		// Cache the failure for a limited time to allow retry later
		p.containerMetadataCache.AddWithLifetime(pidContainerID, data, deferredTimeout)
	} else {
		// Cache success without lifetime
		p.containerMetadataCache.Add(pidContainerID, data)
	}

	return data, err
}

// putCache updates the container id metadata cache for the provided pod.
func (p *containerMetadataProvider) putCache(pod *corev1.Pod) {
	log.Debugf("Update container metadata cache for pod %s", pod.Name)

	for i := range pod.Status.ContainerStatuses {
		var containerID string
		var err error
		if containerID, err = matchContainerID(
			pod.Status.ContainerStatuses[i].ContainerID); err != nil {
			log.Debugf("failed to get kubernetes container metadata for pod %s: %v", pod.Name, err)
			continue
		}

		p.containerMetadataCache.Add(containerID, ContainerMetadata{
			ContainerID:   containerID,
			PodName:       pod.Name,
			ContainerName: pod.Status.ContainerStatuses[i].Name,
		})
	}
}

func matchContainerID(containerIDStr string) (string, error) {
	containerIDParts := containerIDPattern.FindStringSubmatch(containerIDStr)
	if len(containerIDParts) != 2 {
		return "", fmt.Errorf("could not get string submatch for container id %v",
			containerIDStr)
	}
	return containerIDParts[1], nil
}

func getNodeName() (string, error) {
	nodeName := os.Getenv(kubernetesNodeName)
	if nodeName != "" {
		return nodeName, nil
	}
	log.Debugf("%s not set", kubernetesNodeName)

	// The Elastic manifest for kubernetes uses NODE_NAME instead of KUBERNETES_NODE_NAME.
	// Therefore, we check for both environment variables.
	nodeName = os.Getenv(genericNodeName)
	if nodeName == "" {
		return "", errors.New("kubernetes node name not configured")
	}

	return nodeName, nil
}

func (p *containerMetadataProvider) getKubernetesPodMetadata(pidContainerID string) (
	ContainerMetadata, error) {
	log.Debugf("Get kubernetes pod metadata for container id %v", pidContainerID)

	p.kubernetesClientQueryCount.Add(1)
	pods, err := p.kubeClientSet.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{
		FieldSelector: "spec.nodeName=" + p.nodeName,
	})
	if err != nil {
		return ContainerMetadata{}, fmt.Errorf("failed to retrieve kubernetes pods, %w", err)
	}

	for j := range pods.Items {
		podName := pods.Items[j].Name
		containers := pods.Items[j].Status.ContainerStatuses
		for i := range containers {
			var containerID string
			if containers[i].ContainerID == "" {
				continue
			}
			if containerID, err = matchContainerID(containers[i].ContainerID); err != nil {
				log.Error(err)
				continue
			}
			if containerID == pidContainerID {
				containerMetadata := ContainerMetadata{
					ContainerID:   containerID,
					PodName:       podName,
					ContainerName: containers[i].Name,
				}

				return containerMetadata, nil
			}
		}

		initContainers := pods.Items[j].Status.InitContainerStatuses
		for i := range initContainers {
			var containerID string
			if initContainers[i].ContainerID == "" {
				continue
			}
			if containerID, err = matchContainerID(initContainers[i].ContainerID); err != nil {
				log.Error(err)
				continue
			}
			if containerID == pidContainerID {
				containerMetadata := ContainerMetadata{
					ContainerID:   containerID,
					PodName:       podName,
					ContainerName: pods.Items[j].Spec.InitContainers[i].Name,
				}

				return containerMetadata, nil
			}
		}
	}

	return ContainerMetadata{},
		fmt.Errorf("failed to find matching kubernetes pod/container metadata for "+
			"containerID '%v' in %d pods", pidContainerID, len(pods.Items))
}

func (p *containerMetadataProvider) getDockerContainerMetadata(pidContainerID string) (
	ContainerMetadata, error) {
	log.Debugf("Get docker container metadata for container id %v", pidContainerID)

	p.dockerClientQueryCount.Add(1)
	containers, err := p.dockerClient.ContainerList(context.Background(),
		container.ListOptions{})
	if err != nil {
		return ContainerMetadata{}, fmt.Errorf("failed to list docker containers, %w", err)
	}

	for i := range containers {
		if containers[i].ID == pidContainerID {
			// remove / prefix from container name
			containerName := strings.TrimPrefix(containers[i].Names[0], "/")
			metadata := ContainerMetadata{
				ContainerID:   containers[i].ID,
				ContainerName: containerName,
			}
			return metadata, nil
		}
	}

	return ContainerMetadata{},
		fmt.Errorf("failed to find matching docker container metadata for containerID, %v",
			pidContainerID)
}

func (p *containerMetadataProvider) getContainerdContainerMetadata(pidContainerID string) (
	ContainerMetadata, error) {
	log.Debugf("Get containerd container metadata for container id %v", pidContainerID)

	// Avoid heap allocations here - do not use strings.SplitN()
	var fields [4]string // allocate the array on the stack with capacity 3
	n := stringutil.SplitN(pidContainerID, "/", fields[:])

	if n < 3 {
		return ContainerMetadata{},
			fmt.Errorf("unexpected format of containerd identifier: %s",
				pidContainerID)
	}

	p.containerdClientQueryCount.Add(1)
	ctx := namespaces.WithNamespace(context.Background(), fields[1])
	containers, err := p.containerdClient.Containers(ctx)
	if err != nil {
		return ContainerMetadata{},
			fmt.Errorf("failed to get containerd containers in namespace '%s': %w",
				fields[1], err)
	}

	for _, container := range containers {
		if container.ID() == fields[2] {
			// Containerd does not differentiate between the name and the ID of a
			// container. So we both options to the same value.

			metadata := ContainerMetadata{
				ContainerID:   fields[2],
				ContainerName: fields[2],
				PodName:       fields[1],
			}
			return metadata, nil
		}
	}

	return ContainerMetadata{},
		fmt.Errorf("failed to find matching containerd container metadata for containerID, %v",
			pidContainerID)
}

// lookupContainerID looks up a process ID from the host PID namespace,
// returning its container ID and the used container technology.
func (p *containerMetadataProvider) lookupContainerID(pid libpf.PID) (containerID string, env containerEnvironment,
	err error) {
	if entry, exists := p.containerIDCache.Get(pid); exists {
		return entry.containerID, entry.env, nil
	}

	if _, exists := p.deferredPID.Get(pid); exists {
		return "", envUndefined, ErrDeferred
	}

	containerID, env, err = p.extractContainerIDFromFile(fmt.Sprintf(p.cgroupPattern, pid))
	if err != nil {
		p.deferredPID.Add(pid, libpf.Void{})
		return "", envUndefined, err
	}

	// Store the result in the cache.
	p.containerIDCache.Add(pid, containerIDEntry{
		containerID: containerID,
		env:         env,
	})

	return containerID, env, nil
}

func (p *containerMetadataProvider) extractContainerIDFromFile(cgroupFilePath string) (
	containerID string, env containerEnvironment, err error) {
	f, err := os.Open(cgroupFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debugf("%s does not exist anymore. "+
				"Failed to get container id", cgroupFilePath)
			return "", envUndefined, nil
		}
		return "", envUndefined, fmt.Errorf("failed to get container id from %s: %w",
			cgroupFilePath, err)
	}
	defer f.Close()

	containerID = ""
	env = envUndefined

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)

	var parts []string
	for scanner.Scan() {
		line := scanner.Text()

		// In minikube, a new docker instance is run inside a docker container,
		// and kube containers are run in this instance.
		// Therefore there are two different container IDs in cgroup:
		// - container ID of the outer docker container running the inner docker instance
		// - container ID of the kube container running in the inner docker instance
		// If k8 client is not available, profiler is probably running outside k8s and it
		// should use the outer docker container ID.
		if p.kubeClientSet == nil {
			if parts = dockerPattern.FindStringSubmatch(line); parts != nil {
				containerID = parts[1]
				env |= envDocker
				break
			}
		}

		if parts = dockerKubePattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			env |= (envKubernetes | envDocker)
			break
		}

		if parts = kubePattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			env |= envKubernetes
			break
		}

		if parts = altKubePattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			env |= envKubernetes
			break
		}

		if parts = systemdKubePattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			env |= envKubernetes
			break
		}

		if parts = dockerBuildkitPattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			env |= envDockerBuildkit
			break
		}

		if parts = dockerPattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			env |= envDocker
			break
		}

		if parts = lxcPattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[2]
			env |= envLxc
			break
		}

		if parts = containerdPattern.FindStringSubmatch(line); parts != nil {
			// Forward the complete match as containerID so, we can extract later
			// the exact containerd namespace and container ID from it.
			containerID = parts[0]
			env |= envContainerd
			break
		}

		if parts = defaultPattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[1]
			break
		}
	}

	return containerID, env, nil
}
