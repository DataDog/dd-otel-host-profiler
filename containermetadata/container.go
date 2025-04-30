// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.
// From https://github.com/DataDog/dd-trace-go/blob/main/internal/container_linux.go

package containermetadata

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	// cgroupPathPattern is the path to the cgroup file where we can find the container id if one exists.
	cgroupPathPattern = "/proc/%d/cgroup"

	cgroupNsPathPattern = "/proc/%d/ns/cgroup"

	// cgroupV1BaseController is the base controller used to identify the cgroup v1 mount point in the cgroupMounts map.
	cgroupV1BaseController = "memory"

	// defaultCgroupMountPath is the path to the cgroup mount point.
	defaultCgroupMountPath = "/sys/fs/cgroup"

	uuidSource      = "[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}|[0-9a-f]{8}(?:-[0-9a-f]{4}){4}$"
	containerSource = "[0-9a-f]{64}"
	taskSource      = "[0-9a-f]{32}-\\d+"

	// From https://github.com/torvalds/linux/blob/5859a2b1991101d6b978f3feb5325dad39421f29/include/linux/proc_ns.h#L41-L49
	// Currently, host namespace inode number are hardcoded, which can be used to detect
	// if we're running in host namespace or not (does not work when running in DinD)
	hostCgroupNamespaceInode = 0xEFFFFFFB
)

var (
	// expLine matches a line in the /proc/<pid>/cgroup file. It has a submatch for the last element (path), which contains the container ID.
	expLine = regexp.MustCompile(`^\d+:[^:]*:(.+)$`)

	// expContainerID matches contained IDs and sources. Source: https://github.com/Qard/container-info/blob/master/index.js
	expContainerID = regexp.MustCompile(fmt.Sprintf(`(%s|%s|%s)(?:.scope)?$`, uuidSource, containerSource, taskSource))
)

type containerIDProvider struct {
}

func NewContainerIDProvider() Provider {
	return &containerIDProvider{}
}

func (p *containerIDProvider) GetContainerMetadata(pid libpf.PID) (ContainerMetadata, error) {
	cgroupFilePath := fmt.Sprintf(cgroupPathPattern, pid)
	containerID, err := readContainerID(cgroupFilePath)
	if err != nil {
		return ContainerMetadata{}, err
	}

	entityID := ""
	// First try to emit the containerID if available. It will be retrieved if the container is
	// running in the host cgroup namespace, independently of the cgroup version.
	if containerID != "" {
		entityID = "ci-" + containerID
	} else {
		cgroupNsFilePath := fmt.Sprintf(cgroupNsPathPattern, pid)
		entityID = readEntityID(defaultCgroupMountPath, cgroupFilePath,
			isHostCgroupNamespace(cgroupNsFilePath))
	}

	return ContainerMetadata{ContainerID: containerID, EntityID: entityID}, nil
}

// parseContainerID finds the first container ID reading from r and returns it.
func parseContainerID(r io.Reader) string {
	scn := bufio.NewScanner(r)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scn.Buffer(buf, 8192)
	for scn.Scan() {
		m := expLine.FindStringSubmatch(scn.Text())
		if len(m) != 2 {
			// invalid entry, continue
			continue
		}
		if parts := expContainerID.FindStringSubmatch(m[1]); len(parts) == 2 {
			return parts[1]
		}
	}
	return ""
}

// readContainerID attempts to return the container ID from the provided file path or empty on failure.
func readContainerID(fpath string) (string, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return parseContainerID(f), nil
}

// parseCgroupNodePath parses /proc/<pid>/cgroup and returns a map of controller to its associated cgroup node path.
func parseCgroupNodePath(r io.Reader) (cgroupV1BaseControllerPath, emptyControllerPath string) {
	scn := bufio.NewScanner(r)
	buf := make([]byte, 512)
	scn.Buffer(buf, 8192)

	for scn.Scan() {
		line := scn.Text()
		tokens := strings.Split(line, ":")
		if len(tokens) != 3 {
			continue
		}
		if tokens[1] == cgroupV1BaseController {
			cgroupV1BaseControllerPath = tokens[2]
		} else if tokens[1] == "" {
			emptyControllerPath = tokens[2]
		}
	}
	return cgroupV1BaseControllerPath, emptyControllerPath
}

// getCgroupInode returns the cgroup controller inode if it exists otherwise an empty string.
// The inode is prefixed by "in-" and is used by the agent to retrieve the container ID.
// We first try to retrieve the cgroupv1 memory controller inode, if it fails we try to retrieve the cgroupv2 inode.
func getCgroupInode(cgroupMountPath, procCgroupPath string) string {
	// Parse /proc/<pid>/cgroup to retrieve the paths to the memory controller (cgroupv1) and the cgroup node (cgroupv2)
	f, err := os.Open(procCgroupPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	cgroupV1BaseControllerPath, emptyControllerPath := parseCgroupNodePath(f)

	if cgroupV1BaseControllerPath != "" {
		inode := inodeForPath(path.Join(cgroupMountPath, cgroupV1BaseController, cgroupV1BaseControllerPath))
		if inode != "" {
			return inode
		}
	}

	if emptyControllerPath != "" {
		inode := inodeForPath(path.Join(cgroupMountPath, emptyControllerPath))
		if inode != "" {
			return inode
		}
	}

	return ""
}

func inodeForPath(filePath string) string {
	fi, err := os.Stat(filePath)
	if err != nil {
		return ""
	}
	stats, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("in-%d", stats.Ino)
}

// readEntityID attempts to return the cgroup node inode or empty on failure.
func readEntityID(mountPath, cgroupPath string, isHostCgroupNamespace bool) string {
	// Rely on the inode if we're not running in the host cgroup namespace.
	if isHostCgroupNamespace {
		return ""
	}
	return getCgroupInode(mountPath, cgroupPath)
}

// isHostCgroupNamespace checks if the agent is running in the host cgroup namespace.
func isHostCgroupNamespace(cgroupNsPath string) bool {
	fi, err := os.Stat(cgroupNsPath)
	if err != nil {
		return false
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if ok {
		return stat.Ino == hostCgroupNamespaceInode
	}

	return false
}
