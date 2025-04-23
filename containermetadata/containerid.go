// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.
// From https://github.com/DataDog/dd-trace-go/blob/main/internal/container_linux.go

package containermetadata

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	// cgroupPathPattern is the path to the cgroup file where we can find the container id if one exists.
	cgroupPathPattern = "/proc/%d/cgroup"

	uuidSource      = "[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}|[0-9a-f]{8}(?:-[0-9a-f]{4}){4}$"
	containerSource = "[0-9a-f]{64}"
	taskSource      = "[0-9a-f]{32}-\\d+"
)

var (
	// expLine matches a line in the /proc/self/cgroup file. It has a submatch for the last element (path), which contains the container ID.
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
	return ContainerMetadata{ContainerID: containerID}, nil
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
		path := expLine.FindStringSubmatch(scn.Text())
		if len(path) != 2 {
			// invalid entry, continue
			continue
		}
		if parts := expContainerID.FindStringSubmatch(path[1]); len(parts) == 2 {
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
