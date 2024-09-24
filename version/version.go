// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package version

import "runtime/debug"

var (
	// Version is the current version of the profiler
	version = "v0.0.0"
)

type Info struct {
	Version     string
	VcsTime     string
	VcsRevision string
}

// GetVersionInfo returns the version information
func GetVersionInfo() Info {
	buildInfo, ok := debug.ReadBuildInfo()
	versionInfo := Info{
		Version: version,
	}

	if !ok {
		return versionInfo
	}

	modified := false
	for _, v := range buildInfo.Settings {
		switch v.Key {
		case "vcs.revision":
			versionInfo.VcsRevision = v.Value
		case "vcs.time":
			versionInfo.VcsTime = v.Value
		case "vcs.modified":
			modified = v.Value == "true"
		}
	}
	if modified {
		versionInfo.VcsRevision += "-dirty"
	}

	return versionInfo
}
