// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	cgroupRoot     = "/sys/fs/cgroup"
	v1MaxMemory    = "memory.limit_in_bytes"
	v2MaxMemory    = "memory.max"
	memoryMaxUnset = 0x7FFFFFFFFFFFF000
	budgetRatio    = 0.1
)

func isCgroup2UnifiedMode() bool {
	var st unix.Statfs_t
	err := unix.Statfs(cgroupRoot, &st)
	if err != nil {
		return false
	}
	return st.Type == unix.CGROUP2_SUPER_MAGIC
}

func readFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func v1GetMaxUsableMemory() (int64, error) {
	str, err := readFromFile(filepath.Join(cgroupRoot, "memory", v1MaxMemory))
	if err != nil {
		return -1, err
	}

	value, err := strconv.ParseInt(str, 10, 64)

	if err != nil {
		return -1, err
	}

	if value < 0 || value == memoryMaxUnset {
		return -1, nil
	}

	return value, nil
}

func getCurrentCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupRoot, path), nil
		}
	}

	return "", errors.New("cgroup path not found in /proc/self/cgroup")
}

func v2GetMaxUsableMemory() (int64, error) {
	currCgroupPath, err := getCurrentCgroupPath()
	if err != nil {
		return -1, err
	}

	str, err := readFromFile(filepath.Join(currCgroupPath, v2MaxMemory))

	if err != nil {
		return -1, err
	}

	// not error -> no memory constraints
	if str == "max" {
		return -1, nil
	}

	limit, err := strconv.ParseInt(str, 10, 64)

	if err != nil {
		return -1, err
	}

	return limit, nil
}

func GetMaxUsableMemory() (int64, error) {
	if !isCgroup2UnifiedMode() {
		return v1GetMaxUsableMemory()
	}
	return v2GetMaxUsableMemory()
}

func GetMemoryBudget() (int64, error) {
	maxMemory, err := GetMaxUsableMemory()
	if err != nil {
		return -1, err
	} else if maxMemory == -1 {
		return maxMemory, err
	}

	return int64(float32(maxMemory) * budgetRatio), nil
}
