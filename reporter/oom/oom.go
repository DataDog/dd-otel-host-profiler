// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package oom

import (
	"fmt"
	"os"
	"strconv"
)

func SetOOMScoreAdj(pid, score int) error {
	if score < -1000 || score > 1000 {
		return fmt.Errorf("oom_score_adj must be between -1000 and 1000, got %d", score)
	}

	pidString := ""
	if pid == 0 {
		pidString = "self"
	} else {
		pidString = strconv.Itoa(pid)
	}

	procPath := fmt.Sprintf("/proc/%s/oom_score_adj", pidString)

	if err := os.WriteFile(procPath, []byte(strconv.Itoa(score)), 0); err != nil {
		return fmt.Errorf("failed to write oom_score_adj to %s for PID %d: %w", procPath, pid, err)
	}

	return nil
}
