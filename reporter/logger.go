// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import log "github.com/sirupsen/logrus"

// Logger is an interface for logging. It allows using different logging
// implementations from other repositories while maintaining compatibility
// with this package.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// DefaultLogger returns a Logger implementation using the standard logrus logger.
// Note: logrus.FieldLogger already implements the Logger interface, so any
// logrus logger can be used directly without an adapter.
func DefaultLogger() Logger {
	return log.StandardLogger()
}
