/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package runner

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	log "github.com/sirupsen/logrus"

	"github.com/DataDog/dd-otel-host-profiler/reporter"
)

var ValidTagKeyRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-._/]+$`)
var ValidTagValueRegex = regexp.MustCompile(`^[a-zA-Z0-9-:._/]*$`)

// ValidateTags parses and validates user-specified tags.
// Each tag must match ValidTagRegex with ',' used as a separator.
// Tags that can't be validated are dropped.
// The empty string is returned if no tags can be validated.
func ValidateTags(tags string) reporter.Tags {
	if tags == "" {
		return nil
	}

	splitTags := strings.Split(tags, ",")
	validatedTags := make(reporter.Tags, 0, len(splitTags))

	for _, tag := range splitTags {
		key, value, found := strings.Cut(tag, ":")
		if !found || !ValidTagKeyRegex.MatchString(key) || !ValidTagValueRegex.MatchString(value) {
			log.Warnf("Rejected user-specified tag '%s'", tag)
		} else {
			validatedTags = append(validatedTags, reporter.MakeTag(key, value))
		}
	}

	return validatedTags
}

func addTagsFromArgs(tags *reporter.Tags, config *Config) {
	if config.Environment != "" {
		*tags = append(*tags, reporter.MakeTag("env", config.Environment))
	}
}

// IsAPIKeyValid reports whether the given string is a structurally valid API key
func IsAPIKeyValid(key string) bool {
	if len(key) != 32 {
		return false
	}
	for _, c := range key {
		if c > unicode.MaxASCII || (!unicode.IsLower(c) && !unicode.IsNumber(c)) {
			return false
		}
	}
	return true
}

// IsAPPKeyValid reports whether the given string is a structurally valid APP key
func IsAPPKeyValid(key string) bool {
	if len(key) != 40 {
		return false
	}
	for _, c := range key {
		if c > unicode.MaxASCII || (!unicode.IsLower(c) && !unicode.IsNumber(c)) {
			return false
		}
	}
	return true
}

func intakeURLForSite(site string) (string, error) {
	u := fmt.Sprintf("https://intake.profile.%s/api/v2/profile", site)
	_, err := url.Parse(u)
	return u, err
}

func intakeURLForAgent(agentURL string) (string, error) {
	const profilingEndPoint = "/profiling/v1/input"
	return url.JoinPath(agentURL, profilingEndPoint)
}
