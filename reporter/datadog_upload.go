// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"time"
)

type profileData struct {
	name string
	data []byte
}

func uploadProfiles(ctx context.Context, profiles []profileData, startTime, endTime time.Time,
	url string, tags Tags, profilerVersion string, apiKey string, containerID string) error {
	contentType, body, err := buildMultipartForm(profiles, startTime, endTime, tags)
	if err != nil {
		return err
	}

	// If you want a timeout, you can use context.WithTimeout
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Dd-Evp-Origin", profilerName)
	req.Header.Set("Dd-Evp-Origin-Version", profilerVersion)
	if apiKey != "" {
		req.Header.Set("Dd-Api-Key", apiKey)
	}
	if containerID != "" {
		req.Header.Set("Datadog-Container-ID", containerID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		// Success!
		return nil
	}
	return errors.New(resp.Status)
}

type uploadEvent struct {
	Start       string   `json:"start"`
	End         string   `json:"end"`
	Attachments []string `json:"attachments"`
	Tags        string   `json:"tags_profiler"`
	Family      string   `json:"family"`
	Version     string   `json:"version"`
}

func (t Tags) String() string {
	var buf bytes.Buffer
	for i, tag := range t {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(tag.Key)
		buf.WriteString(":")
		buf.WriteString(tag.Value)
	}
	return buf.String()
}

func buildMultipartForm(profiles []profileData, startTime, endTime time.Time,
	tags Tags) (string, io.Reader, error) {
	var buf bytes.Buffer

	mw := multipart.NewWriter(&buf)

	event := &uploadEvent{
		Version: "4",
		Family:  "native",
		Start:   startTime.Format(time.RFC3339Nano),
		End:     endTime.Format(time.RFC3339Nano),
		Tags:    tags.String(),
	}

	for _, p := range profiles {
		event.Attachments = append(event.Attachments, p.name)
		f, err := mw.CreateFormFile(p.name, p.name)
		if err != nil {
			return "", nil, err
		}
		if _, err = f.Write(p.data); err != nil {
			return "", nil, err
		}
	}

	f, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="event"; filename="event.json"`},
		"Content-Type":        []string{"application/json"},
	})
	if err != nil {
		return "", nil, err
	}
	if err := json.NewEncoder(f).Encode(event); err != nil {
		return "", nil, err
	}

	if err := mw.Close(); err != nil {
		return "", nil, err
	}
	return mw.FormDataContentType(), &buf, nil
}
