package main

import (
	"reflect"
	"testing"

	"github.com/DataDog/dd-otel-host-profiler/reporter"
)

func TestValidateTags(t *testing.T) {
	tests := []struct {
		name string
		tags string
		want reporter.Tags
	}{
		{
			name: "empty tags",
			tags: "",
			want: nil,
		},
		{
			name: "valid tags",
			tags: "env:dev,service:web",
			want: reporter.Tags{reporter.MakeTag("env", "dev"), reporter.MakeTag("service", "web")},
		},
		{
			name: "invalid tag",
			tags: "env:dev,service:web,#invalid:tag",
			want: reporter.Tags{reporter.MakeTag("env", "dev"), reporter.MakeTag("service", "web")},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ValidateTags(test.tags)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("ValidateTags(%q) = %v, want %v", test.tags, got, test.want)
			}
		})
	}
}
