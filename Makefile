.PHONY: all build build-debug

all: build

GO_FLAGS := -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo

build:
	go build $(GO_FLAGS)

build-debug:
	go build dd-opentelemetry-profiler-debug $(GO_FLAGS) -gcflags "all=-N -l"

GOLANGCI_LINT_VERSION = "v1.61.0"
lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) version
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run
	go run checkcopyrights.go

test:
	go test -v -race ./...
