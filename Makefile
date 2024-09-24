.PHONY: all build build-debug

VERSION ?= v0.0.0
VERSION_LD_FLAGS := -X github.com/DataDog/dd-otel-host-profiler/version.version=$(VERSION)
GO_FLAGS := -ldflags="${VERSION_LD_FLAGS} -extldflags=-static" -tags osusergo,netgo 

all: build

build:
	go build $(GO_FLAGS)

GOLANGCI_LINT_VERSION = "v1.61.0"
lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) version
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run
	go run checkcopyrights.go

linter-version:
	@echo $(GOLANGCI_LINT_VERSION)

test:
	go test -v -race ./...
