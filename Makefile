.PHONY: all build build-debug

all: build

GO_FLAGS := -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo

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
