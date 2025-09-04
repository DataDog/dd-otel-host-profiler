.PHONY: all build extract_symbols

VERSION ?= v0.0.0
VERSION_LD_FLAGS := -X github.com/DataDog/dd-otel-host-profiler/version.version=$(VERSION)

GO_FLAGS := -ldflags="${VERSION_LD_FLAGS} -extldflags=-static" -tags osusergo,netgo,debugtracer

all: build

build:
	go build $(GO_FLAGS)

GOLANGCI_LINT_VERSION = "v2.1.6"
GO = $(shell go env GOROOT)/bin/go

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) version
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

linter-version:
	@echo $(GOLANGCI_LINT_VERSION)

test:
	go test -v -race ./...

check-copyrights:
	$(GO) run tools/checkcopyright.go

licenses:
	tools/make-licenses.sh

check-licenses:
	tools/check-licenses.sh

docker-image:
	docker build -t dd-otel-host-profiler -f docker/dev/Dockerfile .

profiler-in-docker: docker-image
	docker run -v "$$PWD":/app -it --rm --user $(shell id -u):$(shell id -g) dd-otel-host-profiler \
	   bash -c "cd /app && make VERSION=$(VERSION)"

extract_symbols:
	go build $(GO_FLAGS) ./tools/extract_symbols
