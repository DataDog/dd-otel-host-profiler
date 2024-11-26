.PHONY: all

BINARIES=helloworld \
	helloworld.pie \
	helloworld.stripped.pie

GO = $(shell go env GOROOT)/bin/go

all: $(BINARIES)

clean:
	rm -f $(BINARIES)

helloworld:
	$(GO) build -o $@ helloworld.go

helloworld.pie:
	$(GO) build -buildmode=pie -o $@ helloworld.go

helloworld.stripped.pie:
	$(GO) build -buildmode=pie -ldflags="-s -w" -o $@ helloworld.go
