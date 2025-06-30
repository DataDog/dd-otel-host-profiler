FROM golang:1.24.4-bookworm@sha256:ee7ff13d239350cc9b962c1bf371a60f3c32ee00eaaf0d0f0489713a87e51a67

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y sudo make && apt-get clean autoclean && apt-get autoremove --yes

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

COPY docker/dev/launch-profiler.sh /launch-profiler.sh
COPY /Makefile /tmp

RUN cd /tmp; go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(make linter-version)

VOLUME /go
