FROM golang:1.24.2-bookworm@sha256:79390b5e5af9ee6e7b1173ee3eac7fadf6751a545297672916b59bfa0ecf6f71

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y sudo make && apt-get clean autoclean && apt-get autoremove --yes

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

COPY docker/dev/launch-profiler.sh /launch-profiler.sh
COPY /Makefile /tmp

RUN cd /tmp; go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(make linter-version)

VOLUME /go
