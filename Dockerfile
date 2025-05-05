FROM golang:1.24.2-bookworm@sha256:79390b5e5af9ee6e7b1173ee3eac7fadf6751a545297672916b59bfa0ecf6f71

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y sudo && apt-get clean autoclean && apt-get autoremove --yes 

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0

VOLUME /go
