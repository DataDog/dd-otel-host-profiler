FROM golang:1.23.6-bookworm@sha256:441f59f8a2104b99320e1f5aaf59a81baabbc36c81f4e792d5715ef09dd29355

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y sudo && apt-get clean autoclean && apt-get autoremove --yes 

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0

VOLUME /go
