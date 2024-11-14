FROM golang:1.23.1-bookworm@sha256:dba79eb312528369dea87532a65dbe9d4efb26439a0feacc9e7ac9b0f1c7f607

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y sudo && apt-get clean autoclean && apt-get autoremove --yes 

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0

VOLUME /go
