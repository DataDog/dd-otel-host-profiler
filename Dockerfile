FROM golang:1.23.1-bookworm

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y sudo && apt-get clean autoclean && apt-get autoremove --yes 

RUN wget -qO- https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.61.0

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build
