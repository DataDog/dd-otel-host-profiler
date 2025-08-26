FROM golang:1.24.6-bookworm@sha256:e617461712dbebf8768e10c1a5deab2833d67d2b692894cb8f4f0a3c19a8efb5

RUN cross_debian_arch=$(uname -m | sed -e 's/aarch64/amd64/'  -e 's/x86_64/arm64/'); \
    cross_pkg_arch=$(uname -m | sed -e 's/aarch64/x86-64/' -e 's/x86_64/aarch64/'); \
    dpkg --add-architecture amd64 && dpkg --add-architecture arm64 && \
    apt-get update -y && apt-get dist-upgrade -y && \
    apt-get install -y sudo less lsb-release software-properties-common \
        curl wget make git cmake unzip libc6-dev g++ gcc pkgconf \
        gcc-${cross_pkg_arch}-linux-gnu libc6-${cross_debian_arch}-cross \
        musl-dev:amd64 musl-dev:arm64 && \
    curl -sSf https://apt.llvm.org/llvm.sh | bash -s -- 17 && \
    apt-get install -y clang-format-17 && \
    apt-get clean autoclean && \
    apt-get autoremove --yes

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build

COPY /Makefile /tmp

RUN cd /tmp; go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(make linter-version)

VOLUME /go
