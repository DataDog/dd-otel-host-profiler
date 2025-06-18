FROM golang:1.24.2-bookworm@sha256:79390b5e5af9ee6e7b1173ee3eac7fadf6751a545297672916b59bfa0ecf6f71

RUN cross_debian_arch=$(uname -m | sed -e 's/aarch64/amd64/'  -e 's/x86_64/arm64/'); \
    cross_pkg_arch=$(uname -m | sed -e 's/aarch64/x86-64/' -e 's/x86_64/aarch64/'); \
    dpkg --add-architecture amd64 && dpkg --add-architecture arm64 && \
    apt-get update -y && apt-get dist-upgrade -y && \
    apt-get install -y sudo less lsb-release software-properties-common \
        curl wget make git cmake unzip libc6-dev g++ gcc pkgconf \
        gcc-${cross_pkg_arch}-linux-gnu libc6-${cross_debian_arch}-cross \
        musl-dev:amd64 musl-dev:arm64 && \
    apt-get clean autoclean && \
    apt-get autoremove --yes

RUN curl -sSf https://apt.llvm.org/llvm.sh | bash -s -- 17

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

# Create rust related directories in /usr/local
RUN mkdir -p /usr/local/cargo /usr/local/rustup

# Set environment variable before rustup installation
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup

# Install rustup and cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.77

# Add rust related environment variables
ENV PATH="/usr/local/cargo/bin:$PATH"

RUN chmod -R a+w /usr/local/rustup      \
    && chmod -R a+w /usr/local/cargo

USER build

COPY docker/dev/launch-profiler.sh /launch-profiler.sh
COPY /Makefile /tmp

RUN cd /tmp; go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(make linter-version)

VOLUME /go
WORKDIR /app
