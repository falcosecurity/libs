FROM docker.io/library/ubuntu:22.04
# https://ubuntu.com/about/release-cycle, LTS until 2032

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG DEBIAN_FRONTEND=noninteractive

# need Docker >= 20.10.9 to not run into known issue `Problem executing scripts DPkg::Post-Invoke 'rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true'`
RUN apt-get update -y
RUN apt --fix-broken -y install && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libffi-dev \
    liblzma-dev \
    jq \
    golang \
    build-essential \
    git \
    libncurses-dev \
    pkg-config \
    autoconf \
    libtool \
    libelf-dev \
    libssl-dev \
    libc-ares-dev \
    libprotobuf-dev \
    protobuf-compiler \
    libjq-dev \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libcurl4-openssl-dev \
    libyaml-cpp-dev \
    cmake \
    rpm \
    libelf-dev \
    rpm2cpio \
    cpio \
    sudo \
    zstd \
    libc6 \
    python3 \
    python3-pip \
    gcc-9 \
    gcc-10 \
    llvm-11 \
    clang-11 \
    gcc-11 \
    llvm-12 \
    clang-12 \
    gcc-12 \
    llvm-13 \
    clang-13 \
    llvm-14 \
    clang-14

RUN pip install pandas==2.0.3 pyyaml===6.0.1 tabulate==0.9.0

ENTRYPOINT ["/bin/bash", "-c"]
