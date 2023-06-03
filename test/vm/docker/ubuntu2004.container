FROM docker.io/library/ubuntu:20.04
# https://ubuntu.com/about/release-cycle, LTS until 2030

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG DEBIAN_FRONTEND=noninteractive

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
    llvm-7 \
    clang-7 \
    gcc-7 \
    llvm-8 \
    clang-8 \
    gcc-8 \
    llvm-9 \
    clang-9 \
    gcc-9 \
    llvm-10 \
    clang-10 \
    gcc-10

RUN ln -s -T /usr/bin/make /usr/bin/gmake

ENTRYPOINT ["/bin/bash", "-c"]
