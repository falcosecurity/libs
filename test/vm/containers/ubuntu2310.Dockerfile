FROM docker.io/library/ubuntu:23.10

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y
RUN apt --fix-broken -y install && apt-get install -y \
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
    gcc-9 \
    gcc-10 \
    gcc-11 \
    gcc-12 \
    llvm-13 \
    clang-13 \
    gcc-13 \
    llvm-14 \
    clang-14 \
    llvm-15 \
    clang-15 \
    llvm-16 \
    clang-16

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 90
RUN update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-15 90
RUN git clone https://github.com/libbpf/bpftool.git --branch v7.2.0 --single-branch && cd bpftool && git submodule update --init && cd src && make && make install

ENTRYPOINT ["/bin/bash", "-c"]
