FROM debian:buster

LABEL usage="docker run -i -t -v /path/to/source:/workspace libs-builder [cmake options]"

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    build-essential \
    clang \
    llvm \
    git \
    libncurses-dev \
    pkg-config \
    autoconf \ 
    automake \
    libtool \
    libelf-dev \
    wget \
    libb64-dev \
    libc-ares-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libtbb-dev \
    libjq-dev \
    libjsoncpp-dev \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libgtest-dev \
    libprotobuf-dev \
    linux-headers-${TARGETARCH} \
    && apt-get clean

COPY build.sh /
RUN chmod +x /build.sh

WORKDIR /workspace

ENTRYPOINT ["/build.sh"]
