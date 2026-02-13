# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:24.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install base dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    git \
    clang \
    clangd \
    llvm \
    pkg-config \
    autoconf \
    automake \
    libtool \
    libelf-dev \
    wget \
    curl \
    libre2-dev \
    libtbb-dev \
    libjq-dev \
    libjsoncpp-dev \
    protobuf-compiler \
    libgtest-dev \
    libprotobuf-dev \
    linux-headers-generic \
    sudo \
    bash \
    perl \
    m4 \
    binutils \
    python3 \
    python3-pip \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install pre-commit
RUN pip3 install --break-system-packages pre-commit

# Install CMake (version >= 3.24 required)
# Download and install CMake from official releases (architecture-aware)
RUN CMAKE_VERSION="3.31.11" && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CMAKE_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        CMAKE_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -q https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.sh && \
    chmod +x cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.sh && \
    bash cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.sh --skip-license --prefix=/usr/local && \
    rm -f cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.sh && \
    /usr/local/bin/cmake --version

# Install bpftool for modern eBPF support
# Using the same approach as .github/actions/install-bpftool/action.yml
RUN BPFTOOL_VERSION="v7.3.0" && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        BPFTOOL_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        BPFTOOL_ARCH="arm64"; \
    else \
        BPFTOOL_ARCH=""; \
    fi && \
    if [ "$BPFTOOL_ARCH" = "amd64" ] || [ "$BPFTOOL_ARCH" = "arm64" ]; then \
        echo "Installing bpftool from pre-built package for $BPFTOOL_ARCH..." && \
        curl -L https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/bpftool-${BPFTOOL_VERSION}-${BPFTOOL_ARCH}.tar.gz | \
            tar -C /usr/local/bin --overwrite -xzvf - bpftool && \
        chmod +x /usr/local/bin/bpftool; \
    else \
        echo "Building bpftool from source for $ARCH..." && \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            libbpf-dev \
            libbfd-dev \
            libcap-dev \
            zlib1g-dev \
            libzstd-dev \
            && \
        git clone https://github.com/libbpf/bpftool.git --branch ${BPFTOOL_VERSION} --single-branch /tmp/bpftool && \
        cd /tmp/bpftool && \
        git submodule update --init && \
        cd src && \
        make install && \
        cd / && \
        rm -rf /tmp/bpftool && \
        rm -rf /var/lib/apt/lists/*; \
    fi && \
    bpftool version

# Create a non-root user for development.
# Use 1000:1000 to match the Docker host user (e.g. vagrant in a VM); updateRemoteUserUID is false.
# Always remove any existing user/group with that UID/GID so we can create vscode without conflicts.
ARG USER_UID=1000
ARG USER_GID=1000
RUN userdel -r ubuntu 2>/dev/null || true; \
    groupdel ubuntu 2>/dev/null || true; \
    userdel -r vscode 2>/dev/null || true; \
    groupdel vscode 2>/dev/null || true; \
    groupadd -r -g ${USER_GID} vscode && \
    useradd -r -u ${USER_UID} -g ${USER_GID} -m -s /bin/bash vscode && \
    echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    mkdir -p /home/vscode && chown -R vscode:vscode /home/vscode && \
    echo 'export PS1="\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "' >> /home/vscode/.bashrc && \
    echo 'export PATH="/usr/local/bin:$PATH"' >> /home/vscode/.bashrc

# Create and set up workspace directory with proper permissions
RUN mkdir -p /workspace && \
    chown -R vscode:vscode /workspace

# Set working directory
WORKDIR /workspace

# Copy install-deps script and run it to install third-party dependencies
# Note: This needs to run as root to install to /usr
COPY .github/install-deps.sh /tmp/install-deps.sh
RUN chmod +x /tmp/install-deps.sh && \
    mkdir -p /workspace/third_party && \
    cd /workspace && \
    /tmp/install-deps.sh && \
    rm -f /tmp/install-deps.sh && \
    chown -R vscode:vscode /workspace

# Switch to non-root user
USER vscode

# Default command
CMD ["/bin/bash"]
