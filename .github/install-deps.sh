#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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
#

set -e

mkdir -p third_party
cd third_party

# === Valijson ===
echo "=== Building and installing valijson v1.0.6 ==="

wget "https://github.com/tristanpenman/valijson/archive/refs/tags/v1.0.6.tar.gz"

tar xzf v1.0.6.tar.gz
pushd valijson-1.0.6
cmake -B build -S . \
    -Dvalijson_INSTALL_HEADERS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -Dvalijson_BUILD_TESTS=OFF
cmake --build build --target install --parallel $(nproc)
popd


# === RE2 ===
echo "=== Building and installing re2 (v2022-06-01) ==="

wget "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz"
tar xzf 2022-06-01.tar.gz
pushd re2-2022-06-01
# see: https://github.com/google/re2/wiki/Install
cmake -B build-re2 -S . \
    -DCMAKE_BUILD_TYPE=Release \
    -DRE2_BUILD_TESTING=OFF \
    -DBUILD_SHARED_LIBS=ON
cmake --build build-re2 --target all install --parallel $(nproc)
popd

# === uthash ===
echo "=== Downloading uthash.h (1.9.8) ==="

wget -P "/usr/include" "https://raw.githubusercontent.com/troydhanson/uthash/v1.9.8/src/uthash.h"

# === BS_thread_pool ===
echo "=== Downloading BS_thread_pool.h (4.1.0) ==="

wget -P "/usr/include" "https://github.com/bshoshany/thread-pool/raw/v4.1.0/include/BS_thread_pool.hpp"

# === cxxopts ===
if [ ! -f "/usr/include/cxxopts.hpp" ]; then
    echo "=== Downloading cxxopts.hpp (3.3.1) ==="
    wget -P "/usr/include" "https://raw.githubusercontent.com/jarro2783/cxxopts/refs/tags/v3.3.1/include/cxxopts.hpp"
else
    echo "=== cxxopts.hpp already exists, skipping download ==="
fi
