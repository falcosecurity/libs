#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
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

# Check that the highest glibc symbol version the provided binary links against does not exceed the target ceiling.
#
# Usage: ./<script-name>.sh <binary>
#   <binary>        path to the ELF binary to inspect

set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <binary>" >&2
	exit 2
fi

BINARY="$1"
TARGET_GLIBC="GLIBC_2.17"

# Print all linked glibc symbol versions (sorted) for visibility in the CI logs.
objdump -T "$BINARY" | grep -Eo 'GLIBC_\S+' | sort -u -t "." -k1,1n -k2,2n -k3,3n

# Get the highest glibc version actually required by the binary.
LINKED_GLIBC=$(objdump -T "$BINARY" | grep -Eo 'GLIBC_\S+' | sort -u -t "." -k1,1n -k2,2n -k3,3n | tail -n1 | tr -d ')')

MAX_GLIBC=$(printf '%s\n%s\n' "$TARGET_GLIBC" "$LINKED_GLIBC" | sort -V | tail -1)
if [ "$MAX_GLIBC" != "$TARGET_GLIBC" ]; then
	echo "Binary links $LINKED_GLIBC which exceeds ceiling $TARGET_GLIBC"
	exit 1
fi
