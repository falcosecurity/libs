// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once
#include <unistd.h>
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <libscap/scap_assert.h>

// Strive to read exactly `count` bytes from `fd` into `buff`. Read fewer bytes if an error other
// than `EINTR` occurs or EOF is reached before reading them. The return value has the same semantic
// of the `read()` system call return value.
// note: `noinline` is needed in order to avoid GCC from messing out with `buff` boundaries and
// telling that the underlying read operation could overflow.
// note: `unused` is needed in order to avoid GCC to complain about source files including this
// header while not using this function.
static ssize_t __attribute__((noinline, unused)) read_exact(const int fd,
                                                            void *buff,
                                                            const size_t count) {
	size_t total_read_bytes = 0;
	while(1) {
		const ssize_t read_bytes =
		        read(fd, (char *)buff + total_read_bytes, count - total_read_bytes);
		if(read_bytes == -1) {
			// Re-attempt read upon signal.
			if(errno == EINTR) {
				continue;
			}
			return read_bytes;
		}

		if(read_bytes == 0) {
			return total_read_bytes;
		}

		total_read_bytes += read_bytes;
		if(total_read_bytes == count) {
			return count;
		}
	}

	// Unreachable.
	ASSERT(false);
	return total_read_bytes;
}
