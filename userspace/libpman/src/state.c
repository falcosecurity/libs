// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "state.h"

struct internal_state g_state = {};

static void log_msg_v(const enum falcosecurity_log_severity level, const char* fmt, va_list args) {
	if(!fmt) {
		return;
	}

	// note: `vsnprintf()` returns the number of bytes it would have written if the buffer had been
	// infinitely large, not the amount of written bytes. That's why we must cap it (see below).
	char buf[MAX_ERROR_MESSAGE_LEN];
	const int writable_bytes = vsnprintf(buf, sizeof(buf), fmt, args);
	// Append errno details if set.
	if(errno != 0 && writable_bytes >= 0) {
		// See above why we cap to `sizeof(buf) - 1`.
		const size_t offset = writable_bytes < sizeof(buf) ? writable_bytes : sizeof(buf) - 1;
		// libbpf uses -ESRCH to indicate that something could not be found, e.g. vmlinux or btf id.
		// This will be interpreted via strerror as "No such process" (which was the original
		// meaning of the error code), and it is extremely confusing. Avoid that by having a special
		// case for this error code.
		const char* err_str = errno == ESRCH ? "Object not found" : strerror(errno);
		snprintf(buf + offset, sizeof(buf) - offset, " (errno: %d | message: %s)", errno, err_str);
	}

	if(g_state.log_fn != NULL) {
		g_state.log_fn("libpman", buf, level);
	} else {
		fprintf(stderr, "libpman: %s\n", buf);
	}
}

void pman_print_errorf(const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	log_msg_v(FALCOSECURITY_LOG_SEV_ERROR, fmt, args);
	va_end(args);
}

void pman_print_msgf(const enum falcosecurity_log_severity level, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	log_msg_v(level, fmt, args);
	va_end(args);
}
