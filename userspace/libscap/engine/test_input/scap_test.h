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

#pragma once

#include <stdint.h>
#include <stdlib.h>

//
// Structs used for testing
//

struct ppm_evt_hdr;
struct scap_threadinfo;
struct scap_fdinfo;

struct scap_test_fdinfo_data {
	const struct scap_fdinfo *fdinfos;
	size_t fdinfo_count;
};

typedef struct scap_test_thread_data scap_test_thread_data;

struct scap_test_input_data {
	struct ppm_evt_hdr **events;
	size_t event_count;

	struct scap_threadinfo *threads;
	size_t thread_count;

	struct scap_test_fdinfo_data *fdinfo_data;
};

typedef struct scap_test_input_data scap_test_input_data;

//
// Optional multi-buffer input for the test_input engine.
//
// Each buffer has its own queue of events, consumed with `scap_buffer_next()`, which mimics the
// per-CPU ring buffers of the live engines. There is no ordering between buffers: the consumer
// decides which buffer to read next. This is kept separate from `scap_test_input_data` so that
// existing users of that struct, which do not zero-initialize it, are not affected.
//
struct scap_test_input_buffer {
	struct ppm_evt_hdr **events;
	size_t event_count;
	// If non-zero, an empty buffer reports SCAP_EOF instead of SCAP_TIMEOUT.
	int eof_when_empty;
};

struct scap_test_input_buffers {
	struct scap_test_input_buffer *buffers;
	uint16_t n_buffers;
};

typedef struct scap_test_input_buffers scap_test_input_buffers;
