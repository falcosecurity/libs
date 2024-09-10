// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <stdio.h>
#include <stdint.h>

// Debugging Macros
#define RINGBUF_DEBUGGING 0

#if RINGBUF_DEBUGGING
// R_D stands for Ringbuffer Debugging
#define R_D_MSG(...) printf(__VA_ARGS__)

#define R_D_EVENT(event, ring_id)                                    \
	if(event == NULL) {                                              \
		R_D_MSG("[NULL Event] buf: %d\n", ring_id);                  \
	} else {                                                         \
		R_D_MSG("[Event] ts: %ld, buf: %d\n", (event)->ts, ring_id); \
	}

#else
#define R_D_MSG(...)
#define R_D_EVENT(event, ring_id)
#endif
