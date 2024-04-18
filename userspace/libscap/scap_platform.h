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

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif
#include <libscap/engine_handle.h>

#include <libscap/scap_procs.h>

// this header is designed to be useful to platform *users*

#ifdef __cplusplus
extern "C" {
#endif

struct scap;
struct scap_open_args;
struct scap_platform;

// allocate a generic platform handle with no behavior (no platform data is returned)
// Note: every platform alloc function needs to set up the proc_callback, since
// this needs to be called before opening the engine; otherwise the proclist callback
// won't be set up in time (for the savefile engine)
struct scap_platform* scap_generic_alloc_platform(proc_entry_callback proc_callback, void* proc_callback_context);

// initialize the common part of the platform handle
int32_t scap_generic_init_platform(struct scap_platform* platform, char* lasterr, struct scap_open_args* oargs);

// initialize a platform handle
// this calls `scap_generic_init_platform` and `init_platform` from the vtable
int32_t scap_platform_init(struct scap_platform *platform, char *lasterr, struct scap_engine_handle engine,
			   struct scap_open_args *oargs);

// close a platform
// this calls `close_platform` from the vtable and also
// does any common cleanup
int32_t scap_platform_close(struct scap_platform* platform);

// free a platform structure
// in reality, this will be a pointer to a platform-specific struct
void scap_platform_free(struct scap_platform* platform);

#ifdef __cplusplus
};
#endif
