/*
Copyright (C) 2022 The Falco Authors.

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
#include "engine_handle.h"

// this header is designed to be useful to platform *users*

#ifdef __cplusplus
extern "C" {
#endif

struct scap;
struct scap_open_args;
struct scap_platform;

// allocate a generic platform handle with no behavior (no platform data is returned)
struct scap_platform* scap_generic_alloc_platform();

// initialize a platform handle
// this calls `early_init_platform` from the vtable and also
// does any common initialization
// you cannot access the engine here as it's not initialized yet
// the BPF engines (bpf, modern_bpf) depend on machine_info->boot_time
// so you need to initialize at least that if you want these engines
// to work properly
int32_t scap_platform_early_init(struct scap_platform* platform, char* lasterr, struct scap_open_args* oargs);

// initialize a platform handle
// this calls `init_platform` from the vtable
int32_t scap_platform_init(struct scap_platform* platform, struct scap_engine_handle engine, struct scap_open_args* oargs);

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
