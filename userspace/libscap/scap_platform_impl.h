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

#include <stdbool.h>
#include <stdint.h>

// this header is designed to be useful to platform *implementors*
// i.e. different platforms

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "engine_handle.h"

struct scap_addrlist;
struct scap_open_args;
struct scap_platform;
struct scap_userlist;

// a method table for platform-specific operations
struct scap_platform_vtable
{
	// early initialization the platform-specific structure
	// you cannot access the engine here as it's not initialized yet
	// the BPF engines (bpf, modern_bpf) depend on machine_info->boot_time
	// so you need to initialize at least that if you want these engines
	// to work properly
	int32_t (*early_init_platform)(struct scap_platform* platform, char* lasterr, struct scap_open_args* oargs);
	// initialize the platform-specific structure
	int32_t (*init_platform)(struct scap_platform* platform, struct scap_engine_handle engine, struct scap_open_args* oargs);

	// refresh the interface list and place it inside
	// platform->m_addrlist
	int32_t (*refresh_addr_list)(struct scap_platform* platform);

	// close the platform structure
	// clean up all data, make it ready for another call to `init_platform`
	int32_t (*close_platform)(struct scap_platform* platform);

	// free the structure
	// it must have been previously closed (using `close_platform`)
	// to ensure there are no memory leaks
	void (*free_platform)(struct scap_platform* platform);
};

// the parts of the platform struct shared across all implementations
// this *must* be the first member of all implementations
// (the pointers are cast back&forth between the two)
struct scap_platform
{
	const struct scap_platform_vtable* m_vtable;
	struct scap_addrlist *m_addrlist;
	struct scap_userlist *m_userlist;
};

#ifdef __cplusplus
};
#endif
