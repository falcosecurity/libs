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

#include <libscap/engine_handle.h>
#include <libscap/scap_machine_info.h>
#include <libscap/scap_procs.h>

struct scap_addrlist;
struct scap_open_args;
struct scap_platform;
struct scap_proclist;
struct scap_userlist;
struct ppm_proclist_info;

// a method table for platform-specific operations
struct scap_platform_vtable
{
	// initialize the platform-specific structure
	// at this point the engine is fully initialized and operational
	int32_t (*init_platform)(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs);

	// refresh the interface list and place it inside
	// platform->m_addrlist
	int32_t (*refresh_addr_list)(struct scap_platform* platform);

	// given a mount id, return the device major:minor
	// XXX this is Linux-specific
	uint32_t (*get_device_by_mount_id)(struct scap_platform*, const char *procdir, unsigned long requested_mount_id);

	int32_t (*get_proc)(struct scap_platform*, int64_t tid, struct scap_threadinfo* tinfo, bool scan_sockets);

	int32_t (*refresh_proc_table)(struct scap_platform*, struct scap_proclist* proclist);
	bool (*is_thread_alive)(struct scap_platform*, int64_t pid, int64_t tid, const char* comm);
	int32_t (*get_global_pid)(struct scap_platform*, int64_t *pid, char *error);
	int32_t (*get_threadlist)(struct scap_platform* platform, struct ppm_proclist_info **procinfo_p, char *lasterr);
	int32_t (*get_fdlist)(struct scap_platform* platform, struct scap_threadinfo *tinfo, char *lasterr);

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
	struct scap_proclist m_proclist;

	scap_agent_info m_agent_info;
	scap_machine_info m_machine_info;
	struct ppm_proclist_info* m_driver_procinfo;
};

#ifdef __cplusplus
};
#endif
