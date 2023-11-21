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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include <libscap/linux/scap_cgroup.h>
#include <libscap/scap_platform_impl.h>
#include <libscap/engine_handle.h>
#include <libscap/scap_log.h>

	struct scap_mountinfo;

struct scap_linux_vtable {
	/**
	 * @brief get the vpid of a process
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param pid the pid of the process to check
	 * @param vpid output parameter, pointer to the vpid
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * `vpid` is the pid as seen by the process itself, i.e. within its
	 * PID namespace
	 */
	int32_t (*get_vpid)(struct scap_engine_handle engine, uint64_t pid, int64_t *vpid);

	/**
	 * @brief get the vtid of a process
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param tid the tid of the process to check
	 * @param vtid output parameter, pointer to the vtid
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * `vtid` is the tid as seen by the process itself, i.e. within its
	 * PID namespace
	 */
	int32_t (*get_vtid)(struct scap_engine_handle engine, uint64_t tid, int64_t *vtid);

	/**
	 * @brief get the current process id in the init pid namespace
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param pid output parameter, pointer to the pid
	 * @param error a SCAP_LASTERR_SIZE buffer for error messages
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*getpid_global)(struct scap_engine_handle engine, int64_t* pid, char* error);

	/**
	 * @brief get the list of all threads in the system, with their cpu usage
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param procinfo_p pointer to pointer to the resulting list
	 * @param lasterr pointer to a buffer of SCAP_LASTERR_SIZE bytes
	 *                for the error message (if any)
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * `procinfo_p` must not be NULL, but `*procinfo_p` may be; the returned
	 * list will be (re)allocated on demand
	 */
	int32_t (*get_threadlist)(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr);
};

struct scap_linux_platform
{
	struct scap_platform m_generic;

	char* m_lasterr;
	struct scap_mountinfo* m_dev_list;
	uint32_t m_fd_lookup_limit;
	bool m_minimal_scan;
	struct scap_cgroup_interface m_cgroups;

	// /proc scan parameters
	uint64_t m_proc_scan_timeout_ms;
	uint64_t m_proc_scan_log_interval_ms;

        falcosecurity_log_fn m_log_fn;

	struct scap_engine_handle m_engine;
	const struct scap_linux_vtable* m_linux_vtable;
};

struct scap_platform* scap_linux_alloc_platform(proc_entry_callback proc_callback, void* proc_callback_context);

#ifdef __cplusplus
};
#endif
