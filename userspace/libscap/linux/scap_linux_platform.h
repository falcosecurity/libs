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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "scap_platform_impl.h"
#include "scap_platform.h"
#include "engine_handle.h"

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
};

struct scap_linux_platform
{
	struct scap_platform m_generic;

	char* m_lasterr;
	int m_cgroup_version;
	struct scap_mountinfo* m_dev_list;
	uint32_t m_fd_lookup_limit;
	bool m_minimal_scan;

	// Function which may be called to log a debug event
	void(*m_debug_log_fn)(const char* msg);

	struct scap_engine_handle m_engine;
	const struct scap_linux_vtable* m_linux_vtable;
};

struct scap_platform* scap_linux_alloc_platform();

#ifdef __cplusplus
};
#endif
