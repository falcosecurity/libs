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

#include "test_utils.h"

#include <libscap/scap.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/filterchecks.h>
#include <libscap/strl.h>
#include <libsinsp_test_var.h>

#include <gtest/gtest.h>
#include <stdexcept>

#define DEFAULT_VALUE 0
#define INIT_TID 1
#define INIT_PID INIT_TID
#define INIT_PTID 0

class sinsp_with_test_input : public ::testing::Test
{
protected:
	sinsp_with_test_input();
	~sinsp_with_test_input();

	sinsp m_inspector;

	void open_inspector(sinsp_mode_t mode = SINSP_MODE_TEST);

	template <class ... Ts>
	void _check_event_params(const char *filename, int lineno, ppm_event_code event_type, uint32_t n, Ts && ... inputs)
	{
		uint32_t i = 0;
		std::string prefix = std::string(filename) + ":" + std::to_string(lineno) + " | ";
		// This check is mostly needed to avoid the unused warning when n is 0
		// and therefore the lambda below would never run, leaving us with event_type unused.
		if (event_type < 0 || event_type > PPM_EVENT_MAX)
		{
			throw std::runtime_error(prefix+"wrong event type: " + std::to_string(event_type));
		}
		([&]
		 {
			 const struct ppm_event_info *event_info = &scap_get_event_info_table()[event_type];
			 const struct ppm_param_info *pi = &event_info->params[i];
			 switch(pi->type)
			 {
			 case PT_INT8:
			 case PT_UINT8:
			 case PT_FLAGS8:
			 case PT_SIGTYPE:
			 case PT_L4PROTO:
			 case PT_SOCKFAMILY:
			 case PT_ENUMFLAGS8:
				 if (sizeof(inputs) != 1)
				 {
					 throw std::runtime_error(prefix+"wrong sized argument " +
								  std::to_string(i) + " passed; expected: 1B, received: " +
								  std::to_string(sizeof(inputs)) + "B");
				 }
				 break;

			 case PT_INT16:
			 case PT_UINT16:
			 case PT_SYSCALLID:
			 case PT_PORT:
			 case PT_FLAGS16:
			 case PT_ENUMFLAGS16:
				 if (sizeof(inputs) != 2)
				 {
					 throw std::runtime_error(prefix+"wrong sized argument " +
									std::to_string(i) + " passed; expected: 2B, received: " +
								  	std::to_string(sizeof(inputs)) + "B");
				 }
				 break;

			 case PT_INT32:
			 case PT_UINT32:
			 case PT_BOOL:
			 case PT_IPV4ADDR:
			 case PT_UID:
			 case PT_GID:
			 case PT_FLAGS32:
			 case PT_SIGSET:
			 case PT_MODE:
			 case PT_ENUMFLAGS32:
				 if (sizeof(inputs) != 4)
				 {
					 throw std::runtime_error(prefix+"wrong sized argument " +
								  std::to_string(i) + " passed; expected: 4B, received: " +
								  std::to_string(sizeof(inputs)) + "B");
				 }
				 break;

			 case PT_INT64:
			 case PT_UINT64:
			 case PT_ERRNO:
			 case PT_FD:
			 case PT_PID:
			 case PT_RELTIME:
			 case PT_ABSTIME:
			 case PT_DOUBLE:
				 if (sizeof(inputs) != 8)
				 {
					 throw std::runtime_error(prefix+"wrong sized argument " +
								  std::to_string(i) + " passed; expected: 8B, received: " +
								  std::to_string(sizeof(inputs)) + "B");
				 }
				 break;
			 default:
				 // we only assert integer-like arguments that are the most common failures.
				 break;
			 }
			 i++;
		 } (), ...);
		if (i != n)
		{
			throw std::runtime_error(prefix+"wrong number of arguments: specified " +
						 std::to_string(n) + " but passed: " + std::to_string(i));
		}
	}

#define add_event(ts, tid, code, n, ...) \
        			_add_event(ts, tid, code, n, ##__VA_ARGS__); \
 				_check_event_params(__FILE__, __LINE__, code, n, ##__VA_ARGS__)

	scap_evt* _add_event(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, ...);
	sinsp_evt* advance_ts_get_event(uint64_t ts);

#define add_event_advance_ts(ts, tid, code, n, ...) \
                        	_add_event_advance_ts(ts, tid, code, n, ##__VA_ARGS__); \
				_check_event_params(__FILE__, __LINE__, code, n, ##__VA_ARGS__)

	sinsp_evt* _add_event_advance_ts(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, ...);
	sinsp_evt* add_event_advance_ts_v(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, va_list args);
	scap_evt* create_event_v(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, va_list args);
	scap_evt* add_event_v(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, va_list args);
	scap_evt* add_async_event(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, ...);
	scap_evt* add_async_event_v(uint64_t ts, uint64_t tid, ppm_event_code, uint32_t n, va_list args);

	//=============================== PROCESS GENERATION ===========================

	// Allowed event types: PPME_SYSCALL_CLONE_20_X, PPME_SYSCALL_FORK_20_X, PPME_SYSCALL_VFORK_20_X, PPME_SYSCALL_CLONE3_X
	sinsp_evt* generate_clone_x_event(int64_t retval, int64_t tid, int64_t pid, int64_t ppid, uint32_t flags = 0,
					  int64_t vtid = DEFAULT_VALUE, int64_t vpid = DEFAULT_VALUE,
					  const std::string& name = "bash", const std::vector<std::string>& cgroup_vec = {},
					  ppm_event_code event_type = PPME_SYSCALL_CLONE_20_X);
	sinsp_evt* generate_execve_enter_and_exit_event(int64_t retval, int64_t old_tid, int64_t new_tid, int64_t pid,
							int64_t ppid, const std::string& pathname = "/bin/test-exe",
							const std::string& comm = "test-exe",
							const std::string& resolved_kernel_path = "/bin/test-exe",
							const std::vector<std::string>& cgroup_vec = {});
	void remove_thread(int64_t tid_to_remove, int64_t reaper_tid);
	sinsp_evt* generate_proc_exit_event(int64_t tid_to_remove, int64_t reaper_tid);
	sinsp_evt* generate_random_event(int64_t tid_caller = INIT_TID);
	sinsp_evt* generate_getcwd_failed_entry_event(int64_t tid_caller = INIT_TID);

	//=============================== PROCESS GENERATION ===========================

	void add_thread(const scap_threadinfo&, const std::vector<scap_fdinfo>&);
	void set_threadinfo_last_access_time(int64_t tid, uint64_t access_time_ns);
	void remove_inactive_threads(uint64_t m_lastevent_ts, uint64_t thread_timeout);

	static scap_threadinfo create_threadinfo(
		uint64_t tid, uint64_t pid, uint64_t ptid, uint64_t vpgid, int64_t vtid, int64_t vpid,
		const std::string& comm, const std::string& exe, const std::string& exepath,
		uint64_t clone_ts, uint32_t uid, uint32_t gid,
		const std::vector<std::string>& args, uint64_t sid, const std::vector<std::string>& env,
		const std::string& cwd,
		int64_t fdlimit = 0x100000, uint32_t flags = 0, bool exe_writable = true,
		uint64_t cap_permitted = 0x1ffffffffff, uint64_t cap_inheritable = 0, uint64_t cap_effective = 0x1ffffffffff,
		uint32_t vmsize_kb = 10000, uint32_t vmrss_kb = 100, uint32_t vmswap_kb = 0, uint64_t pfmajor = 222, uint64_t pfminor = 22,
		const std::vector<std::string>& cgroups = {}, const std::string& root = "/",
		int filtered_out = 0, uint32_t tty = 0, uint32_t loginuid = UINT32_MAX, bool exe_upper_layer = false, bool exe_from_memfd = false);

	void add_default_init_thread();
	void add_simple_thread(int64_t tid, int64_t pid, int64_t ptid, const std::string& comm = "random");
	uint64_t increasing_ts();
	bool field_exists(sinsp_evt*, std::string_view field_name);
	bool field_exists(sinsp_evt*, std::string_view field_name, filter_check_list&);
	bool field_has_value(sinsp_evt*, std::string_view field_name);
	bool field_has_value(sinsp_evt*, std::string_view field_name, filter_check_list&);
	std::string get_field_as_string(sinsp_evt*, std::string_view field_name);
	std::string get_field_as_string(sinsp_evt*, std::string_view field_name, filter_check_list&);
	sinsp_evt* next_event();

	scap_test_input_data m_test_data;
	std::vector<scap_evt*> m_events;
	std::vector<scap_evt*> m_async_events;

	std::vector<scap_threadinfo> m_threads;
	std::vector<std::vector<scap_fdinfo>> m_fdinfos;
	std::vector<scap_test_fdinfo_data> m_test_fdinfo_data;
	sinsp_filter_check_list m_default_filterlist;

	uint64_t m_test_timestamp = 1566230400000000000;
	uint64_t m_last_recorded_timestamp = 0;
};
