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

#include <functional>
#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/state/dynamic_struct.h>

class sinsp_filter_check_thread : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_EXE = 0,
		TYPE_PEXE,
		TYPE_AEXE,
		TYPE_CONCAT_AEXE,
		TYPE_EXEPATH,
		TYPE_PEXEPATH,
		TYPE_AEXEPATH,
		TYPE_CONCAT_AEXEPATH,
		TYPE_NAME,
		TYPE_PNAME,
		TYPE_ANAME,
		TYPE_CONCAT_ANAME,
		TYPE_ARGS,
		TYPE_CMDLINE,
		TYPE_PCMDLINE,
		TYPE_ACMDLINE,
		TYPE_CMDNARGS,
		TYPE_CMDLENARGS,
		TYPE_EXELINE,
		TYPE_ENV,
		TYPE_AENV,
		TYPE_CWD,
		TYPE_LOGINSHELLID,
		TYPE_TTY,
		TYPE_PID,
		TYPE_PPID,
		TYPE_APID,
		TYPE_VPID,
		TYPE_PVPID,
		TYPE_SID,
		TYPE_SNAME,
		TYPE_SID_EXE,
		TYPE_SID_EXEPATH,
		TYPE_VPGID,
		TYPE_VPGID_NAME,
		TYPE_VPGID_EXE,
		TYPE_VPGID_EXEPATH,
		TYPE_DURATION,
		TYPE_PPID_DURATION,
		TYPE_PID_CLONE_TS,
		TYPE_PPID_CLONE_TS,
		TYPE_IS_EXE_WRITABLE,
		TYPE_IS_EXE_UPPER_LAYER,
		TYPE_IS_EXE_FROM_MEMFD,
		TYPE_IS_SID_LEADER,
		TYPE_IS_VPGID_LEADER,
		TYPE_EXE_INO,
		TYPE_EXE_INO_CTIME,
		TYPE_EXE_INO_MTIME,
		TYPE_EXE_INO_CTIME_DURATION_CLONE_TS,
		TYPE_EXE_INO_CTIME_DURATION_PIDNS_START,
		TYPE_PIDNS_INIT_START_TS,
		TYPE_CAP_PERMITTED,
		TYPE_CAP_INHERITABLE,
		TYPE_CAP_EFFECTIVE,
		TYPE_IS_CONTAINER_HEALTHCHECK,
		TYPE_IS_CONTAINER_LIVENESS_PROBE,
		TYPE_IS_CONTAINER_READINESS_PROBE,
		TYPE_FDOPENCOUNT,
		TYPE_FDLIMIT,
		TYPE_FDUSAGE,
		TYPE_VMSIZE,
		TYPE_VMRSS,
		TYPE_VMSWAP,
		TYPE_PFMAJOR,
		TYPE_PFMINOR,
		TYPE_TID,
		TYPE_ISMAINTHREAD,
		TYPE_VTID,
		TYPE_NAMETID,
		TYPE_EXECTIME,
		TYPE_TOTEXECTIME,
		TYPE_CGROUPS,
		TYPE_CGROUP,
		TYPE_NTHREADS,
		TYPE_NCHILDS,
		TYPE_THREAD_CPU,
		TYPE_THREAD_CPU_USER,
		TYPE_THREAD_CPU_SYSTEM,
		TYPE_THREAD_VMSIZE,
		TYPE_THREAD_VMRSS,
		TYPE_THREAD_VMSIZE_B,
		TYPE_THREAD_VMRSS_B,
	};

	sinsp_filter_check_thread();
	virtual ~sinsp_filter_check_thread() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;

	int32_t get_argid() const;

protected:
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;
	bool compare_nocache(sinsp_evt*) override;

private:
	uint64_t extract_exectime(sinsp_evt *evt);
	int32_t extract_arg(std::string fldname, std::string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_thread_cpu(sinsp_evt *evt, OUT uint32_t* len, sinsp_threadinfo* tinfo, bool extract_user, bool extract_system);
	sinsp_threadinfo* get_main_thread(sinsp_threadinfo* tinfo);
	inline bool compare_full_apid(sinsp_evt *evt);
	bool compare_full_aname(sinsp_evt *evt);
	bool compare_full_aexe(sinsp_evt *evt);
	bool compare_full_aexepath(sinsp_evt *evt);
	bool compare_full_acmdline(sinsp_evt *evt);
	bool compare_full_aenv(sinsp_evt *evt);

	template<typename T>
	std::string concat_attribute_thread_hierarchy(sinsp_threadinfo* mt, int32_t m_argid, const std::function<T(sinsp_threadinfo*)>& get_attribute_func)
	{
		// nullptr check of mt is done within each filtercheck prior to calling this function
		static_assert(std::is_convertible<T, std::string>::value, "T must be convertible to std::string");
		std::string result = get_attribute_func(mt);

		for (int32_t j = 0; j < m_argid; j++)
		{
			mt = mt->get_parent_thread();
			if(mt == NULL)
			{
				return result;
			}
			result = get_attribute_func(mt) + "->" + result;
		}

		return result;
	}

	template<typename T>
	std::string extract_leader_attribute_thread_hierarchy(sinsp_threadinfo* tinfo, const std::function<int64_t(sinsp_threadinfo*)>& get_thread_attribute_func, const std::function<T(sinsp_threadinfo*)>& get_attribute_func)
	{
		// nullptr check of tinfo is done prior to calling this function
		static_assert(std::is_convertible<T, std::string>::value, "T must be convertible to std::string");
		int64_t thread_attribute = get_thread_attribute_func(tinfo);

		if (!tinfo->is_in_pid_namespace())
		{
			// `threadinfo` lookup only applies when the process is running on the host and not in a PID namespace.
			sinsp_threadinfo* attribute_info = m_inspector->get_thread_ref(thread_attribute, false, true).get();
			if (attribute_info != NULL)
			{
				return get_attribute_func(attribute_info);
			}
		}

		// However, if the leader process has exited or if the process is running in a PID namespace, we instead 
		// traverse the process lineage until we find a match.
		// Find the highest ancestor process that has the same id and declare it to be the leader.
		sinsp_threadinfo* leader = tinfo;
		sinsp_threadinfo::visitor_func_t visitor = [thread_attribute, &leader, get_thread_attribute_func](sinsp_threadinfo* pt)
		{
			if (get_thread_attribute_func(pt) != thread_attribute)
			{
				return false;
			}
			leader = pt;
			return true;
		};

		tinfo->traverse_parent_state(visitor);
		return get_attribute_func(leader);
	}

	int32_t m_argid;
	std::string m_argname;
	uint32_t m_tbool;
	std::string m_tstr;
	uint64_t m_u64val;
	int64_t m_s64val;
	double m_dval;
	std::vector<uint64_t> m_last_proc_switch_times;
	std::unique_ptr<libsinsp::state::dynamic_struct::field_accessor<uint64_t>> m_thread_dyn_field_accessor;
};
