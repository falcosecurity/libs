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

#include <gtest/gtest.h>
#include <stdexcept>

#include "scap.h"
#include "sinsp.h"
#include "filterchecks.h"
#include "strl.h"
#include "test_utils.h"
#include <libsinsp_test_var.h>

#define DEFAULT_VALUE 0
#define INIT_TID 1
#define INIT_PID INIT_TID
#define INIT_PTID 0
#define UNUSED __attribute__((unused))

class sinsp_with_test_input : public ::testing::Test {
protected:
	void SetUp() override
	{
		m_test_data = std::unique_ptr<scap_test_input_data>(new scap_test_input_data);
		m_test_data->event_count = 0;
		m_test_data->events = nullptr;
		m_test_data->thread_count = 0;
		m_test_data->threads = nullptr;

		m_test_timestamp = 1566230400000000000;
		m_last_recorded_timestamp = 0;
	}

	void TearDown() override
	{
		for (size_t i = 0; i < m_events.size(); i++)
		{
			free(m_events[i]);
		}
	}

	sinsp m_inspector;

	void open_inspector(scap_mode_t mode = SCAP_MODE_TEST) {
		m_inspector.open_test_input(m_test_data.get(), mode);
	}

	scap_evt* add_event(uint64_t ts, uint64_t tid, ppm_event_code event_type, uint32_t n, ...)
	{
		va_list args;
		va_start(args, n);
		scap_evt *ret = add_event_v(ts, tid, event_type, n, args);
		va_end(args);

		return ret;
	}

	sinsp_evt* advance_ts_get_event(uint64_t ts)
	{
		sinsp_evt *sinsp_event;
		for (sinsp_event = next_event(); sinsp_event != nullptr; sinsp_event = next_event()) {
			if (sinsp_event->get_ts() == ts) {
				return sinsp_event;
			}
		}

		return nullptr;
	}

	// adds an event and advances the inspector to the new timestamp
	sinsp_evt* add_event_advance_ts(uint64_t ts, uint64_t tid, ppm_event_code event_type, uint32_t n, ...)
	{
		va_list args;
		va_start(args, n);
		sinsp_evt *ret = add_event_advance_ts_v(ts, tid, event_type, n, args);
		va_end(args);

		return ret;
	}

	sinsp_evt* add_event_advance_ts_v(uint64_t ts, uint64_t tid, ppm_event_code event_type, uint32_t n, va_list args)
	{
		add_event_v(ts, tid, event_type, n, args);
		sinsp_evt *sinsp_event = advance_ts_get_event(ts);
		if (sinsp_event != nullptr) {
			return sinsp_event;
		}

		throw std::runtime_error("could not retrieve last event or internal error (event vector size: " + std::to_string(m_events.size()) + std::string(")"));
	}

	scap_evt* add_event_v(uint64_t ts, uint64_t tid, ppm_event_code event_type, uint32_t n, va_list args)
	{
		struct scap_sized_buffer event_buf = {NULL, 0};
		size_t event_size = 0;
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args2;
		va_copy(args2, args);

		if (ts <= m_last_recorded_timestamp) {
			va_end(args2);
			throw std::runtime_error("the test framework does not currently support equal timestamps or out of order events");
		}

		int32_t ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);

		if(ret != SCAP_INPUT_TOO_SMALL) {
			va_end(args2);
			return nullptr;
		}

		event_buf.buf = malloc(event_size);
		event_buf.size = event_size;

		if(event_buf.buf == NULL) {
			va_end(args2);
			return nullptr;
		}

		ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args2);

		if(ret != SCAP_SUCCESS) {
			free(event_buf.buf);
			event_buf.size = 0;
			va_end(args2);
			return nullptr;
		}

		scap_evt *event = static_cast<scap_evt*>(event_buf.buf);
		event->ts = ts;
		event->tid = tid;

		uint64_t evtoffset = m_events.size() - m_test_data->event_count;
		m_events.push_back(event);
		m_test_data->events = m_events.data() + evtoffset;
		m_test_data->event_count = m_events.size() - evtoffset;
		m_last_recorded_timestamp = ts;

		va_end(args2);
		return event;
	}

	/*=============================== PROCESS GENERATION ===========================*/

	sinsp_evt* generate_clone_x_event(int64_t retval, int64_t tid, int64_t pid, int64_t ppid, uint32_t flags = 0, int64_t vtid = DEFAULT_VALUE, int64_t vpid = DEFAULT_VALUE, std::string name = "bash")
	{
		if(vtid == DEFAULT_VALUE)
		{
			vtid = tid;
		}

		if(vpid == DEFAULT_VALUE)
		{
			vpid = pid;
		}

		/* Scaffolding needed to call the PPME_SYSCALL_CLONE_20_X */
		uint64_t not_relevant_64 = 0;
		uint32_t not_relevant_32 = 0;
		scap_const_sized_buffer empty_bytebuf = {/*.buf =*/ nullptr, /*.size =*/ 0};
		return add_event_advance_ts(increasing_ts(), tid, PPME_SYSCALL_CLONE_20_X, 20, retval, name.c_str(), empty_bytebuf, tid, pid, ppid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, name.c_str(), empty_bytebuf, flags, not_relevant_32, not_relevant_32, vtid, vpid);
	}

	sinsp_evt* generate_execve_enter_and_exit_event(int64_t retval, int64_t old_tid, int64_t new_tid, int64_t pid, int64_t ppid, std::string pathname = "/bin/test-exe", std::string comm = "test-exe", std::string resolved_kernel_path = "/bin/test-exe")
	{
		/* Scaffolding needed to call the PPME_SYSCALL_EXECVE_19_X */
		uint64_t not_relevant_64 = 0;
		uint32_t not_relevant_32 = 0;
		scap_const_sized_buffer empty_bytebuf = {/*.buf =*/ nullptr, /*.size =*/ 0};

		add_event_advance_ts(increasing_ts(), old_tid, PPME_SYSCALL_EXECVE_19_E, 1, pathname.c_str());
		/* we have an `old_tid` and a `new_tid` because if a secondary thread calls the
		 * execve the thread leader will take control so the `tid` between enter and exit event
		 * will change
		 * */
		return add_event_advance_ts(increasing_ts(), new_tid, PPME_SYSCALL_EXECVE_19_X, 28, retval, pathname.c_str(), empty_bytebuf, new_tid, pid, ppid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, comm.c_str(), empty_bytebuf, empty_bytebuf, not_relevant_32, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, resolved_kernel_path.c_str());
	}

	void remove_thread(int64_t tid_to_remove, int64_t reaper_tid)
	{
		generate_proc_exit_event(tid_to_remove, reaper_tid);
		/* Generate a random event on init to trigger the removal after proc exit */
		generate_random_event();
	}

	sinsp_evt* generate_proc_exit_event(int64_t tid_to_remove, int64_t reaper_tid)
	{
		/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
		int64_t not_relevant_64 = 0;
		uint8_t not_relevant_8 = 0;

		return add_event_advance_ts(increasing_ts(), tid_to_remove, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64, not_relevant_8, not_relevant_8, reaper_tid);
	}

	sinsp_evt* generate_random_event(int64_t tid_caller = INIT_TID)
	{
		/* Generate a random event on init to trigger the removal after proc exit */
		return add_event_advance_ts(increasing_ts(), tid_caller, PPME_SYSCALL_GETCWD_E, 0);
	}

	/*=============================== PROCESS GENERATION ===========================*/

	void add_thread(const scap_threadinfo &tinfo, const std::vector<scap_fdinfo> &fdinfos)
	{
		m_threads.push_back(tinfo);
		m_test_data->threads = m_threads.data();
		m_test_data->thread_count = m_threads.size();

		m_fdinfos.push_back(fdinfos);
		scap_test_fdinfo_data fdinfo_descriptor = {
			/*.fdinfos =*/ m_fdinfos.back().data(),
			/*.fdinfo_count =*/ m_fdinfos.back().size()
		};
		m_test_fdinfo_data.push_back(fdinfo_descriptor);

		m_test_data->fdinfo_data = m_test_fdinfo_data.data();
	}

	void set_threadinfo_last_access_time(int64_t tid, uint64_t access_time_ns)
	{
		auto tinfo = m_inspector.get_thread_ref(tid, false).get();
		if(tinfo != nullptr)
		{
			tinfo->m_lastaccess_ts = access_time_ns;
		}
		else
		{
			throw sinsp_exception("There is no thread info associated with tid: " + std::to_string(tid));
		}
	}

	/* Remove all threads with `tinfo->m_lastaccess_ts` minor than `m_lastevent_ts - thread_timeout` */
	void remove_inactive_threads(uint64_t m_lastevent_ts, uint64_t thread_timeout)
	{
		/* We need to set these 2 variables to enable the remove_inactive_logic */
		m_inspector.m_thread_manager->m_last_flush_time_ns = 1;
		m_inspector.m_inactive_thread_scan_time_ns = 2;

		m_inspector.m_lastevent_ts = m_lastevent_ts;
		m_inspector.m_thread_timeout_ns = thread_timeout;
		m_inspector.remove_inactive_threads();
	}

	static scap_threadinfo create_threadinfo(
		uint64_t tid, uint64_t pid, uint64_t ptid, uint64_t vpgid, int64_t vtid, int64_t vpid,
		std::string comm, std::string exe, std::string exepath, uint64_t clone_ts, uint32_t uid, uint32_t gid,

		std::vector<std::string> args={}, uint64_t sid=0, std::vector<std::string> env={}, std::string cwd="/test",
		int64_t fdlimit=0x100000, uint32_t flags=0, bool exe_writable=true, 
		uint64_t cap_permitted=0x1ffffffffff, uint64_t cap_inheritable=0, uint64_t cap_effective=0x1ffffffffff,
		uint32_t vmsize_kb=10000, uint32_t vmrss_kb=100, uint32_t vmswap_kb=0, uint64_t pfmajor=222, uint64_t pfminor=22,
		std::vector<std::string> cgroups={}, std::string root="/", int filtered_out=0, uint32_t tty=0, uint32_t loginuid=UINT32_MAX)
	{
		scap_threadinfo tinfo = {};
		tinfo.tid = tid;
		tinfo.pid = pid;
		tinfo.ptid = ptid;
		tinfo.sid = sid;
		tinfo.vpgid = vpgid;
		tinfo.exe_writable = exe_writable;
		tinfo.fdlimit = fdlimit;
		tinfo.flags = flags;
		tinfo.uid = uid;
		tinfo.gid = gid;
		tinfo.cap_permitted = cap_permitted;
		tinfo.cap_effective = cap_effective;
		tinfo.cap_inheritable = cap_inheritable;
		tinfo.vmsize_kb = vmsize_kb;
		tinfo.vmrss_kb = vmrss_kb;
		tinfo.pfmajor = pfmajor;
		tinfo.pfminor = pfminor;
		tinfo.vtid = vtid;
		tinfo.vpid = vpid;
		tinfo.filtered_out = filtered_out;
		tinfo.fdlist = nullptr;
		tinfo.clone_ts = clone_ts;
		tinfo.tty = tty;
		tinfo.loginuid = loginuid;

		std::string argsv = "";
		if (!args.empty())
		{
			argsv = test_utils::to_null_delimited(args);
			argsv.push_back('\0');
		}

		std::string envv = "";
		if (!env.empty())
		{
			envv = test_utils::to_null_delimited(env);
			envv.push_back('\0');
		}

		std::string cgroupsv = "";
		if (!cgroups.empty())
		{
			cgroupsv = test_utils::to_null_delimited(cgroups);
			cgroupsv.push_back('\0');
		}

		memcpy(tinfo.args, argsv.data(), argsv.size());
		tinfo.args_len = argsv.size();
		memcpy(tinfo.env, envv.data(), envv.size());
		tinfo.env_len = envv.size();
		memcpy(tinfo.cgroups.path, cgroupsv.data(), cgroupsv.size());
		tinfo.cgroups.len = cgroupsv.size();

		strlcpy(tinfo.cwd, cwd.c_str(), sizeof(tinfo.cwd));
		strlcpy(tinfo.comm, comm.c_str(), sizeof(tinfo.comm));
		strlcpy(tinfo.exe, exe.c_str(), sizeof(tinfo.exe));
		strlcpy(tinfo.exepath, exepath.c_str(), sizeof(tinfo.exepath));
		strlcpy(tinfo.root, root.c_str(), sizeof(tinfo.root));
		return tinfo;
	}

	void add_default_init_thread()
	{
		scap_threadinfo tinfo = create_threadinfo(1, 1, 0, 1, 1, 1, "init", "/sbin/init", "/sbin/init", increasing_ts(), 0, 0, {}, 0, {}, "/root/");

		std::vector<scap_fdinfo> fdinfos;
		scap_fdinfo fdinfo;
		fdinfo.fd = 0;
		fdinfo.ino = 5;
		fdinfo.type = SCAP_FD_FILE_V2;

		fdinfo.info.regularinfo.open_flags = PPM_O_RDONLY;
		fdinfo.info.regularinfo.mount_id = 25;
		fdinfo.info.regularinfo.dev = 0;
		strlcpy(fdinfo.info.regularinfo.fname, "/dev/null", sizeof(fdinfo.info.regularinfo.fname));

		fdinfos.push_back(fdinfo);

		add_thread(tinfo, fdinfos);
	}

	void add_simple_thread(int64_t tid, int64_t pid, int64_t ptid, std::string comm = "random")
	{
		scap_threadinfo tinfo = create_threadinfo(tid, pid, ptid, tid, tid, pid, comm, "/sbin/init", "/sbin/init", increasing_ts(), 0, 0, {}, 0, {}, "/root/");
		add_thread(tinfo, {});
	}

	uint64_t increasing_ts()
	{
		uint64_t ret = m_test_timestamp;
		m_test_timestamp += 10000000; // 10 msec increment
		return ret;
	}

	bool field_exists(sinsp_evt *evt, const std::string& field_name, filter_check_list& flist = g_filterlist)
	{
		if (evt == nullptr) {
			throw sinsp_exception("The event class is NULL");
		}

		std::unique_ptr<sinsp_filter_check> chk(flist.new_filter_check_from_fldname(field_name, &m_inspector, false));
		if(chk == nullptr)
		{
			throw sinsp_exception("The field " + field_name + " is not a valid field.");
		}
		/* we created a filter check starting from the field name so if we arrive here we will find it for sure */
		chk->parse_field_name(field_name.c_str(), true, false);
		std::vector<extract_value_t> values;
		return chk->extract(evt, values);
	}

	std::string get_field_as_string(sinsp_evt *evt, const std::string& field_name, filter_check_list& flist = g_filterlist)
	{
		if (evt == nullptr) {
			throw sinsp_exception("The event class is NULL");
		}

		std::unique_ptr<sinsp_filter_check> chk(flist.new_filter_check_from_fldname(field_name, &m_inspector, false));
		if(chk == nullptr)
		{
			throw sinsp_exception("The field " + field_name + " is not a valid field.");
		}
		/* we created a filter check starting from the field name so if we arrive here we will find it for sure */
		chk->parse_field_name(field_name.c_str(), true, false);

		const char* result = chk->tostring(evt);
		if (result == nullptr) {
			throw sinsp_exception("The field " + field_name + " is NULL");
		}

		return result;
	}

	sinsp_evt *next_event()
	{
		sinsp_evt *evt;
		auto result = m_inspector.next(&evt);
		return result == SCAP_SUCCESS ? evt : nullptr;
	}

	std::unique_ptr<scap_test_input_data> m_test_data;
	std::vector<scap_evt*> m_events;

	std::vector<scap_threadinfo> m_threads;
	std::vector<std::vector<scap_fdinfo>> m_fdinfos;
	std::vector<scap_test_fdinfo_data> m_test_fdinfo_data;

	uint64_t m_test_timestamp;
	uint64_t m_last_recorded_timestamp;
};
