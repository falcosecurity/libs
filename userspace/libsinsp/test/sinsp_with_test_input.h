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
#include "../../common/strlcpy.h"
#include "test_utils.h"

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

	void open_inspector()
	{
		m_inspector.open_test_input(m_test_data.get());
	}

	scap_evt* add_event(uint64_t ts, uint64_t tid, enum ppm_event_type event_type, uint32_t n, ...)
	{
		va_list args;
		va_start(args, n);
		scap_evt *ret = add_event_v(ts, tid, event_type, n, args);
		va_end(args);

		return ret;
	}

	// adds an event and advances the inspector to the new timestamp
	sinsp_evt* add_event_advance_ts(uint64_t ts, uint64_t tid, enum ppm_event_type event_type, uint32_t n, ...)
	{
		sinsp_evt *sinsp_event;
		va_list args;
		va_start(args, n);
		add_event_v(ts, tid, event_type, n, args);
		va_end(args);

		for (sinsp_event = next_event(); sinsp_event != nullptr; sinsp_event = next_event()) {
			if (sinsp_event->get_ts() == ts) {
				return sinsp_event;
			}
		}

		throw std::runtime_error("could not retrieve last event or internal error (event vector size: " + m_events.size() + std::string(")"));
	}

	scap_evt* add_event_v(uint64_t ts, uint64_t tid, enum ppm_event_type event_type, uint32_t n, va_list args)
	{
		struct scap_sized_buffer event_buf = {NULL, 0};
		size_t event_size;
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args2;
		va_copy(args2, args);

		if (ts <= m_last_recorded_timestamp) {
			throw std::runtime_error("the test framework does not currently support equal timestamps or out of order events");
		}

		int32_t ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);

		if(ret != SCAP_INPUT_TOO_SMALL) {
			return nullptr;
		}

		event_buf.buf = malloc(event_size);
		event_buf.size = event_size;

		if(event_buf.buf == NULL) {
			return nullptr;
		}

		ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args2);

		if(ret != SCAP_SUCCESS) {
			free(event_buf.buf);
			event_buf.size = 0;
			return nullptr;
		}

		scap_evt *event = static_cast<scap_evt*>(event_buf.buf);
		event->ts = ts;
		event->tid = tid;

		m_events.push_back(event);
		m_test_data->events = m_events.data();
		m_test_data->event_count = m_events.size();
		m_last_recorded_timestamp = ts;

		return event;
	}

	void add_thread(const scap_threadinfo &tinfo, const std::vector<scap_fdinfo> &fdinfos)
	{
		m_threads.push_back(tinfo);
		m_test_data->threads = m_threads.data();
		m_test_data->thread_count = m_threads.size();

		m_fdinfos.push_back(fdinfos);
		scap_test_fdinfo_data fdinfo_descriptor = {
			.fdinfos = m_fdinfos.back().data(),
			.fdinfo_count = m_fdinfos.back().size()
		};
		m_test_fdinfo_data.push_back(fdinfo_descriptor);

		m_test_data->fdinfo_data = m_test_fdinfo_data.data();
	}

	static scap_threadinfo create_threadinfo(
		uint64_t tid, uint64_t pid, uint64_t ptid, uint64_t vpgid, int64_t vtid, int64_t vpid,
		std::string comm, std::string exe, std::string exepath, uint64_t clone_ts, uint32_t uid, uint32_t gid,

		std::vector<std::string> args={}, uint64_t sid=0, std::vector<std::string> env={}, std::string cwd="",
		int64_t fdlimit=0x100000, uint32_t flags=0, bool exe_writable=true, 
		uint64_t cap_permitted=0x1ffffffffff, uint64_t cap_inheritable=0, uint64_t cap_effective=0x1ffffffffff,
		uint32_t vmsize_kb=10000, uint32_t vmrss_kb=100, uint32_t vmswap_kb=0, uint64_t pfmajor=222, uint64_t pfminor=22,
		std::vector<std::string> cgroups={}, std::string root="/", int filtered_out=0, int32_t tty=0, int32_t loginuid=-1)
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
		memcpy(tinfo.cgroups, cgroupsv.data(), cgroupsv.size());
		tinfo.cgroups_len = cgroupsv.size();

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

	uint64_t increasing_ts()
	{
		uint64_t ret = m_test_timestamp;
		m_test_timestamp += 10000000; // 10 msec increment
		return ret;
	}

	std::string get_field_as_string(sinsp_evt *evt, const std::string& field_name)
	{
		std::unique_ptr<sinsp_filter_check> chk(g_filterlist.new_filter_check_from_fldname(field_name, &m_inspector, false));
		chk->parse_field_name(field_name.c_str(), true, false);
		std::string result = chk->tostring(evt);
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
