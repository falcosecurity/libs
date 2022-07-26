#pragma once

#include <gtest/gtest.h>

#include "scap.h"
#include "filterchecks.h"
#include "../../common/strlcpy.h"

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
		struct scap_sized_buffer event_buf = {NULL, 0};
		size_t event_size;
		char error[SCAP_LASTERR_SIZE] = {'\0'};

		va_list args;
		va_start(args, n);
		int32_t ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);
		va_end(args);

		if(ret != SCAP_INPUT_TOO_SMALL) {
			return nullptr;
		}

		event_buf.buf = malloc(event_size);
		event_buf.size = event_size;

		if(event_buf.buf == NULL) {
			return nullptr;
		}

		va_start(args, n);
		ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);
		va_end(args);

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
		scap_threadinfo tinfo = {
			.tid = tid,
			.pid = pid,
			.ptid = ptid,
			.sid = sid,
			.vpgid = vpgid,
			.exe_writable = exe_writable,
			.fdlimit = fdlimit,
			.flags = flags,
			.uid = uid,
			.gid = gid,
			.cap_permitted = cap_permitted,
			.cap_effective = cap_effective,
			.cap_inheritable = cap_inheritable,
			.vmsize_kb = vmsize_kb,
			.vmrss_kb = vmrss_kb,
			.pfmajor = pfmajor,
			.pfminor = pfminor,
			.vtid = vtid,
			.vpid = vpid,
			.filtered_out = filtered_out,
			.fdlist = nullptr,
			.clone_ts = clone_ts,
			.tty = tty,
			.loginuid = loginuid
		};

		std::string argsv = "";
		for (std::string a : args) {
			argsv += a;
			argsv.push_back('\0');
		}
		argsv.push_back('\0');

		std::string envv = "";
		for (std::string a : env) {
			envv += a;
			envv.push_back('\0');
		}
		envv.push_back('\0');

		std::string cgroupsv = "";
		for (std::string a : cgroups) {
			cgroupsv += a;
			cgroupsv.push_back('\0');
		}
		cgroupsv.push_back('\0');

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
		scap_threadinfo tinfo = create_threadinfo(1, 1, 0, 1, 1, 1, "init", "/sbin/init", "/sbin/init", increasing_ts(), 0, 0);

		std::vector<scap_fdinfo> fdinfos;
		scap_fdinfo fdinfo = {
			.fd = 0,
			.ino = 5,
			.type = SCAP_FD_FILE_V2
		};

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

	std::string get_field_as_string(sinsp_evt *evt, std::string field_name)
	{
		std::unique_ptr<sinsp_filter_check> chk(g_filterlist.new_filter_check_from_fldname(field_name, &m_inspector, false));
		chk->parse_field_name(field_name.c_str(), true, false);
		std::string result = chk->tostring(evt);
		return result;
	}

	sinsp_evt *next_event()
	{
		sinsp_evt *evt;
		m_inspector.next(&evt);
		return evt;
	}

	std::unique_ptr<scap_test_input_data> m_test_data;
	std::vector<scap_evt*> m_events;

	std::vector<scap_threadinfo> m_threads;
	std::vector<std::vector<scap_fdinfo>> m_fdinfos;
	std::vector<scap_test_fdinfo_data> m_test_fdinfo_data;

	uint64_t m_test_timestamp;
};
