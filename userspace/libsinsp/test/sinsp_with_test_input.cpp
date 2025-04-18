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

#include "sinsp_with_test_input.h"

sinsp_with_test_input::sinsp_with_test_input() {
	m_test_data.event_count = 0;
	m_test_data.events = nullptr;
	m_test_data.thread_count = 0;
	m_test_data.threads = nullptr;
}

sinsp_with_test_input::~sinsp_with_test_input() {
	for(auto& el : m_events) {
		free(el);
	}

	for(auto& el : m_async_events) {
		free(el);
	}

	libsinsp_logger()->reset();
}

void sinsp_with_test_input::open_inspector(sinsp_mode_t mode) {
	m_inspector.open_test_input(&m_test_data, mode);
}

scap_evt* sinsp_with_test_input::_add_event(uint64_t ts,
                                            uint64_t tid,
                                            ppm_event_code event_type,
                                            uint32_t n,
                                            ...) {
	va_list args;
	va_start(args, n);
	scap_evt* ret = add_event_v(ts, tid, event_type, n, args);
	va_end(args);

	return ret;
}

sinsp_evt* sinsp_with_test_input::advance_ts_get_event(uint64_t ts) {
	for(sinsp_evt* evt = next_event(); evt != nullptr; evt = next_event()) {
		if(evt->get_ts() == ts) {
			return evt;
		}
	}

	return nullptr;
}

// adds an event and advances the inspector to the new timestamp
sinsp_evt* sinsp_with_test_input::_add_event_advance_ts(uint64_t ts,
                                                        uint64_t tid,
                                                        ppm_event_code event_type,
                                                        uint32_t n,
                                                        ...) {
	va_list args;
	va_start(args, n);
	sinsp_evt* ret = add_event_advance_ts_v(ts, tid, event_type, n, args);
	va_end(args);

	return ret;
}

sinsp_evt* sinsp_with_test_input::add_event_advance_ts_v(uint64_t ts,
                                                         uint64_t tid,
                                                         ppm_event_code event_type,
                                                         uint32_t n,
                                                         va_list args) {
	add_event_v(ts, tid, event_type, n, args);
	sinsp_evt* evt = advance_ts_get_event(ts);
	if(evt != nullptr) {
		return evt;
	}

	throw std::runtime_error(
	        "could not retrieve last event or internal error (event vector size: " +
	        std::to_string(m_events.size()) + std::string(")"));
}

// Generates and allocates a new event.
scap_evt* sinsp_with_test_input::create_event_v(uint64_t ts,
                                                uint64_t tid,
                                                ppm_event_code event_type,
                                                uint32_t n,
                                                va_list args) {
	struct scap_sized_buffer event_buf = {NULL, 0};
	size_t event_size = 0;
	char error[SCAP_LASTERR_SIZE] = {'\0'};
	va_list args2;
	va_copy(args2, args);

	int32_t ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);

	if(ret != SCAP_INPUT_TOO_SMALL) {
		va_end(args2);
		throw std::runtime_error(std::string("cannot compute the size of the event: ") + error);
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
		throw std::runtime_error(std::string("cannot encode the event: ") + error);
	}

	scap_evt* event = static_cast<scap_evt*>(event_buf.buf);
	event->ts = ts;
	event->tid = tid;

	va_end(args2);
	return event;
}

scap_evt* sinsp_with_test_input::add_event_v(uint64_t ts,
                                             uint64_t tid,
                                             ppm_event_code event_type,
                                             uint32_t n,
                                             va_list args) {
	if(ts < m_last_recorded_timestamp) {
		throw std::runtime_error(
		        "the test framework does not currently support out of order events with decreasing "
		        "timestamps");
	}

	scap_evt* event = create_event_v(ts, tid, event_type, n, args);
	if(event == nullptr) {
		std::stringstream ss;
		ss << "cannot create event type: " << event_type << ", ts: " << ts << ", tid: " << tid
		   << ", n: " << n;
		throw std::runtime_error(ss.str());
	}

	uint64_t evtoffset = m_events.size() - m_test_data.event_count;
	m_events.push_back(event);
	m_test_data.events = m_events.data() + evtoffset;
	m_test_data.event_count = m_events.size() - evtoffset;
	m_last_recorded_timestamp = ts;

	return event;
}

scap_evt* sinsp_with_test_input::add_async_event(uint64_t ts,
                                                 uint64_t tid,
                                                 ppm_event_code event_type,
                                                 uint32_t n,
                                                 ...) {
	va_list args;
	va_start(args, n);
	scap_evt* ret = add_async_event_v(ts, tid, event_type, n, args);
	va_end(args);

	return ret;
}

scap_evt* sinsp_with_test_input::add_async_event_v(uint64_t ts,
                                                   uint64_t tid,
                                                   ppm_event_code event_type,
                                                   uint32_t n,
                                                   va_list args) {
	scap_evt* scap_event = create_event_v(ts, tid, event_type, n, args);
	m_async_events.push_back(scap_event);

	auto event = std::make_unique<sinsp_evt>();
	event->set_scap_evt(scap_event);
	event->set_cpuid(0);
	event->get_scap_evt()->ts = ts;
	m_inspector.handle_async_event(std::move(event));

	return scap_event;
}

//=============================== PROCESS GENERATION ===========================

// Allowed event types: PPME_SYSCALL_CLONE_20_X, PPME_SYSCALL_FORK_20_X, PPME_SYSCALL_VFORK_20_X,
// PPME_SYSCALL_CLONE3_X
sinsp_evt* sinsp_with_test_input::generate_clone_x_event(int64_t retval,
                                                         int64_t tid,
                                                         int64_t pid,
                                                         int64_t ppid,
                                                         uint32_t flags,
                                                         int64_t vtid,
                                                         int64_t vpid,
                                                         const std::string& name,
                                                         const std::vector<std::string>& cgroup_vec,
                                                         ppm_event_code event_type) {
	if(vtid == DEFAULT_VALUE) {
		vtid = tid;
	}

	if(vpid == DEFAULT_VALUE) {
		vpid = pid;
	}

	// Scaffolding needed to call the PPME_SYSCALL_CLONE_20_X
	uint64_t not_relevant_64 = 0;
	uint32_t not_relevant_32 = 0;

	scap_const_sized_buffer empty_bytebuf = {/*.buf =*/nullptr, /*.size =*/0};
	scap_const_sized_buffer cgroup_byte_buf = empty_bytebuf;
	std::string cgroupsv = test_utils::to_null_delimited(cgroup_vec);

	// If the cgroup vector is not empty overwrite it
	if(!cgroup_vec.empty()) {
		cgroup_byte_buf = scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()};
	}

	return add_event_advance_ts(increasing_ts(),
	                            tid,
	                            event_type,
	                            20,
	                            retval,
	                            name.c_str(),
	                            empty_bytebuf,
	                            tid,
	                            pid,
	                            ppid,
	                            "",
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_32,
	                            not_relevant_32,
	                            not_relevant_32,
	                            name.c_str(),
	                            cgroup_byte_buf,
	                            flags,
	                            not_relevant_32,
	                            not_relevant_32,
	                            vtid,
	                            vpid);
}

sinsp_evt* sinsp_with_test_input::generate_execve_enter_and_exit_event(
        int64_t retval,
        int64_t old_tid,
        int64_t new_tid,
        int64_t pid,
        int64_t ppid,
        const std::string& pathname,
        const std::string& comm,
        const std::string& resolved_kernel_path,
        const std::vector<std::string>& cgroup_vec,
        int64_t pgid) {
	// Scaffolding needed to call the PPME_SYSCALL_EXECVE_19_X
	uint64_t not_relevant_64 = 0;
	uint32_t not_relevant_32 = 0;
	scap_const_sized_buffer empty_bytebuf = {/*.buf =*/nullptr, /*.size =*/0};
	scap_const_sized_buffer cgroup_byte_buf = empty_bytebuf;
	std::string cgroupsv = test_utils::to_null_delimited(cgroup_vec);

	// If the cgroup vector is not empty overwrite it
	if(!cgroup_vec.empty()) {
		cgroup_byte_buf = scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()};
	}

	add_event_advance_ts(increasing_ts(), old_tid, PPME_SYSCALL_EXECVE_19_E, 1, pathname.c_str());
	// we have an `old_tid` and a `new_tid` because if a secondary thread calls the execve
	// the thread leader will take control so the `tid` between enter and exit event will change
	return add_event_advance_ts(increasing_ts(),
	                            new_tid,
	                            PPME_SYSCALL_EXECVE_19_X,
	                            29,
	                            retval,
	                            pathname.c_str(),
	                            empty_bytebuf,
	                            new_tid,
	                            pid,
	                            ppid,
	                            "",
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_32,
	                            not_relevant_32,
	                            not_relevant_32,
	                            comm.c_str(),
	                            cgroup_byte_buf,
	                            empty_bytebuf,
	                            not_relevant_32,
	                            not_relevant_64,
	                            not_relevant_32,
	                            not_relevant_32,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_64,
	                            not_relevant_32,
	                            resolved_kernel_path.c_str(),
	                            pgid);
}

void sinsp_with_test_input::remove_thread(int64_t tid_to_remove, int64_t reaper_tid) {
	generate_proc_exit_event(tid_to_remove, reaper_tid);
	// Generate a random event on init to trigger the removal after proc exit
	generate_random_event();
}

sinsp_evt* sinsp_with_test_input::generate_proc_exit_event(int64_t tid_to_remove,
                                                           int64_t reaper_tid) {
	// Scaffolding needed to call the PPME_PROCEXIT_1_E
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;
	int64_t ret_err_perm = -1;  // mostly non-relevant, used in few tests

	return add_event_advance_ts(increasing_ts(),
	                            tid_to_remove,
	                            PPME_PROCEXIT_1_E,
	                            5,
	                            not_relevant_64,
	                            ret_err_perm,
	                            not_relevant_8,
	                            not_relevant_8,
	                            reaper_tid);
}

sinsp_evt* sinsp_with_test_input::generate_random_event(int64_t tid_caller) {
	// Generate a random failed event. Useful when we want to trigger some actions on an event
	// and we don't care about the event chosen.
	return add_event_advance_ts(increasing_ts(), tid_caller, PPME_SYSCALL_GETCWD_E, 0);
}

sinsp_evt* sinsp_with_test_input::generate_getcwd_failed_entry_event(int64_t tid_caller) {
	int64_t err = -1;
	std::string path = "/test/dir";
	return add_event_advance_ts(increasing_ts(),
	                            tid_caller,
	                            PPME_SYSCALL_GETCWD_X,
	                            2,
	                            err,
	                            path.c_str());
}

sinsp_evt* sinsp_with_test_input::generate_open_x_event(sinsp_test_input::open_params params,
                                                        int64_t tid_caller) {
	return add_event_advance_ts(increasing_ts(),
	                            tid_caller,
	                            PPME_SYSCALL_OPEN_X,
	                            6,
	                            params.fd,
	                            params.path,
	                            params.flags,
	                            params.mode,
	                            params.dev,
	                            params.ino);
}

sinsp_evt* sinsp_with_test_input::generate_socket_events(sinsp_test_input::socket_params params,
                                                         int64_t tid_caller) {
	// todo!: remove it when we will disable enter events by default. At the moment we want to test
	// the use case in which we generate both the enter event and the exit one.
	add_event_advance_ts(increasing_ts(),
	                     tid_caller,
	                     PPME_SOCKET_SOCKET_E,
	                     3,
	                     params.domain,
	                     params.type,
	                     params.proto);
	return add_event_advance_ts(increasing_ts(),
	                            tid_caller,
	                            PPME_SOCKET_SOCKET_X,
	                            4,
	                            params.fd,
	                            params.domain,
	                            params.type,
	                            params.proto);
}

//=============================== PROCESS GENERATION ===========================

void sinsp_with_test_input::add_thread(const scap_threadinfo& tinfo,
                                       const std::vector<scap_fdinfo>& fdinfos) {
	m_threads.push_back(tinfo);
	m_test_data.threads = m_threads.data();
	m_test_data.thread_count = m_threads.size();

	m_fdinfos.push_back(fdinfos);
	scap_test_fdinfo_data fdinfo_descriptor = {/*.fdinfos =*/m_fdinfos.back().data(),
	                                           /*.fdinfo_count =*/m_fdinfos.back().size()};
	m_test_fdinfo_data.push_back(fdinfo_descriptor);

	m_test_data.fdinfo_data = m_test_fdinfo_data.data();
}

void sinsp_with_test_input::set_threadinfo_last_access_time(int64_t tid, uint64_t access_time_ns) {
	auto tinfo = m_inspector.get_thread_ref(tid, false).get();
	if(tinfo != nullptr) {
		tinfo->m_lastaccess_ts = access_time_ns;
	} else {
		throw sinsp_exception("There is no thread info associated with tid: " +
		                      std::to_string(tid));
	}
}

// Remove all threads with `tinfo->m_lastaccess_ts` minor than `m_lastevent_ts - thread_timeout`
void sinsp_with_test_input::remove_inactive_threads(uint64_t m_lastevent_ts,
                                                    uint64_t thread_timeout) {
	// We need to set these 2 variables to enable the remove_inactive_logic
	m_inspector.m_thread_manager->set_last_flush_time_ns(1);
	m_inspector.m_threads_purging_scan_time_ns = 2;

	m_inspector.set_lastevent_ts(m_lastevent_ts);
	m_inspector.m_thread_timeout_ns = thread_timeout;
	m_inspector.m_thread_manager->remove_inactive_threads();
}

// static
scap_threadinfo sinsp_with_test_input::create_threadinfo(uint64_t tid,
                                                         uint64_t pid,
                                                         uint64_t ptid,
                                                         uint64_t vpgid,
                                                         int64_t vtid,
                                                         int64_t vpid,
                                                         const std::string& comm,
                                                         const std::string& exe,
                                                         const std::string& exepath,
                                                         uint64_t clone_ts,
                                                         uint32_t uid,
                                                         uint32_t gid,
                                                         const std::vector<std::string>& args,
                                                         uint64_t sid,
                                                         const std::vector<std::string>& env,
                                                         const std::string& cwd,
                                                         int64_t fdlimit,
                                                         uint32_t flags,
                                                         bool exe_writable,
                                                         uint64_t cap_permitted,
                                                         uint64_t cap_inheritable,
                                                         uint64_t cap_effective,
                                                         uint32_t vmsize_kb,
                                                         uint32_t vmrss_kb,
                                                         uint32_t vmswap_kb,
                                                         uint64_t pfmajor,
                                                         uint64_t pfminor,
                                                         const std::vector<std::string>& cgroups,
                                                         const std::string& root,
                                                         int filtered_out,
                                                         uint32_t tty,
                                                         uint32_t loginuid,
                                                         bool exe_upper_layer,
                                                         bool exe_lower_layer,
                                                         bool exe_from_memfd) {
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
	tinfo.exe_upper_layer = exe_upper_layer;
	tinfo.exe_lower_layer = exe_lower_layer;
	tinfo.exe_from_memfd = exe_from_memfd;

	std::string argsv;
	if(!args.empty()) {
		argsv = test_utils::to_null_delimited(args);
	}

	std::string envv;
	if(!env.empty()) {
		envv = test_utils::to_null_delimited(env);
	}

	std::string cgroupsv;
	if(!cgroups.empty()) {
		cgroupsv = test_utils::to_null_delimited(cgroups);
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

void sinsp_with_test_input::add_default_init_thread() {
	std::vector<std::string> env = {"TEST_ENV_PARENT_LINEAGE=secret", "HOME=/home/user/parent"};
	scap_threadinfo tinfo = create_threadinfo(1,
	                                          1,
	                                          0,
	                                          1,
	                                          1,
	                                          1,
	                                          "init",
	                                          "/sbin/init",
	                                          "/sbin/init",
	                                          increasing_ts(),
	                                          0,
	                                          0,
	                                          {},
	                                          0,
	                                          env,
	                                          "/root/");

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

void sinsp_with_test_input::add_simple_thread(int64_t tid,
                                              int64_t pid,
                                              int64_t ptid,
                                              const std::string& comm) {
	scap_threadinfo tinfo = create_threadinfo(tid,
	                                          pid,
	                                          ptid,
	                                          tid,
	                                          tid,
	                                          pid,
	                                          comm,
	                                          "/sbin/init",
	                                          "/sbin/init",
	                                          increasing_ts(),
	                                          0,
	                                          0,
	                                          {},
	                                          0,
	                                          {},
	                                          "/root/");
	add_thread(tinfo, {});
}

uint64_t sinsp_with_test_input::increasing_ts() {
	uint64_t ret = m_test_timestamp;
	m_test_timestamp += 10000000;  // 10 msec increment
	return ret;
}

// Return true if `field_name` exists in the filtercheck list.
// The field value could also be NULL, but in this method, we are not interested in the value.
bool sinsp_with_test_input::field_exists(sinsp_evt* evt, std::string_view field_name) {
	return field_exists(evt, field_name, m_default_filterlist);
}

bool sinsp_with_test_input::field_exists(sinsp_evt* evt,
                                         std::string_view field_name,
                                         filter_check_list& flist) {
	if(evt == nullptr) {
		throw sinsp_exception("The event class is NULL");
	}

	auto new_fl = flist.new_filter_check_from_fldname(field_name, &m_inspector, false);
	if(new_fl != nullptr) {
		// if we can create a filter check it means that the field exists
		return true;
	} else {
		return false;
	}
}

// Return true if `field_name` value is not NULL for this event.
bool sinsp_with_test_input::field_has_value(sinsp_evt* evt, std::string_view field_name) {
	return field_has_value(evt, field_name, m_default_filterlist);
}

bool sinsp_with_test_input::field_has_value(sinsp_evt* evt,
                                            std::string_view field_name,
                                            filter_check_list& flist) {
	if(evt == nullptr) {
		throw sinsp_exception("The event class is NULL");
	}

	std::unique_ptr<sinsp_filter_check> chk(
	        flist.new_filter_check_from_fldname(field_name, &m_inspector, false));
	if(chk == nullptr) {
		throw sinsp_exception("The field " + std::string(field_name) + " is not a valid field.");
	}
	// we created a filter check starting from the field name so if we arrive here we will find it
	// for sure
	chk->parse_field_name(field_name, true, false);
	std::vector<extract_value_t> values;
	return chk->extract(evt, values);
}

std::string sinsp_with_test_input::get_field_as_string(sinsp_evt* evt,
                                                       std::string_view field_name) {
	return get_field_as_string(evt, field_name, m_default_filterlist);
}

std::string sinsp_with_test_input::get_field_as_string(sinsp_evt* evt,
                                                       std::string_view field_name,
                                                       filter_check_list& flist) {
	if(evt == nullptr) {
		throw sinsp_exception("The event class is NULL");
	}

	std::unique_ptr<sinsp_filter_check> chk(
	        flist.new_filter_check_from_fldname(field_name, &m_inspector, false));
	if(chk == nullptr) {
		throw sinsp_exception("The field " + std::string(field_name) + " is not a valid field.");
	}
	// we created a filter check starting from the field name so if we arrive here we will find it
	// for sure
	chk->parse_field_name(field_name, true, false);

	const char* result = chk->tostring(evt);
	if(result == nullptr) {
		throw sinsp_exception("The field " + std::string(field_name) + " is NULL");
	}

	return result;
}

extract_offset_t sinsp_with_test_input::get_value_offsets(sinsp_evt* evt,
                                                          std::string_view field_name,
                                                          filter_check_list& flist,
                                                          size_t val_idx) {
	if(evt == nullptr) {
		throw sinsp_exception("The event class is NULL");
	}

	std::unique_ptr<sinsp_filter_check> chk(
	        flist.new_filter_check_from_fldname(field_name, &m_inspector, false));
	if(chk == nullptr) {
		throw sinsp_exception("The field " + std::string(field_name) + " is not a valid field.");
	}
	// we created a filter check starting from the field name so if we arrive here we will find it
	// for sure
	chk->parse_field_name(field_name, true, false);
	std::vector<extract_value_t> values;
	std::vector<extract_offset_t> offsets;
	chk->extract_with_offsets(evt, values, offsets);
	if(offsets.size() == 0) {
		throw sinsp_exception("Unable to extract offsets for " + std::string(field_name));
	}
	if(val_idx >= values.size()) {
		throw sinsp_exception("Offset index " + std::to_string(val_idx) + " out of range for " +
		                      std::string(field_name));
	}

	return offsets.at(val_idx);
}

uint32_t sinsp_with_test_input::get_value_offset_start(sinsp_evt* evt,
                                                       std::string_view field_name,
                                                       filter_check_list& flist,
                                                       size_t val_idx) {
	return get_value_offsets(evt, field_name, flist, val_idx).start;
}

uint32_t sinsp_with_test_input::get_value_offset_length(sinsp_evt* evt,
                                                        std::string_view field_name,
                                                        filter_check_list& flist,
                                                        size_t val_idx) {
	return get_value_offsets(evt, field_name, flist, val_idx).length;
}

bool sinsp_with_test_input::eval_filter(sinsp_evt* evt,
                                        std::string_view filter_str,
                                        std::shared_ptr<sinsp_filter_cache_factory> cachef) {
	return eval_filter(evt, filter_str, m_default_filterlist, cachef);
}

bool sinsp_with_test_input::eval_filter(sinsp_evt* evt,
                                        std::string_view filter_str,
                                        filter_check_list& flist,
                                        std::shared_ptr<sinsp_filter_cache_factory> cachef) {
	auto factory = std::make_shared<sinsp_filter_factory>(&m_inspector, flist);
	sinsp_filter_compiler compiler(factory, std::string(filter_str), cachef);

	auto filter = compiler.compile();

	return filter->run(evt);
}

bool sinsp_with_test_input::eval_filter(sinsp_evt* evt,
                                        std::string_view filter_str,
                                        std::shared_ptr<sinsp_filter_factory> filterf,
                                        std::shared_ptr<sinsp_filter_cache_factory> cachef) {
	sinsp_filter_compiler compiler(filterf, std::string(filter_str), cachef);
	auto filter = compiler.compile();
	return filter->run(evt);
}

bool sinsp_with_test_input::filter_compiles(std::string_view filter_str) {
	return filter_compiles(filter_str, m_default_filterlist);
}

bool sinsp_with_test_input::filter_compiles(std::string_view filter_str, filter_check_list& flist) {
	auto factory = std::make_shared<sinsp_filter_factory>(&m_inspector, flist);
	sinsp_filter_compiler compiler(factory, std::string(filter_str));
	try {
		auto f = compiler.compile();
		return true;
	} catch(const sinsp_exception& e) {
		return false;
	}
}

sinsp_evt* sinsp_with_test_input::next_event() {
	sinsp_evt* evt;
	auto result = m_inspector.next(&evt);
	return result == SCAP_SUCCESS ? evt : nullptr;
}

void sinsp_with_test_input::assert_return_value(sinsp_evt* evt, int64_t expected_retval) {
	// First the event we provide should have the return value
	ASSERT_TRUE(evt->has_return_value());

	// The raw value should be equal to what we expect
	ASSERT_EQ(evt->get_syscall_return_value(), expected_retval);

	// We need to create the filtercheck name for the first parameter, usually `res`/`fd` but not
	// always, could be also `addr` for example...
	std::string evt_rawarg_name = std::string("evt.rawarg.") + std::string(evt->get_param_name(0));

	// SUCCESS CASE: we consider success when retval >= 0 (so != errno)
	if(expected_retval >= 0) {
		/////////////
		// Res
		/////////////
		ASSERT_EQ(get_field_as_string(evt, "evt.res"), "SUCCESS");
		ASSERT_EQ(get_field_as_string(evt, "evt.rawres"), std::to_string(expected_retval));
		ASSERT_EQ(get_field_as_string(evt, "evt.failed"), "false");

		/////////////
		// First parameter (arg0)
		/////////////
		auto arg0_info = evt->get_param_info(0);
		ASSERT_TRUE(arg0_info);
		// Default values
		std::string arg0 = std::to_string(expected_retval);
		std::string raw_arg0 = std::to_string(expected_retval);

		// Some cases in which we need to modify `arg0` or `raw_arg0`
		if(arg0_info->type == PT_FD) {
			// If the return value is a file descriptor the value of `evt.arg[0]` is the path
			// prefixed by `<f>`
			auto fdinfo = evt->get_fd_info();
			ASSERT_TRUE(fdinfo);
			arg0 = std::string("<f>") + fdinfo->m_name;

			// raw_arg0 is ok!
		}

		if(arg0_info->fmt == PF_HEX && arg0_info->type == PT_UINT64) {
			// both `evt.arg[0]` and `evt.rawarg` become hexadecimal
			char buffer[100];
			std::snprintf(buffer, sizeof(buffer), "%" PRIX64, expected_retval);
			arg0 = buffer;
			raw_arg0 = buffer;
		}

		ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), arg0);
		ASSERT_EQ(get_field_as_string(evt, evt_rawarg_name), raw_arg0);
	} else {
		/////////////
		// Res
		/////////////
		ASSERT_EQ(get_field_as_string(evt, "evt.res"), sinsp_utils::errno_to_str(expected_retval));
		ASSERT_EQ(get_field_as_string(evt, "evt.rawres"), std::to_string(expected_retval));
		ASSERT_EQ(get_field_as_string(evt, "evt.failed"), "true");

		/////////////
		// First parameter (arg0)
		/////////////
		ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), get_field_as_string(evt, "evt.res"));
		ASSERT_EQ(get_field_as_string(evt, evt_rawarg_name),
		          get_field_as_string(evt, "evt.rawres"));
	}
}

void sinsp_with_test_input::assert_fd_fields(sinsp_evt* evt,
                                             sinsp_test_input::fd_info_fields fields) {
	auto fdinfo = evt->get_fd_info();

	// Right now we only assert if the fdinfo is present, but we want to be sure that for some
	// events the fdinfo should be here
	if((evt->creates_fd() || evt->uses_fd()) && evt->get_syscall_return_value() >= 0) {
		ASSERT_TRUE(fdinfo);
	}

	if(fdinfo) {
		if(fields.fd_num.has_value()) {
			ASSERT_EQ(fdinfo->m_fd, fields.fd_num.value());
		}

		if(fields.fd_name.has_value()) {
			ASSERT_EQ(fdinfo->m_name, fields.fd_name.value());
		}

		if(fields.fd_name_raw.has_value()) {
			ASSERT_EQ(fdinfo->m_name_raw, fields.fd_name_raw.value());
		}
	}

	if(fields.fd_num.has_value()) {
		ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(fields.fd_num.value()));
	}

	if(fields.fd_name.has_value()) {
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), fields.fd_name.value());
	}

	if(fields.fd_name_raw.has_value()) {
		ASSERT_EQ(get_field_as_string(evt, "fd.nameraw"), fields.fd_name_raw.value());
	}

	if(fields.fd_directory.has_value()) {
		ASSERT_EQ(get_field_as_string(evt, "fd.directory"), fields.fd_directory.value());
	}

	if(fields.fd_filename.has_value()) {
		ASSERT_EQ(get_field_as_string(evt, "fd.filename"), fields.fd_filename.value());
	}
}
