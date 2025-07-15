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

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/un.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __x86_64__
#include <driver/syscall_compat_x86_64.h>
#elif __aarch64__
#include <driver/syscall_compat_aarch64.h>
#elif __s390x__
#include <driver/syscall_compat_s390x.h>
#elif __powerpc64__
#include <driver/syscall_compat_ppc64le.h>
#elif __riscv
#include <driver/syscall_compat_riscv64.h>
#elif __loongarch64
#include <driver/syscall_compat_loongarch64.h>
#endif /* __x86_64__ */

#include <functional>
#include <unordered_map>
#include <sstream>
#include <string>

#include <json/json.h>

#include <libscap/engine/gvisor/gvisor.h>
#include <libscap/engine/gvisor/parsers.h>
#include <libscap/engine/gvisor/fillers.h>
#include <libscap/compat/misc.h>
#include <driver/ppm_events_public.h>
#include <libscap/strl.h>

#include <libscap/userspace_flag_helpers.h>

#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

#include <libscap/strerror.h>

namespace scap_gvisor {
namespace parsers {

constexpr size_t socktuple_buffer_size = 1024;

// In gVisor there's no concept of tid and tgid but only vtid and vtgid.
// However, to fit into sinsp we do need values for tid and tgid.
static uint64_t generate_tid_field(uint64_t tid, uint32_t sandbox_id) {
	uint64_t tid_field = sandbox_id;
	tid_field = tid | (tid_field << 32);
	return tid_field;
}

// Perform conversion from pid/tid field to vpid/vtid
uint64_t get_vxid(uint64_t xid) {
	return xid & 0xffffffff;
}

template<class T>
static void fill_context_data(scap_evt *evt, T &gvisor_evt, uint32_t id) {
	auto &context_data = gvisor_evt.context_data();
	evt->ts = context_data.time_ns();
	evt->tid = generate_tid_field(context_data.thread_id(), id);
}

static int32_t process_unhandled_syscall(uint64_t sysno, char *error_buf) {
	scap_errprintf(error_buf, 0, "Unhandled syscall: %s", std::to_string(sysno).c_str());
	return SCAP_NOT_SUPPORTED;
}

static parse_result parse_container_start(uint32_t id,
                                          scap_const_sized_buffer proto,
                                          scap_sized_buffer scap_buf) {
	parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	scap_sized_buffer event_buf = scap_buf;
	size_t event_size;

	gvisor::container::Start gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking container start protobuf message";
		return ret;
	}

	std::string args;

	// skip argv[0]
	for(int j = 1; j < gvisor_evt.args_size(); j++) {
		args += gvisor_evt.args(j);
		args.push_back('\0');
	}

	std::string env;
	for(int j = 0; j < gvisor_evt.env_size(); j++) {
		env += gvisor_evt.env(j);
		env.push_back('\0');
	}

	std::string container_id = gvisor_evt.id();

	std::string cgroups = "gvisor_container_id=/";
	cgroups += container_id;

	std::string exe, comm;
	exe = gvisor_evt.args(0).c_str();  // exe, best available info from gVisor evt
	size_t pos = exe.find_last_of("/");
	if(pos != std::string::npos) {
		comm = exe.substr(pos + 1);
	} else {
		comm = exe;
	}

	auto &context_data = gvisor_evt.context_data();

	std::string cwd = context_data.cwd();

	uint64_t tid_field = generate_tid_field(1, id);
	uint64_t tgid_field = generate_tid_field(1, id);

	// encode clone entry
	ret.status = scap_gvisor::fillers::fill_event_clone_20_e(event_buf, &event_size, scap_err);
	if(ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if(ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt *>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char *)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode clone exit
	ret.status = scap_gvisor::fillers::fill_event_clone_20_x(
	        event_buf,
	        &event_size,
	        scap_err,
	        0,  // res = 0 in the child thread
	        exe.c_str(),
	        scap_const_sized_buffer{args.data(), args.size()},
	        tid_field,   // tid
	        tgid_field,  // pid
	        1,           // ptid for initial process
	        "",          // cwd for initial process
	        comm.c_str(),
	        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
	        0,  // flags -- INVALID/not available in gVisor event
	        context_data.credentials().effective_uid(),  // uid
	        context_data.credentials().effective_gid(),  // gid
	        1,                                           // vtid
	        1,                                           // vpid
	        context_data.thread_start_time_ns());        // pidns_init_start_ts

	if(ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if(ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt *>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char *)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode execve entry
	ret.status =
	        scap_gvisor::fillers::fill_event_execve_19_e(event_buf,
	                                                     &event_size,
	                                                     scap_err,
	                                                     exe.c_str());  // TODO actual exe missing

	if(ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if(ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt *>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char *)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode execve exit
	ret.status = scap_gvisor::fillers::fill_event_execve_19_x(
	        event_buf,
	        &event_size,
	        scap_err,
	        0,  // res
	        exe.c_str(),
	        scap_const_sized_buffer{args.data(), args.size()},
	        tid_field,   // tid
	        tgid_field,  // pid
	        cwd.c_str(),
	        comm.c_str(),
	        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
	        scap_const_sized_buffer{env.data(), env.size()},
	        context_data.credentials().effective_uid(),  // uid
	        context_data.credentials().effective_gid()   // gid
	);

	if(ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if(ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt *>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char *)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	return ret;
}

static parse_result parse_execve(uint32_t id,
                                 scap_const_sized_buffer proto,
                                 scap_sized_buffer scap_buf) {
	parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	gvisor::syscall::Execve gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking execve protobuf message";
		return ret;
	}

	std::string pathname = gvisor_evt.pathname();

	if(gvisor_evt.has_exit()) {
		std::string args;

		// skip argv[0]
		for(int j = 1; j < gvisor_evt.argv_size(); j++) {
			args += gvisor_evt.argv(j);
			args.push_back('\0');
		}

		std::string env;
		for(int j = 0; j < gvisor_evt.envv_size(); j++) {
			env += gvisor_evt.envv(j);
			env.push_back('\0');
		}

		std::string comm;

		size_t pos = pathname.find_last_of("/");
		if(pos != std::string::npos) {
			comm = pathname.substr(pos + 1);
		} else {
			comm = pathname;
		}

		auto &context_data = gvisor_evt.context_data();

		std::string cwd = context_data.cwd();

		std::string cgroups = "gvisor_container_id=/";
		cgroups += context_data.container_id();

		switch(gvisor_evt.sysno()) {
		case __NR_execve:
			ret.status = scap_gvisor::fillers::fill_event_execve_19_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),  // res
			        pathname.c_str(),            // exe
			        scap_const_sized_buffer{args.data(), args.size()},
			        generate_tid_field(context_data.thread_id(), id),        // tid
			        generate_tid_field(context_data.thread_group_id(), id),  // pid
			        cwd.c_str(),                                             // cwd
			        comm.c_str(),                                            // comm
			        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
			        scap_const_sized_buffer{env.data(), env.size()},
			        0,  // uid -- INVALID/not available in gVisor evt
			        0   // gid -- INVALID/not available in gVisor evt
			);
			break;

		case __NR_execveat:
			ret.status = scap_gvisor::fillers::fill_event_execveat_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),  // res
			        pathname.c_str(),            // exe
			        scap_const_sized_buffer{args.data(), args.size()},
			        generate_tid_field(context_data.thread_id(), id),        // tid
			        generate_tid_field(context_data.thread_group_id(), id),  // pid
			        cwd.c_str(),                                             // cwd
			        comm.c_str(),                                            // comm
			        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
			        scap_const_sized_buffer{env.data(), env.size()},
			        0);  // uid -- INVALID/not available in gVisor evt
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}

	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_execve:
			ret.status = scap_gvisor::fillers::fill_event_execve_19_e(scap_buf,
			                                                          &ret.size,
			                                                          scap_err,
			                                                          pathname.c_str());
			break;

		case __NR_execveat:
			ret.status = scap_gvisor::fillers::fill_event_execveat_e(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.fd(),
			        pathname.c_str(),
			        execveat_flags_to_scap(gvisor_evt.flags()));
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_sentry_clone(uint32_t id,
                                       scap_const_sized_buffer proto,
                                       scap_sized_buffer scap_buf) {
	parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	gvisor::sentry::CloneInfo gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking sentry clone protobuf message";
		return ret;
	}

	auto &context_data = gvisor_evt.context_data();

	std::string cgroups = "gvisor_container_id=/";
	cgroups += context_data.container_id();

	uint64_t tid_field = generate_tid_field(gvisor_evt.created_thread_id(), id);

	ret.status = scap_gvisor::fillers::fill_event_clone_20_x(
	        scap_buf,
	        &ret.size,
	        scap_err,
	        0,                                    // res for child thread
	        context_data.process_name().c_str(),  // exe
	        scap_const_sized_buffer{"", 0},       // args -- INV/not available
	        tid_field,                            // tid
	        generate_tid_field(gvisor_evt.created_thread_group_id(), id),  // pid
	        generate_tid_field(context_data.thread_id(), id),              // ptid
	        context_data.cwd().c_str(),                                    // cwd
	        context_data.process_name().c_str(),                           // comm
	        scap_const_sized_buffer{cgroups.c_str(), cgroups.size() + 1},
	        0,                                     // flags -- INV/not available
	        0,                                     // uid -- INV/not available
	        0,                                     // gid -- INV/not available
	        gvisor_evt.created_thread_id(),        // vtid
	        gvisor_evt.created_thread_group_id(),  // vpid
	        context_data.thread_start_time_ns());  // pidns_init_start_ts

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	evt->ts = context_data.time_ns();
	evt->tid = tid_field;

	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_read(uint32_t id,
                               scap_const_sized_buffer proto,
                               scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Read gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking read protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_read:
			ret.status = scap_gvisor::fillers::fill_event_read_x(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.exit().result(),
			                                                     gvisor_evt.fd(),
			                                                     gvisor_evt.count());
			break;

		case __NR_pread64:
			ret.status = scap_gvisor::fillers::fill_event_pread_x(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.exit().result(),
			                                                      gvisor_evt.fd(),
			                                                      gvisor_evt.count(),
			                                                      gvisor_evt.offset());
			break;

		case __NR_readv:
			ret.status = scap_gvisor::fillers::fill_event_readv_x(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.exit().result(),
			                                                      gvisor_evt.count(),
			                                                      gvisor_evt.fd());
			break;

		case __NR_preadv:
			ret.status = scap_gvisor::fillers::fill_event_preadv_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.count(),
			                                                       gvisor_evt.fd(),
			                                                       gvisor_evt.offset());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_read:
			ret.status = scap_gvisor::fillers::fill_event_read_e(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.fd(),
			                                                     gvisor_evt.count());
			break;

		case __NR_pread64:
			ret.status = scap_gvisor::fillers::fill_event_pread_e(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.fd(),
			                                                      gvisor_evt.count(),
			                                                      gvisor_evt.offset());
			break;

		case __NR_readv:
			ret.status = scap_gvisor::fillers::fill_event_readv_e(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.fd());
			break;

		case __NR_preadv:
			ret.status = scap_gvisor::fillers::fill_event_preadv_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.fd(),
			                                                       gvisor_evt.offset());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

// Converts the address + port portion of a sockaddr in our representation
// Providing a large enough buffer is responsibility of the caller.
// Returns the number of bytes written
static inline size_t pack_addr_port(sockaddr *sa, char *targetbuf) {
	size_t size = 0;
	switch(sa->sa_family) {
	case AF_INET: {
		sockaddr_in *sa_in = (sockaddr_in *)sa;
		uint16_t dport = ntohs(sa_in->sin_port);
		memcpy(targetbuf, &sa_in->sin_addr.s_addr, sizeof(uint32_t));
		targetbuf += sizeof(uint32_t);
		memcpy(targetbuf, &dport, sizeof(uint16_t));
		size = sizeof(uint32_t) + sizeof(uint16_t);
	} break;

	case AF_INET6: {
		sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
		uint16_t dport = ntohs(sa_in6->sin6_port);
		memcpy(targetbuf, &sa_in6->sin6_addr, 2 * sizeof(uint64_t));
		targetbuf += 2 * sizeof(uint64_t);
		memcpy(targetbuf, &dport, sizeof(uint16_t));
		size = 2 * sizeof(uint64_t) + sizeof(uint16_t);
	} break;

	case AF_UNIX: {
		sockaddr_un *sa_un = (sockaddr_un *)sa;
		size_t len = strlcpy(targetbuf, sa_un->sun_path, UNIX_PATH_MAX);
		size = len + 1;
	} break;
	}

	return size;
}

static inline size_t pack_sock_family(sockaddr *sa, char *targetbuf) {
	uint8_t sock_family = 0;
	switch(sa->sa_family) {
	case AF_INET: {
		sockaddr_in *sa_in = (sockaddr_in *)sa;
		sock_family = socket_family_to_scap(sa_in->sin_family);
	} break;

	case AF_INET6: {
		sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
		sock_family = socket_family_to_scap(sa_in6->sin6_family);
	} break;

	case AF_UNIX: {
		sockaddr_un *sa_un = (sockaddr_un *)sa;
		sock_family = socket_family_to_scap(sa_un->sun_family);
	} break;
	}

	memcpy(targetbuf, &sock_family, sizeof(uint8_t));
	return sizeof(uint8_t);
}

// Converts a single address into a socktuple with a zeroed out local part and a remote counterpart
// Providing a large enough buffer is responsibility of the caller (socktuple_buffer_size is set for
// this reason)
static size_t pack_sockaddr_to_remote_tuple(sockaddr *sa, char *targetbuf) {
	char *buf = targetbuf;
	size_t size = 0;
	switch(sa->sa_family) {
	case AF_INET: {
		size += pack_sock_family(sa, buf);
		memset(targetbuf + 1, 0, sizeof(uint32_t));
		memset(targetbuf + 5, 0, sizeof(uint16_t));
		size += sizeof(uint32_t) + sizeof(uint16_t);
		buf = targetbuf + size;
		size += pack_addr_port(sa, buf);
	} break;

	case AF_INET6: {
		size += pack_sock_family(sa, buf);
		memset(targetbuf + 1, 0, 2 * sizeof(uint64_t));  // saddr
		memset(targetbuf + 17, 0, sizeof(uint16_t));     // sport
		size += 2 * sizeof(uint64_t) + sizeof(uint16_t);
		buf = targetbuf + size;
		size += pack_addr_port(sa, buf);
	} break;

	case AF_UNIX: {
		size += pack_sock_family(sa, buf);
		memset(targetbuf + 1, 0, sizeof(uint64_t));  // TODO: understand how to fill this
		memset(targetbuf + 1 + 8, 0, sizeof(uint64_t));
		size += sizeof(uint64_t) + sizeof(uint64_t);
		buf = targetbuf + size;
		size += pack_addr_port(sa, buf);
	} break;
	}

	return size;
}

static size_t pack_sockaddr(sockaddr *sa, char *targetbuf) {
	char *buf = targetbuf;
	size_t size = 0;
	size += pack_sock_family(sa, buf);
	buf = targetbuf + size;
	size += pack_addr_port(sa, buf);

	return size;
}

static parse_result parse_connect(uint32_t id,
                                  scap_const_sized_buffer proto,
                                  scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Connect gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking connect protobuf message";
		return ret;
	}

	if(gvisor_evt.address().size() == 0) {
		ret.status = SCAP_FAILURE;
		ret.error = "No address data received";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		char targetbuf[socktuple_buffer_size];

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr_to_remote_tuple(addr, targetbuf);
		if(size == 0) {
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		ret.status = scap_gvisor::fillers::fill_event_connect_x(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        gvisor_evt.exit().result(),
		        scap_const_sized_buffer{targetbuf, size},
		        gvisor_evt.fd(),
		        scap_const_sized_buffer{targetbuf, size});
	} else {
		char targetbuf[socktuple_buffer_size];

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr(addr, targetbuf);
		if(size == 0) {
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		ret.status = scap_gvisor::fillers::fill_event_connect_e(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        gvisor_evt.fd(),
		        scap_const_sized_buffer{targetbuf, size});
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_socket(uint32_t id,
                                 scap_const_sized_buffer proto,
                                 scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Socket gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking socket protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_socket_x(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        gvisor_evt.exit().result(),
		        socket_family_to_scap(gvisor_evt.domain()),
		        gvisor_evt.type(),
		        gvisor_evt.protocol());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_socket_e(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        socket_family_to_scap(gvisor_evt.domain()),
		        gvisor_evt.type(),
		        gvisor_evt.protocol());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_generic_syscall(uint32_t id,
                                          scap_const_sized_buffer proto,
                                          scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Syscall gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking generic syscall protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_mmap:
			ret.status = scap_gvisor::fillers::fill_event_mmap_x(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.exit().result(),
			                                                     gvisor_evt.arg1(),
			                                                     gvisor_evt.arg2(),
			                                                     gvisor_evt.arg3(),
			                                                     gvisor_evt.arg4(),
			                                                     gvisor_evt.arg5(),
			                                                     gvisor_evt.arg6());
			break;

		case __NR_munmap:
			ret.status = scap_gvisor::fillers::fill_event_munmap_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.arg1(),
			                                                       gvisor_evt.arg2());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_mmap:
			ret.status = scap_gvisor::fillers::fill_event_mmap_e(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.arg1(),
			                                                     gvisor_evt.arg2(),
			                                                     gvisor_evt.arg3(),
			                                                     gvisor_evt.arg4(),
			                                                     gvisor_evt.arg5(),
			                                                     gvisor_evt.arg6());
			break;

		case __NR_munmap:
			ret.status = scap_gvisor::fillers::fill_event_munmap_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.arg1(),
			                                                       gvisor_evt.arg2());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_accept(uint32_t id,
                                 scap_const_sized_buffer proto,
                                 scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Accept gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking accept protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		char targetbuf[socktuple_buffer_size];
		if(gvisor_evt.address().size() == 0) {
			ret.status = SCAP_FAILURE;
			ret.error = "No address data received";
			return ret;
		}

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr_to_remote_tuple(addr, targetbuf);
		if(size == 0) {
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		switch(gvisor_evt.sysno()) {
		case __NR_accept4:
			ret.status = scap_gvisor::fillers::fill_event_accept4_6_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.fd(),
			        scap_const_sized_buffer{targetbuf, size},
			        gvisor_evt.flags());
			break;

		case __NR_accept:
			ret.status = scap_gvisor::fillers::fill_event_accept_5_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.fd(),
			        scap_const_sized_buffer{targetbuf, size});
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_accept4:
			ret.status = scap_gvisor::fillers::fill_event_accept4_6_e(scap_buf,
			                                                          &ret.size,
			                                                          scap_err,
			                                                          gvisor_evt.flags());
			break;

		case __NR_accept:
			ret.status = scap_gvisor::fillers::fill_event_accept_5_e(scap_buf, &ret.size, scap_err);
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_fcntl(uint32_t id,
                                scap_const_sized_buffer proto,
                                scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Fcntl gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking fcntl protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_fcntl_x(scap_buf,
		                                                      &ret.size,
		                                                      scap_err,
		                                                      gvisor_evt.exit().result());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_fcntl_e(scap_buf,
		                                                      &ret.size,
		                                                      scap_err,
		                                                      gvisor_evt.fd(),
		                                                      fcntl_cmd_to_scap(gvisor_evt.cmd()));
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_bind(uint32_t id,
                               scap_const_sized_buffer proto,
                               scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Bind gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking bind protobuf message";
		return ret;
	}

	char targetbuf[socktuple_buffer_size];  // XXX maybe a smaller version for addr

	if(gvisor_evt.has_exit()) {
		if(gvisor_evt.address().size() == 0) {
			ret.status = SCAP_FAILURE;
			ret.error = "No address data received";
			return ret;
		}

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr(addr, targetbuf);
		if(size == 0) {
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		ret.status =
		        scap_gvisor::fillers::fill_event_bind_x(scap_buf,
		                                                &ret.size,
		                                                scap_err,
		                                                gvisor_evt.exit().result(),
		                                                scap_const_sized_buffer{targetbuf, size},
		                                                gvisor_evt.fd());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_bind_e(scap_buf,
		                                                     &ret.size,
		                                                     scap_err,
		                                                     gvisor_evt.fd());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_pipe(uint32_t id,
                               scap_const_sized_buffer proto,
                               scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Pipe gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking pipe protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_pipe_x(scap_buf,
		                                                     &ret.size,
		                                                     scap_err,
		                                                     gvisor_evt.exit().result(),
		                                                     gvisor_evt.reader(),
		                                                     gvisor_evt.writer());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_pipe_e(scap_buf, &ret.size, scap_err);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_open(uint32_t id,
                               scap_const_sized_buffer proto,
                               scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Open gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking open protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_open:
			ret.status = scap_gvisor::fillers::fill_event_open_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),
			        gvisor_evt.pathname().c_str(),
			        open_flags_to_scap(gvisor_evt.flags()),
			        open_modes_to_scap(gvisor_evt.flags(), gvisor_evt.mode()));
			break;

		case __NR_openat:
			ret.status = scap_gvisor::fillers::fill_event_openat_2_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),
			        gvisor_evt.fd(),
			        gvisor_evt.pathname().c_str(),
			        open_flags_to_scap(gvisor_evt.flags()),
			        open_modes_to_scap(gvisor_evt.mode(), gvisor_evt.flags()));
			break;

		case __NR_creat:
			ret.status = scap_gvisor::fillers::fill_event_creat_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),
			        gvisor_evt.pathname().c_str(),
			        open_modes_to_scap(O_CREAT, gvisor_evt.mode()));
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_open:
			ret.status = scap_gvisor::fillers::fill_event_open_e(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.pathname().c_str(),
			        open_flags_to_scap(gvisor_evt.flags()),
			        open_modes_to_scap(gvisor_evt.mode(), gvisor_evt.flags()));
			break;

		case __NR_openat:
			ret.status = scap_gvisor::fillers::fill_event_openat_2_e(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.fd(),
			        gvisor_evt.pathname().c_str(),
			        open_flags_to_scap(gvisor_evt.flags()),
			        open_modes_to_scap(gvisor_evt.flags(), gvisor_evt.mode()));
			break;

		case __NR_creat:
			ret.status = scap_gvisor::fillers::fill_event_creat_e(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.pathname().c_str(),
			        open_modes_to_scap(O_CREAT, gvisor_evt.mode()));
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_chdir(uint32_t id,
                                scap_const_sized_buffer proto,
                                scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Chdir gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking chdir protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_chdir:
			ret.status = scap_gvisor::fillers::fill_event_chdir_x(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.exit().result(),
			                                                      gvisor_evt.pathname().c_str());
			break;

		case __NR_fchdir:
			ret.status = scap_gvisor::fillers::fill_event_fchdir_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.fd());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_chdir:
			ret.status = scap_gvisor::fillers::fill_event_chdir_e(scap_buf, &ret.size, scap_err);
			break;

		case __NR_fchdir:
			ret.status = scap_gvisor::fillers::fill_event_fchdir_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.fd());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_setresid(uint32_t id,
                                   scap_const_sized_buffer proto,
                                   scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Setresid gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking setresid protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_setresuid:
			ret.status = scap_gvisor::fillers::fill_event_setresuid_x(scap_buf,
			                                                          &ret.size,
			                                                          scap_err,
			                                                          gvisor_evt.exit().result(),
			                                                          gvisor_evt.rid(),
			                                                          gvisor_evt.eid(),
			                                                          gvisor_evt.sid());
			break;

		case __NR_setresgid:
			ret.status = scap_gvisor::fillers::fill_event_setresgid_x(scap_buf,
			                                                          &ret.size,
			                                                          scap_err,
			                                                          gvisor_evt.exit().result(),
			                                                          gvisor_evt.rid(),
			                                                          gvisor_evt.eid(),
			                                                          gvisor_evt.sid());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_setresuid:
			ret.status = scap_gvisor::fillers::fill_event_setresuid_e(scap_buf,
			                                                          &ret.size,
			                                                          scap_err,
			                                                          gvisor_evt.rid(),
			                                                          gvisor_evt.eid(),
			                                                          gvisor_evt.sid());
			break;

		case __NR_setresgid:
			ret.status = scap_gvisor::fillers::fill_event_setresgid_e(scap_buf,
			                                                          &ret.size,
			                                                          scap_err,
			                                                          gvisor_evt.rid(),
			                                                          gvisor_evt.eid(),
			                                                          gvisor_evt.sid());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_setid(uint32_t id,
                                scap_const_sized_buffer proto,
                                scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Setid gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking setid protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_setuid:
			ret.status = scap_gvisor::fillers::fill_event_setuid_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.id());
			break;

		case __NR_setgid:
			ret.status = scap_gvisor::fillers::fill_event_setgid_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.id());
			break;

		case __NR_setsid:
			ret.status = scap_gvisor::fillers::fill_event_setsid_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_setuid:
			ret.status = scap_gvisor::fillers::fill_event_setuid_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.id());
			break;

		case __NR_setgid:
			ret.status = scap_gvisor::fillers::fill_event_setgid_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.id());
			break;

		case __NR_setsid:
			ret.status = scap_gvisor::fillers::fill_event_setsid_e(scap_buf, &ret.size, scap_err);
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_chroot(uint32_t id,
                                 scap_const_sized_buffer proto,
                                 scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Chroot gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking chroot protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_chroot_x(scap_buf,
		                                                       &ret.size,
		                                                       scap_err,
		                                                       gvisor_evt.exit().result(),
		                                                       gvisor_evt.pathname().c_str());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_chroot_e(scap_buf, &ret.size, scap_err);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_dup(uint32_t id,
                              scap_const_sized_buffer proto,
                              scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Dup gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking dup protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_dup:
			ret.status = scap_gvisor::fillers::fill_event_dup_1_x(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.exit().result(),
			                                                      gvisor_evt.old_fd());
			break;

		case __NR_dup2:
			ret.status = scap_gvisor::fillers::fill_event_dup2_x(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.exit().result(),
			                                                     gvisor_evt.old_fd(),
			                                                     gvisor_evt.new_fd());
			break;

		case __NR_dup3:
			ret.status = scap_gvisor::fillers::fill_event_dup3_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),
			        gvisor_evt.old_fd(),
			        gvisor_evt.new_fd(),
			        dup3_flags_to_scap((int)gvisor_evt.flags()));
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_dup:
			ret.status = scap_gvisor::fillers::fill_event_dup_1_e(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.old_fd());
			break;

		case __NR_dup2:
			ret.status = scap_gvisor::fillers::fill_event_dup2_e(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.old_fd());
			break;

		case __NR_dup3:
			ret.status = scap_gvisor::fillers::fill_event_dup3_e(scap_buf,
			                                                     &ret.size,
			                                                     scap_err,
			                                                     gvisor_evt.old_fd());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_sentry_task_exit(uint32_t id,
                                           scap_const_sized_buffer proto,
                                           scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];

	gvisor::sentry::TaskExit gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking task exit protobuf message";
		return ret;
	}

	int32_t exit_status = gvisor_evt.exit_status();
	ret.status = scap_gvisor::fillers::fill_event_procexit_1_e(
	        scap_buf,
	        &ret.size,
	        scap_err,
	        exit_status,
	        __WEXITSTATUS(exit_status),
	        ((__WIFSIGNALED(exit_status)) ? __WTERMSIG(exit_status) : 0),
	        ((__WCOREDUMP(exit_status)) ? 1 : 0));

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_prlimit64(uint32_t id,
                                    scap_const_sized_buffer proto,
                                    scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Prlimit gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking prlimit64 protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_prlimit_x(scap_buf,
		                                                        &ret.size,
		                                                        scap_err,
		                                                        gvisor_evt.exit().result(),
		                                                        gvisor_evt.new_limit().cur(),
		                                                        gvisor_evt.new_limit().max(),
		                                                        gvisor_evt.old_limit().cur(),
		                                                        gvisor_evt.old_limit().max());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_prlimit_e(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        gvisor_evt.pid(),
		        rlimit_resource_to_scap(gvisor_evt.resource()));
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_signalfd(uint32_t id,
                                   scap_const_sized_buffer proto,
                                   scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Signalfd gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking signalfd protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_signalfd_x(scap_buf,
		                                                         &ret.size,
		                                                         scap_err,
		                                                         gvisor_evt.exit().result(),
		                                                         gvisor_evt.fd(),
		                                                         gvisor_evt.sigset(),
		                                                         gvisor_evt.flags());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_signalfd_e(scap_buf,
		                                                         &ret.size,
		                                                         scap_err,
		                                                         gvisor_evt.fd(),
		                                                         gvisor_evt.sigset(),
		                                                         gvisor_evt.flags());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_eventfd(uint32_t id,
                                  scap_const_sized_buffer proto,
                                  scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Eventfd gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking eventfd protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_eventfd_x(scap_buf,
		                                                        &ret.size,
		                                                        scap_err,
		                                                        gvisor_evt.exit().result());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_eventfd_e(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        gvisor_evt.val(),
		        0);  // hardcoded flags=0, matches driver behavior
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_close(uint32_t id,
                                scap_const_sized_buffer proto,
                                scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Close gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking close protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_close_x(scap_buf,
		                                                      &ret.size,
		                                                      scap_err,
		                                                      gvisor_evt.exit().result(),
		                                                      gvisor_evt.fd());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_close_e(scap_buf,
		                                                      &ret.size,
		                                                      scap_err,
		                                                      gvisor_evt.fd());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_clone(uint32_t id,
                                scap_const_sized_buffer proto,
                                scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Clone gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking clone protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		auto &context_data = gvisor_evt.context_data();

		std::string cgroups = "gvisor_container_id=/";
		cgroups += context_data.container_id();

		ret.status = scap_gvisor::fillers::fill_event_clone_20_x(
		        scap_buf,
		        &ret.size,
		        scap_err,
		        gvisor_evt.exit().result(),
		        context_data.process_name().c_str(),               // exe
		        scap_const_sized_buffer{"", 0},                    // args -- INV/not available
		        generate_tid_field(context_data.thread_id(), id),  // tid
		        generate_tid_field(context_data.thread_group_id(), id),  // pid
		        0,  // ptid -- INV/not available
		        context_data.cwd().c_str(),
		        context_data.process_name().c_str(),  // comm
		        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
		        clone_flags_to_scap((int)gvisor_evt.flags()),
		        context_data.credentials().effective_uid(),  // uid
		        context_data.credentials().effective_gid(),  // gid
		        context_data.thread_id(),                    // vtid
		        context_data.thread_group_id(),              // vpid
		        context_data.thread_start_time_ns());        // pidns_init_start_ts
	} else {
		ret.status = scap_gvisor::fillers::fill_event_clone_20_e(scap_buf, &ret.size, scap_err);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_timerfd_create(uint32_t id,
                                         scap_const_sized_buffer proto,
                                         scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::TimerfdCreate gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking timerfd_create protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_timerfd_create_x(scap_buf,
		                                                               &ret.size,
		                                                               scap_err,
		                                                               gvisor_evt.exit().result(),
		                                                               gvisor_evt.clock_id(),
		                                                               gvisor_evt.flags());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_timerfd_create_e(scap_buf,
		                                                               &ret.size,
		                                                               scap_err,
		                                                               gvisor_evt.clock_id(),
		                                                               gvisor_evt.flags());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_fork(uint32_t id,
                               scap_const_sized_buffer proto,
                               scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Fork gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking fork protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		auto &context_data = gvisor_evt.context_data();

		std::string cgroups = "gvisor_container_id=/";
		cgroups += context_data.container_id();

		switch(gvisor_evt.sysno()) {
		case __NR_fork:
			ret.status = scap_gvisor::fillers::fill_event_fork_20_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),
			        context_data.process_name().c_str(),                     // exe
			        generate_tid_field(context_data.thread_id(), id),        // tid
			        generate_tid_field(context_data.thread_group_id(), id),  // pid
			        context_data.cwd().c_str(),
			        context_data.process_name().c_str(),  // comm
			        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
			        context_data.credentials().effective_uid(),  // uid
			        context_data.credentials().effective_gid(),  // gid
			        context_data.thread_id(),                    // vtid
			        context_data.thread_group_id(),              // vpid
			        context_data.thread_start_time_ns());        // pidns_init_start_ts

		case __NR_vfork:
			ret.status = scap_gvisor::fillers::fill_event_vfork_20_x(
			        scap_buf,
			        &ret.size,
			        scap_err,
			        gvisor_evt.exit().result(),
			        context_data.process_name().c_str(),                     // exe
			        generate_tid_field(context_data.thread_id(), id),        // tid
			        generate_tid_field(context_data.thread_group_id(), id),  // pid
			        context_data.cwd().c_str(),
			        context_data.process_name().c_str(),  // comm
			        scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1},
			        context_data.credentials().effective_uid(),  // uid
			        context_data.credentials().effective_gid(),  // gid
			        context_data.thread_id(),                    // vtid
			        context_data.thread_group_id(),              // vpid
			        context_data.thread_start_time_ns());        // pidns_init_start_ts
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_fork:
			ret.status = scap_gvisor::fillers::fill_event_fork_20_e(scap_buf, &ret.size, scap_err);
			break;

		case __NR_vfork:
			ret.status = scap_gvisor::fillers::fill_event_vfork_20_e(scap_buf, &ret.size, scap_err);
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_inotify_init(uint32_t id,
                                       scap_const_sized_buffer proto,
                                       scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Eventfd gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking inotify_init protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_inotify_init_x(scap_buf,
		                                                             &ret.size,
		                                                             scap_err,
		                                                             gvisor_evt.exit().result(),
		                                                             gvisor_evt.flags());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_inotify_init_e(scap_buf,
		                                                             &ret.size,
		                                                             scap_err,
		                                                             gvisor_evt.flags());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_socketpair(uint32_t id,
                                     scap_const_sized_buffer proto,
                                     scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::SocketPair gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking socketpair protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		ret.status = scap_gvisor::fillers::fill_event_socketpair_x(scap_buf,
		                                                           &ret.size,
		                                                           scap_err,
		                                                           gvisor_evt.exit().result(),
		                                                           gvisor_evt.socket1(),
		                                                           gvisor_evt.socket2());
	} else {
		ret.status = scap_gvisor::fillers::fill_event_socketpair_e(scap_buf,
		                                                           &ret.size,
		                                                           scap_err,
		                                                           gvisor_evt.domain(),
		                                                           gvisor_evt.type(),
		                                                           gvisor_evt.protocol());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_write(uint32_t id,
                                scap_const_sized_buffer proto,
                                scap_sized_buffer scap_buf) {
	parse_result ret;
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Write gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size)) {
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking write protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit()) {
		switch(gvisor_evt.sysno()) {
		case __NR_write:
			ret.status = scap_gvisor::fillers::fill_event_write_x(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.exit().result(),
			                                                      gvisor_evt.fd(),
			                                                      gvisor_evt.count());
			break;

		case __NR_pwrite64:
			ret.status = scap_gvisor::fillers::fill_event_pwrite_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.fd(),
			                                                       gvisor_evt.count(),
			                                                       gvisor_evt.offset());
			break;

		case __NR_writev:
			ret.status = scap_gvisor::fillers::fill_event_writev_x(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.exit().result(),
			                                                       gvisor_evt.fd(),
			                                                       gvisor_evt.count());
			break;

		case __NR_pwritev:
			ret.status = scap_gvisor::fillers::fill_event_pwritev_x(scap_buf,
			                                                        &ret.size,
			                                                        scap_err,
			                                                        gvisor_evt.exit().result(),
			                                                        gvisor_evt.fd(),
			                                                        gvisor_evt.count(),
			                                                        gvisor_evt.offset());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	} else {
		switch(gvisor_evt.sysno()) {
		case __NR_write:
			ret.status = scap_gvisor::fillers::fill_event_write_e(scap_buf,
			                                                      &ret.size,
			                                                      scap_err,
			                                                      gvisor_evt.fd(),
			                                                      gvisor_evt.count());
			break;

		case __NR_pwrite64:
			ret.status = scap_gvisor::fillers::fill_event_pwrite_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.fd(),
			                                                       gvisor_evt.count(),
			                                                       gvisor_evt.offset());
			break;

		case __NR_writev:
			ret.status = scap_gvisor::fillers::fill_event_writev_e(scap_buf,
			                                                       &ret.size,
			                                                       scap_err,
			                                                       gvisor_evt.fd(),
			                                                       gvisor_evt.count());
			break;

		case __NR_pwritev:
			ret.status = scap_gvisor::fillers::fill_event_pwritev_e(scap_buf,
			                                                        &ret.size,
			                                                        scap_err,
			                                                        gvisor_evt.fd(),
			                                                        gvisor_evt.count(),
			                                                        gvisor_evt.offset());
			break;

		default:
			ret.status = process_unhandled_syscall(gvisor_evt.sysno(), scap_err);
			break;
		}
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt, id);
	ret.scap_events.push_back(evt);

	return ret;
}

parse_result parse_gvisor_proto(uint32_t id,
                                scap_const_sized_buffer gvisor_buf,
                                scap_sized_buffer scap_buf) {
	parse_result ret;

	if(id == 0) {
		ret.error = "Invalid sandbox ID 0";
		ret.status = SCAP_FAILURE;
		return ret;
	}

	const char *buf = static_cast<const char *>(gvisor_buf.buf);
	const header *hdr = reinterpret_cast<const header *>(buf);
	if(hdr->header_size > gvisor_buf.size) {
		ret.error = std::string("Header size (") + std::to_string(hdr->header_size) +
		            ") is larger than message " + std::to_string(gvisor_buf.size);
		ret.status = SCAP_FAILURE;
		return ret;
	}

	// dropped count is the absolute number of events dropped from gVisor side
	ret.dropped_count = hdr->dropped_count;
	const char *proto = &buf[hdr->header_size];
	size_t proto_size = gvisor_buf.size - hdr->header_size;

	size_t message_type = hdr->message_type;
	if(message_type == 0) {
		ret.error = std::string("Invalid message type 0");
		ret.status = SCAP_FAILURE;
		return ret;
	}

	if(message_type >= dispatchers.size()) {
		ret.error = std::string("No parser registered for message type: ") +
		            std::to_string(message_type);
		ret.status = SCAP_NOT_SUPPORTED;
		return ret;
	}

	event_parser parser = dispatchers[message_type];
	if(parser.parse_msg == nullptr) {
		ret.error = std::string("No parser registered for message type: ") +
		            std::to_string(message_type);
		ret.status = SCAP_NOT_SUPPORTED;
		return ret;
	}

	return parser.parse_msg(id, scap_const_sized_buffer{proto, proto_size}, scap_buf);
}

std::string parse_container_id(scap_const_sized_buffer gvisor_buf) {
	const char *buf = static_cast<const char *>(gvisor_buf.buf);
	const header *hdr = reinterpret_cast<const header *>(buf);
	if(hdr->header_size > gvisor_buf.size) {
		return "";
	}

	const char *proto = &buf[hdr->header_size];
	size_t proto_size = gvisor_buf.size - hdr->header_size;

	size_t message_type = hdr->message_type;
	if(message_type == 0) {
		return "";
	}

	if(message_type >= dispatchers.size()) {
		return "";
	}

	event_parser parser = dispatchers[message_type];
	if(parser.parse_container_id == nullptr) {
		return "";
	}

	return parser.parse_container_id(scap_const_sized_buffer{proto, proto_size});
}

procfs_result parse_procfs_json(const std::string &input, uint32_t sandbox_id) {
	procfs_result res;
	memset(&res.tinfo, 0, sizeof(res.tinfo));
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::string err;
	const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());

	bool json_parse = reader->parse(input.c_str(), input.c_str() + input.size(), &root, &err);
	if(!json_parse) {
		res.status = SCAP_FAILURE;
		res.error = "Malformed json string: cannot parse procfs entry: " + err;
		return res;
	}

	//
	// Initialize res, so that in case of error we can
	// directly return it
	//

	res.status = SCAP_FAILURE;
	res.error = "Missing json field or wrong type: cannot parse procfs entry";
	scap_threadinfo &tinfo = res.tinfo;

	//
	// Fill threadinfo
	//

	if(!root.isMember("status")) {
		return res;
	}
	Json::Value &status = root["status"];

	if(!root.isMember("stat")) {
		return res;
	}
	Json::Value &stat = root["stat"];

	// tid
	if(!status.isMember("pid") || !status["pid"].isUInt64()) {
		return res;
	}
	tinfo.tid = generate_tid_field(status["pid"].asUInt64(), sandbox_id);

	// pid
	if(!stat.isMember("pgid") || !stat["pgid"].isUInt64()) {
		return res;
	}
	tinfo.pid = generate_tid_field(stat["pgid"].asUInt64(), sandbox_id);

	// sid
	if(!stat.isMember("sid") || !stat["sid"].isUInt64()) {
		return res;
	}
	tinfo.sid = stat["sid"].asUInt64();

	// vpgid
	tinfo.vpgid = stat["pgid"].asUInt64();

	// comm
	if(!status.isMember("comm") || !status["comm"].isString()) {
		return res;
	}
	strlcpy(tinfo.comm, status["comm"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// exe
	if(!root.isMember("args") || !root["args"].isArray() || !root["args"][0].isString()) {
		return res;
	}
	strlcpy(tinfo.exe, root["args"][0].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// exepath
	if(!root.isMember("exe") || !root["exe"].isString()) {
		return res;
	}
	strlcpy(tinfo.exepath, root["exe"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// args
	if(!root.isMember("args") || !root["args"].isArray()) {
		return res;
	}
	std::string args;
	for(Json::Value::ArrayIndex i = 0; i < root["args"].size(); i++) {
		args += root["args"][i].asString();
		args.push_back('\0');
	}
	size_t args_size = args.size() > SCAP_MAX_ARGS_SIZE ? SCAP_MAX_ARGS_SIZE : args.size();
	tinfo.args_len = args_size;
	memcpy(tinfo.args, args.data(), args_size);
	tinfo.args[SCAP_MAX_ARGS_SIZE] = '\0';

	// env
	if(!root.isMember("env") || !root["env"].isArray()) {
		return res;
	}
	std::string env;
	for(Json::Value::ArrayIndex i = 0; i < root["env"].size(); i++) {
		env += root["env"][i].asString();
		env.push_back('\0');
	}
	size_t env_size = env.size() > SCAP_MAX_ENV_SIZE ? SCAP_MAX_ENV_SIZE : env.size();
	tinfo.env_len = env_size;
	memcpy(tinfo.env, env.data(), env_size);
	tinfo.env[SCAP_MAX_ENV_SIZE] = '\0';

	// cwd
	if(!root.isMember("cwd") || !root["cwd"].isString()) {
		return res;
	}
	strlcpy(tinfo.cwd, root["cwd"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// uid
	if(!status.isMember("uid") || !status["uid"].isMember("effective") ||
	   !status["uid"]["effective"].isUInt64()) {
		return res;
	}
	tinfo.uid = status["uid"]["effective"].asUInt64();

	// gid
	if(!status.isMember("gid") || !status["gid"].isMember("effective") ||
	   !status["gid"]["effective"].isUInt64()) {
		return res;
	}
	tinfo.gid = status["gid"]["effective"].asUInt64();

	// vtid
	tinfo.vtid = status["pid"].asUInt64();

	// vpid
	tinfo.vpid = status["pgid"].asUInt64();

	// root
	if(!root.isMember("root") || !root["root"].isString()) {
		return res;
	}
	strlcpy(tinfo.root, root["root"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// clone_ts
	if(!root.isMember("clone_ts") || !root["clone_ts"].isUInt64()) {
		return res;
	}
	tinfo.clone_ts = root["clone_ts"].asUInt64();

	// fdinfos

	// set error so that we can understand that parsing failed here
	res.error = "Error parsing fdlist";

	std::vector<scap_fdinfo> &fds = res.fdinfos;
	if(!root.isMember("fdlist") || !root["fdlist"].isArray()) {
		return res;
	}
	for(Json::Value::ArrayIndex i = 0; i != root["fdlist"].size(); i++) {
		Json::Value &entry = root["fdlist"][i];
		scap_fdinfo fdinfo;

		if(!entry.isMember("number") || !entry["number"].isUInt64()) {
			return res;
		}
		fdinfo.fd = entry["number"].asUInt64();

		if(!entry.isMember("mode") || !entry["mode"].isUInt64()) {
			return res;
		}

		if(!entry.isMember("path") || !entry["path"].isString()) {
			return res;
		}

		uint64_t mode = entry["mode"].asUInt64();

		if(S_ISREG(mode)) {
			fdinfo.type = SCAP_FD_FILE_V2;
			strlcpy(fdinfo.info.regularinfo.fname, entry["path"].asCString(), SCAP_MAX_PATH_SIZE);
		} else {
			continue;
		}

		fds.push_back(fdinfo);
	}

	res.status = SCAP_SUCCESS;
	res.error = "";
	return res;
}

config_result parse_config(std::string config) {
	config_result res;
	res.socket_path = "";
	res.error = "";
	res.status = SCAP_FAILURE;

	std::string err;
	Json::Value root;
	Json::CharReaderBuilder builder;
	const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());

	bool json_parse = reader->parse(config.c_str(), config.c_str() + config.size(), &root, &err);
	if(!json_parse) {
		res.error = "Could not parse configuration file contents: " + err;
		return res;
	}

	if(!root.isMember("trace_session")) {
		res.error = "Could not find trace_session entry in configuration";
		return res;
	}
	Json::Value &trace_session = root["trace_session"];

	if(!trace_session.isMember("sinks") || !trace_session["sinks"].isArray()) {
		res.error = "Could not find trace_session -> sinks array in configuration";
		return res;
	}

	if(trace_session["sinks"].size() == 0) {
		res.error = "trace_session -> sinks array is empty";
		return res;
	}

	// We don't know how to distinguish between sinks in case there is more than one
	// we're taking the first for now but this can be tweaked if necessary.
	Json::Value &sink = trace_session["sinks"][0];

	if(!sink.isMember("config")) {
		res.error = "Could not find config in sink item";
		return res;
	}
	Json::Value &sink_config = sink["config"];

	if(!sink_config.isMember("endpoint") || !sink_config["endpoint"].isString()) {
		res.error = "Could not find endpoint in sink configuration";
		return res;
	}

	res.socket_path = sink_config["endpoint"].asString();
	res.status = SCAP_SUCCESS;
	return res;
}

}  // namespace parsers
}  // namespace scap_gvisor
