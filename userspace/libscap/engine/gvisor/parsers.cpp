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
#include <sys/syscall.h> // SYS_* constants

#include <functional>
#include <unordered_map>
#include <sstream>
#include <string>

#include <json/json.h>

#include "gvisor.h"
#include "parsers.h"
#include "compat/misc.h"
#include "../../driver/ppm_events_public.h"
#include "strl.h"

#include "userspace_flag_helpers.h"

#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

namespace scap_gvisor {
namespace parsers {

constexpr size_t socktuple_buffer_size = 1024;

// In gVisor there's no concept of tid and tgid but only vtid and vtgid.
// However, to fit into sinsp we do need values for tid and tgid.
static uint64_t generate_tid_field(uint64_t tid, std::string container_id_hex)
{
	std::string container_id_64 = container_id_hex.length() > 16 ? container_id_hex.substr(0, 15) : container_id_hex;

	uint64_t tid_field = stoull(container_id_64, nullptr, 16);
	tid_field = (tid_field & 0xffffffff00000000) ^ tid;
	return tid_field;
}

// Perform conversion from pid/tid field to vpid/vtid
uint64_t get_vxid(uint64_t xid)
{
	return xid & 0xffffffff;
}

template<class T>
static void fill_context_data(scap_evt *evt, T& gvisor_evt)
{
	auto& context_data = gvisor_evt.context_data();
	evt->ts = context_data.time_ns();
	evt->tid = generate_tid_field(context_data.thread_id(), context_data.container_id());
}

static parse_result parse_container_start(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	scap_sized_buffer event_buf = scap_buf;
	size_t event_size;

	gvisor::container::Start gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking container start protobuf message";
		return ret;
	}

	std::string args;
	for(int j = 0; j < gvisor_evt.args_size(); j++) {
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

	auto& context_data = gvisor_evt.context_data();

	std::string cwd = context_data.cwd();

	uint64_t tid_field = generate_tid_field(1, container_id);
	uint64_t tgid_field = generate_tid_field(1, container_id);

	// encode clone entry

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_CLONE_20_E, 0);
	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode clone exit

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_CLONE_20_X, 20,
		(int64_t) 0, // child tid (0 in the child)
		gvisor_evt.args(0).c_str(), // actual exe is not currently sent
		scap_const_sized_buffer{args.data(), args.size()},
		tid_field, // tid
		tgid_field, // pid
		(int64_t) 1, // ptid
		"", // cwd
		(uint64_t) 75000, // fdlimit
		(uint64_t) 0, // pgft_maj
		(uint64_t) 0, // pgft_min
		0, // vm_size
		0, // vm_rss
		0, // vm_swap
		gvisor_evt.args(0).c_str(), // comm
		scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
		0, // clone_flags
		context_data.credentials().real_uid(), // uid
		context_data.credentials().real_gid(), // gid
		(int64_t) 1, // vtid
		(int64_t) 1); // vpid

	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode execve entry

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_EXECVE_19_E,
		1, gvisor_evt.args(0).c_str()); // TODO actual exe missing

	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode execve exit

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_EXECVE_19_X, 20,
		(int64_t) 0, // res
		gvisor_evt.args(0).c_str(), // actual exe missing
		scap_const_sized_buffer{args.data(), args.size()},
		tid_field, // tid
		tgid_field, // pid
		(int64_t) -1, // ptid is only needed if we don't have the corresponding clone event
		cwd.c_str(), // cwd
		(uint64_t) 75000, // fdlimit ?
		(uint64_t) 0, // pgft_maj
		(uint64_t) 0, // pgft_min
		0, // vm_size
		0, // vm_rss
		0, // vm_swap
		gvisor_evt.args(0).c_str(), // args.c_str() // comm
		scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
		scap_const_sized_buffer{env.data(), env.size()}, // env
		0, // tty
		(int64_t) 0, // pgid
		UINT32_MAX, // loginuid (auid)
		0); // flags (not necessary)
	
	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = context_data.time_ns();
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	return ret;
}

static parse_result parse_execve(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	gvisor::syscall::Execve gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking execve protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		std::string args;
		for(int j = 0; j < gvisor_evt.argv_size(); j++) {
			args += gvisor_evt.argv(j);
			args.push_back('\0');
		}

		std::string env;
		for(int j = 0; j < gvisor_evt.envv_size(); j++) {
			env += gvisor_evt.envv(j);
			env.push_back('\0');
		}

		std::string comm, pathname;
		pathname = gvisor_evt.pathname();
		comm = pathname.substr(pathname.find_last_of("/") + 1);

		auto& context_data = gvisor_evt.context_data();

		std::string cwd = context_data.cwd();

		std::string cgroups = "gvisor_container_id=/";
		cgroups += context_data.container_id();

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_EXECVE_19_X, 20,
			gvisor_evt.exit().result(), // res
			gvisor_evt.pathname().c_str(), // exe
			scap_const_sized_buffer{args.data(), args.size()}, // args
			generate_tid_field(context_data.thread_id(), context_data.container_id()), // tid
			generate_tid_field(context_data.thread_group_id(), context_data.container_id()), // pid
			(int64_t) -1, // ptid is only needed if we don't have the corresponding clone event
			cwd.c_str(), // cwd
			(uint64_t) 75000, // fdlimit
			(uint64_t) 0, // pgft_maj
			(uint64_t) 0, // pgft_min
			0, // vm_size
			0, // vm_rss
			0, // vm_swap
			comm.c_str(), // comm
			scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
			scap_const_sized_buffer{env.data(), env.size()}, // env
			0, // tty
			(int64_t) 0, // pgid
			UINT32_MAX, // loginuid (auid)
			0); // flags (not necessary)

	} else 
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_EXECVE_19_E, 1, gvisor_evt.pathname().c_str());
	}

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_clone(const gvisor::syscall::Syscall &gvisor_evt, scap_sized_buffer scap_buf, bool is_fork)
{
	parse_result ret = {0};
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	auto& context_data = gvisor_evt.context_data();

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CLONE_20_X, 20,
			gvisor_evt.exit().result(), // res
			"", // exe
			scap_const_sized_buffer{"", 0}, // args
			generate_tid_field(context_data.thread_id(), context_data.container_id()), // tid
			generate_tid_field(context_data.thread_group_id(), context_data.container_id()), // pid
			(int64_t) 0, // ptid
			context_data.cwd().c_str(), // cwd
			(uint64_t) 75000, // fdlimit
			(uint64_t) 0, // pgft_maj
			(uint64_t) 0, // pgft_min
			0, // vm_size
			0, // vm_rss
			0, // vm_swap
			context_data.process_name().c_str(), // comm
			scap_const_sized_buffer{"", 0},
			is_fork ? PPM_CL_CLONE_CHILD_CLEARTID|PPM_CL_CLONE_CHILD_SETTID : clone_flags_to_scap(gvisor_evt.arg1()),
			0,
			0,
			gvisor_evt.context_data().thread_id(),
			gvisor_evt.context_data().thread_group_id());
	} else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CLONE_20_E, 0);
	}

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_sentry_clone(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	gvisor::sentry::CloneInfo gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking sentry clone protobuf message";
		return ret;
	}

	auto& context_data = gvisor_evt.context_data();

	std::string cgroups = "gvisor_container_id=/";
	cgroups += context_data.container_id();

	uint64_t tid_field = generate_tid_field(gvisor_evt.created_thread_id(), context_data.container_id());

	ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CLONE_20_X, 20,
		0, // res
		context_data.process_name().c_str(), // exe
		scap_const_sized_buffer{"", 0}, // args
		tid_field, // tid
		generate_tid_field(gvisor_evt.created_thread_group_id(), context_data.container_id()), // pid
		generate_tid_field(context_data.thread_id(), context_data.container_id()), // ptid
		"", // cwd
		(uint64_t) 75000, // fdlimit
		(uint64_t) 0, // pgft_maj
		(uint64_t) 0, // pgft_min
		0, // vm_size
		0, // vm_rss
		0, // vm_swap
		context_data.process_name().c_str(), // comm
		scap_const_sized_buffer{cgroups.c_str(), cgroups.size() + 1},
		0,
		0,
		0,
		gvisor_evt.created_thread_id(),
		gvisor_evt.created_thread_group_id());

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}
	
	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	evt->ts = context_data.time_ns();
	evt->tid = tid_field;

	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_read(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Read gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking read protobuf message";
		return ret;
	}

	if(!gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_READ_E, 2,
							gvisor_evt.fd(),
							gvisor_evt.count());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_READ_X, 2,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{NULL, 0});
	}

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}
	
	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);

	ret.scap_events.push_back(evt);

	return ret;
}

// Converts the address + port portion of a sockaddr in our representation
// Providing a large enough buffer is responsibility of the caller.
// Returns the number of bytes written
static inline size_t pack_addr_port(sockaddr *sa, char *targetbuf)
{
	size_t size = 0;
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			sockaddr_in *sa_in = (sockaddr_in *)sa;
			uint16_t dport = ntohs(sa_in->sin_port);
			memcpy(targetbuf, &sa_in->sin_addr.s_addr, sizeof(uint32_t));
			targetbuf += sizeof(uint32_t);
			memcpy(targetbuf, &dport, sizeof(uint16_t));
			size = sizeof(uint32_t) + sizeof(uint16_t);
		}
		break;

		case AF_INET6:
		{
			sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
			uint16_t dport = ntohs(sa_in6->sin6_port);
			memcpy(targetbuf, &sa_in6->sin6_addr, 2 * sizeof(uint64_t));
			targetbuf += 2 * sizeof(uint64_t);
			memcpy(targetbuf, &dport, sizeof(uint16_t));
			size = 2 * sizeof(uint64_t) + sizeof(uint16_t);
		}
		break;

		case AF_UNIX:
		{
			sockaddr_un *sa_un = (sockaddr_un *)sa;
			size_t len = strlcpy(targetbuf, sa_un->sun_path, UNIX_PATH_MAX);
			size = len + 1;
		}
		break;
	}

	return size;
}

static inline size_t pack_sock_family(sockaddr *sa, char *targetbuf)
{
	uint8_t sock_family = 0;
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			sockaddr_in *sa_in = (sockaddr_in *)sa;
			sock_family = socket_family_to_scap(sa_in->sin_family);
		}
		break;

		case AF_INET6:
		{
			sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
			sock_family = socket_family_to_scap(sa_in6->sin6_family);
		}
		break;

		case AF_UNIX:
		{
			sockaddr_un *sa_un = (sockaddr_un *)sa;
			sock_family = socket_family_to_scap(sa_un->sun_family);
		}
		break;
	}

	memcpy(targetbuf, &sock_family, sizeof(uint8_t));
	return sizeof(uint8_t);
}

// Converts a single address into a socktuple with a zeroed out local part and a remote counterpart
// Providing a large enough buffer is responsibility of the caller (socktuple_buffer_size is set for this reason)
static size_t pack_sockaddr_to_remote_tuple(sockaddr *sa, char *targetbuf)
{
	char *buf = targetbuf;
	size_t size = 0;
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			size += pack_sock_family(sa, buf);
			memset(targetbuf + 1, 0, sizeof(uint32_t));
			memset(targetbuf + 5, 0, sizeof(uint16_t));
			size += sizeof(uint32_t) + sizeof(uint16_t);
			buf = targetbuf + size;
			size += pack_addr_port(sa, buf);
		}
		break;

		case AF_INET6:
		{
			size += pack_sock_family(sa, buf);
			memset(targetbuf + 1, 0, 2 * sizeof(uint64_t)); //saddr
			memset(targetbuf + 17, 0, sizeof(uint16_t)); //sport
			size += 2 * sizeof(uint64_t) + sizeof(uint16_t);
			buf = targetbuf + size;
			size += pack_addr_port(sa, buf);
		}
		break;

		case AF_UNIX:
		{
			size += pack_sock_family(sa, buf);
			memset(targetbuf + 1, 0, sizeof(uint64_t)); // TODO: understand how to fill this 
			memset(targetbuf + 1 + 8, 0, sizeof(uint64_t));
			size += sizeof(uint64_t) + sizeof(uint64_t);
			buf = targetbuf + size;
			size += pack_addr_port(sa, buf);
		}
		break;
	}

	return size;
}

static size_t pack_sockaddr(sockaddr *sa, char *targetbuf)
{
	char *buf = targetbuf;
	size_t size = 0;
	size += pack_sock_family(sa, buf);
	buf = targetbuf + size;
	size += pack_addr_port(sa, buf);

	return size;
}

static parse_result parse_connect(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Connect gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking connect protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		char targetbuf[socktuple_buffer_size];
		if(gvisor_evt.address().size() == 0)
		{
			ret.status = SCAP_FAILURE;
			ret.error = "No address data received";
			return ret;
		}

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr_to_remote_tuple(addr, targetbuf);
		if (size == 0)
		{
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_CONNECT_X, 3,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{targetbuf, size},
						                gvisor_evt.fd());
		if (ret.status != SCAP_SUCCESS) {
			ret.error = scap_err;
			return ret;
		}
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_CONNECT_E, 1, gvisor_evt.fd());
		if (ret.status != SCAP_SUCCESS) {
			ret.error = scap_err;
			return ret;
		}
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_socket(const char *proto, size_t proto_size, scap_sized_buffer event_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Socket gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking socket protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(event_buf, &ret.size, scap_err, PPME_SOCKET_SOCKET_X, 1, gvisor_evt.exit().result());
	}
	else
	{
		ret.status = scap_event_encode_params(event_buf, &ret.size, scap_err, PPME_SOCKET_SOCKET_E, 3, socket_family_to_scap(gvisor_evt.domain()), gvisor_evt.type(), gvisor_evt.protocol());
	}

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_generic_syscall(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	gvisor::syscall::Syscall gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking generic syscall protobuf message";
		return ret;
	}

	switch(gvisor_evt.sysno())
	{
		case SYS_clone:
			return parse_clone(gvisor_evt, scap_buf, true);
		case SYS_fork:
			return parse_clone(gvisor_evt, scap_buf, false);
		default:
			ret.error = std::string("Unhandled syscall: ") + std::to_string(gvisor_evt.sysno());
			ret.status = SCAP_NOT_SUPPORTED;
			return ret;
	}
	
	ret.status = SCAP_FAILURE;
	return ret;
}

static parse_result parse_accept(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Accept gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking accept protobuf message";
		return ret;
	}

	ppm_event_code type;

	if(gvisor_evt.has_exit())
	{
		char targetbuf[socktuple_buffer_size];
		if(gvisor_evt.address().size() == 0)
		{
			ret.status = SCAP_FAILURE;
			ret.error = "No address data received";
			return ret;
		}

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr_to_remote_tuple(addr, targetbuf);
		if (size == 0)
		{
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		type = gvisor_evt.sysno() == SYS_accept4 ? PPME_SOCKET_ACCEPT4_6_X : PPME_SOCKET_ACCEPT_5_X;

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 5,
			gvisor_evt.fd(),
			scap_const_sized_buffer{targetbuf, size},
			0, 0, 0); // queue information missing
	}
	else
	{
		type = gvisor_evt.sysno() == SYS_accept4 ? PPME_SOCKET_ACCEPT4_6_E : PPME_SOCKET_ACCEPT_5_E;

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 0);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_fcntl(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Fcntl gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking fcntl protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_FCNTL_X, 1,
			gvisor_evt.exit().result());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_FCNTL_E, 2,
			gvisor_evt.fd(),
			fcntl_cmd_to_scap(gvisor_evt.cmd()));
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_bind(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Bind gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking bind protobuf message";
		return ret;
	}

	char targetbuf[socktuple_buffer_size]; // XXX maybe a smaller version for addr

	if(gvisor_evt.has_exit())
	{
		if(gvisor_evt.address().size() == 0)
		{
			ret.status = SCAP_FAILURE;
			ret.error = "No address data received";
			return ret;
		}

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		size_t size = pack_sockaddr(addr, targetbuf);
		if (size == 0)
		{
			ret.status = SCAP_FAILURE;
			ret.error = "Could not parse received address";
			return ret;
		}

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_BIND_X, 2,
			gvisor_evt.exit().result(),
			scap_const_sized_buffer{targetbuf, size});
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_BIND_E, 1,
			gvisor_evt.fd());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_pipe(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Pipe gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking pipe protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_PIPE_X, 4,
							gvisor_evt.exit().result(),
							gvisor_evt.reader(),
							gvisor_evt.writer(),
							0); // missing "ino"
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_PIPE_E, 0);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_open(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Open gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking open protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		uint32_t flags = gvisor_evt.flags();

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_OPEN_X, 5,
		    					gvisor_evt.exit().result(),
								gvisor_evt.pathname().c_str(),
								open_flags_to_scap(flags),
								open_modes_to_scap(gvisor_evt.mode(), flags),
								0); // missing "dev"
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_OPEN_E, 0);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_chdir(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Chdir gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking chdir protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CHDIR_X, 2,
							gvisor_evt.exit().result(),
							gvisor_evt.pathname().c_str());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CHDIR_E, 0);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_setresid(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Setresid gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking setresid protobuf message";
		return ret;
	}

	ppm_event_code type;

	if(gvisor_evt.has_exit())
	{
		type = gvisor_evt.sysno() == SYS_setresuid ? PPME_SYSCALL_SETRESUID_X : PPME_SYSCALL_SETRESGID_X;

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 1,
		    					gvisor_evt.exit().result()); 
	}
	else
	{
		type = gvisor_evt.sysno() == SYS_setresuid ? PPME_SYSCALL_SETRESUID_E : PPME_SYSCALL_SETRESGID_E;

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 3,
								gvisor_evt.rgid(), 
								gvisor_evt.egid(),
								gvisor_evt.sgid());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_setid(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Setid gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking setid protobuf message";
		return ret;
	}

	ppm_event_code type;

	if(gvisor_evt.has_exit())
	{
		type = gvisor_evt.sysno() == SYS_setuid ? PPME_SYSCALL_SETUID_X : PPME_SYSCALL_SETGID_X;

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 1,
		    					gvisor_evt.exit().result()); 
	}
	else
	{
		type = gvisor_evt.sysno() == SYS_setuid ? PPME_SYSCALL_SETUID_E : PPME_SYSCALL_SETGID_E;

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 1,
								gvisor_evt.id());
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_chroot(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Chroot gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking chroot protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CHROOT_X, 2,
							gvisor_evt.exit().result(),
							gvisor_evt.pathname().c_str());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CHROOT_E, 0);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_dup(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Dup gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking dup protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		switch(gvisor_evt.sysno())
		{
		case SYS_dup:
			ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_DUP_1_X, 2,
							gvisor_evt.exit().result(),
							gvisor_evt.old_fd());
			break;
		case SYS_dup2:
			ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_DUP2_X, 3,
							gvisor_evt.exit().result(),
							gvisor_evt.old_fd(),
							gvisor_evt.new_fd());
			break;
		case SYS_dup3:
			ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_DUP3_X, 4,
							gvisor_evt.exit().result(),
							gvisor_evt.old_fd(),
							gvisor_evt.new_fd(),
							dup3_flags_to_scap(gvisor_evt.flags()));
			break;
		}
	}
	else
	{
		ppm_event_code type;

		switch(gvisor_evt.sysno())
		{
		case SYS_dup:
			type = PPME_SYSCALL_DUP_1_E;
			break;
		case SYS_dup2:
			type = PPME_SYSCALL_DUP2_E;
			break;
		case SYS_dup3:
			type = PPME_SYSCALL_DUP3_E;
			break;
		default:
			ret.status = SCAP_FAILURE;
			ret.error = "Unrecognized syscall number for dup family syscalls";
			return ret;
		}

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, type, 1, gvisor_evt.old_fd());
	}

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_task_exit(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::sentry::TaskExit gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking task exit protobuf message";
		return ret;
	}

	ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_PROCEXIT_1_E, 4, gvisor_evt.exit_status(),
					(int64_t) 0, 0, 0);

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_prlimit64(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Prlimit gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking prlimit64 protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_PRLIMIT_X, 5,
							gvisor_evt.exit().result(),
							gvisor_evt.new_limit().cur(),
							gvisor_evt.new_limit().max(),
							gvisor_evt.old_limit().cur(),
							gvisor_evt.old_limit().max());
	}
	else 
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_PRLIMIT_E, 2,
							gvisor_evt.pid(),
							rlimit_resource_to_scap(gvisor_evt.resource()));
	}

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

static parse_result parse_signalfd(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Signalfd gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking signalfd protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_SIGNALFD_X, 1,
							gvisor_evt.exit().result());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_SIGNALFD_E, 3,
							gvisor_evt.fd(),
							gvisor_evt.sigset(),
							gvisor_evt.flags());
	}

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

parse_result parse_eventfd(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Eventfd gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto, proto_size))
	{
		ret.status = SCAP_FAILURE;
		ret.error = "Error unpacking signalfd protobuf message";
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_EVENTFD_X, 1,
						      gvisor_evt.exit().result());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_EVENTFD_E, 2,
						      gvisor_evt.val(),
						      0); // flags not yet implemented, also in the drivers
	}

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt *>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

parse_result parse_gvisor_proto(scap_const_sized_buffer gvisor_buf, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	const char *buf = static_cast<const char*>(gvisor_buf.buf);

	const header *hdr = reinterpret_cast<const header *>(buf);
	if(hdr->header_size > gvisor_buf.size)
	{
		ret.error = std::string("Header size (") + std::to_string(hdr->header_size) + ") is larger than message " + std::to_string(gvisor_buf.size);
		ret.status = SCAP_FAILURE;
		return ret;
	}

	// dropped count is the absolute number of events dropped from gVisor side
	ret.dropped_count = hdr->dropped_count;
	const char *proto = &buf[hdr->header_size];
	ssize_t proto_size = gvisor_buf.size - hdr->header_size;

	size_t message_type = hdr->message_type;
	if (message_type == 0) {
		ret.error = std::string("Invalid message type 0");
		ret.status = SCAP_FAILURE;
		return ret;
 	}

	if (message_type >= dispatchers.size()) {
		ret.error = std::string("No parser registered for message type: ") + std::to_string(message_type);
		ret.status = SCAP_NOT_SUPPORTED;
		return ret;
	}

	parser parser = dispatchers[message_type];
	if(parser == nullptr)
	{
		ret.error = std::string("No parser registered for message type: ") + std::to_string(message_type);
		ret.status = SCAP_NOT_SUPPORTED;
		return ret;
	}

	return parser(proto, proto_size, scap_buf);
}

procfs_result parse_procfs_json(const std::string &input, const std::string &sandbox)
{
	procfs_result res = {0};
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::string err;
	const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());

	bool json_parse = reader->parse(input.c_str(), input.c_str() + input.size(), &root, &err);
	if(!json_parse)
	{
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

	if(!root.isMember("status"))
	{
		return res;
	}
	Json::Value &status = root["status"];

	if(!root.isMember("stat"))
	{
		return res;
	}
	Json::Value &stat = root["stat"];

	// tid
	if(!status.isMember("pid") || !status["pid"].isUInt64())
	{
		return res;
	}
	tinfo.tid = generate_tid_field(status["pid"].asUInt64(), sandbox);

	// pid
	if(!stat.isMember("pgid") || !stat["pgid"].isUInt64())
	{
		return res;
	}
	tinfo.pid = generate_tid_field(stat["pgid"].asUInt64(), sandbox);

	// sid
	if(!stat.isMember("sid") || !stat["sid"].isUInt64())
	{
		return res;
	}
	tinfo.sid = stat["sid"].asUInt64();

	// vpgid
	tinfo.vpgid = stat["pgid"].asUInt64();

	// comm
	if(!status.isMember("comm") || !status["comm"].isString())
	{
		return res;
	}
	strlcpy(tinfo.comm, status["comm"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// exe
	if(!root.isMember("args") || !root["args"].isArray() || !root["args"][0].isString())
	{
		return res;
	}
	strlcpy(tinfo.exe, root["args"][0].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// exepath
	if(!root.isMember("exe") || !root["exe"].isString())
	{
		return res;
	}
	strlcpy(tinfo.exepath, root["exe"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// args
	if(!root.isMember("args") || !root["args"].isArray())
	{
		return res;
	}
	std::string args;
	for(Json::Value::ArrayIndex i = 0; i < root["args"].size(); i++)
	{
		args += root["args"][i].asString();
		args.push_back('\0');
	}
	size_t args_size = args.size() > SCAP_MAX_ARGS_SIZE ? SCAP_MAX_ARGS_SIZE : args.size();
	tinfo.args_len = args_size;
	memcpy(tinfo.args, args.data(), args_size);
	tinfo.args[SCAP_MAX_ARGS_SIZE] = '\0';

	// env
	if(!root.isMember("env") || !root["env"].isArray())
	{
		return res;
	}
	std::string env;
	for(Json::Value::ArrayIndex i = 0; i < root["env"].size(); i++)
	{
		env += root["env"][i].asString();
		env.push_back('\0');
	}
	size_t env_size = env.size() > SCAP_MAX_ENV_SIZE ? SCAP_MAX_ENV_SIZE : env.size();
	tinfo.env_len = env_size;
	memcpy(tinfo.env, env.data(), env_size);
	tinfo.env[SCAP_MAX_ENV_SIZE] = '\0';

	// cwd
	if(!root.isMember("cwd") || !root["cwd"].isString())
	{
		return res;
	}
	strlcpy(tinfo.cwd, root["cwd"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// uid 
	if(!status.isMember("uid") || !status["uid"].isMember("effective") || 
		!status["uid"]["effective"].isUInt64())
	{
		return res;
	}
	tinfo.uid = status["uid"]["effective"].asUInt64();

	// gid
	if(!status.isMember("gid") || !status["gid"].isMember("effective") || 
		!status["gid"]["effective"].isUInt64())
	{
		return res;
	}
	tinfo.gid = status["gid"]["effective"].asUInt64();

	// vtid
	tinfo.vtid = status["pid"].asUInt64();

	// vpid
	tinfo.vpid = status["pgid"].asUInt64();

	// root
	if(!root.isMember("root") || !root["root"].isString())
	{
		return res;
	}
	strlcpy(tinfo.root, root["root"].asCString(), SCAP_MAX_PATH_SIZE + 1);

	// clone_ts
	if(!root.isMember("clone_ts") || !root["clone_ts"].isUInt64())
	{
		return res;
	}
	tinfo.clone_ts = root["clone_ts"].asUInt64();

	// fdinfos 

	// set error so that we can understand that parsing failed here
	res.error = "Error parsing fdlist";

	std::vector<scap_fdinfo> &fds = res.fdinfos;
	if(!root.isMember("fdlist") || !root["fdlist"].isArray())
	{
		return res;
	}
	for(Json::Value::ArrayIndex i = 0; i != root["fdlist"].size(); i++)
	{
		Json::Value &entry = root["fdlist"][i];
		scap_fdinfo fdinfo;
		
		if(!entry.isMember("number") || !entry["number"].isUInt64())
		{
			return res;
		}
		fdinfo.fd = entry["number"].asUInt64();

		if(!entry.isMember("mode") || !entry["mode"].isUInt64())
		{
			return res;
		}
		
		if(!entry.isMember("path") || !entry["path"].isString())
		{
			return res;
		}

		uint64_t mode = entry["mode"].asUInt64();

		if(S_ISREG(mode))
		{
			fdinfo.type = SCAP_FD_FILE_V2;
			strlcpy(fdinfo.info.regularinfo.fname, entry["path"].asCString(), SCAP_MAX_PATH_SIZE);
		}
		else
		{
			continue;
		}

		fds.push_back(fdinfo);
	}

	res.status = SCAP_SUCCESS;
	res.error = "";
	return res;
}

config_result parse_config(std::string config)
{
	config_result res;
	res.socket_path = "";
	res.error = "";
	res.status = SCAP_FAILURE;	

	std::string err;
	Json::Value root;
	Json::CharReaderBuilder builder;
	const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	
	bool json_parse = reader->parse(config.c_str(), config.c_str() + config.size(), &root, &err);
	if(!json_parse)
	{
		res.error = "Could not parse configuration file contents: " + err;
		return res;
	}

	if(!root.isMember("trace_session"))
	{
		res.error = "Could not find trace_session entry in configuration";
		return res;
	}
	Json::Value &trace_session = root["trace_session"];

	if(!trace_session.isMember("sinks") || !trace_session["sinks"].isArray())
	{
		res.error = "Could not find trace_session -> sinks array in configuration";
		return res;
	}

	if(trace_session["sinks"].size() == 0)
	{
		res.error = "trace_session -> sinks array is empty";
		return res;
	}

	// We don't know how to distinguish between sinks in case there is more than one
	// we're taking the first for now but this can be tweaked if necessary.
	Json::Value &sink = trace_session["sinks"][0];

	if(!sink.isMember("config"))
	{
		res.error = "Could not find config in sink item";
		return res;
	}
	Json::Value &sink_config = sink["config"];

	if(!sink_config.isMember("endpoint") || !sink_config["endpoint"].isString())
	{
		res.error = "Could not find endpoint in sink configuration";
		return res;
	}
	
	res.socket_path = sink_config["endpoint"].asString();
	res.status = SCAP_SUCCESS;
	return res;
}

} // namespace parsers
} // namespace scap_gvisor