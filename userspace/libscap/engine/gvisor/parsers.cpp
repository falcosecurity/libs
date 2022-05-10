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
#include <netinet/in.h>
#include <linux/un.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <functional>
#include <unordered_map>
#include <sstream>
#include <string>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "userspace_flag_helpers.h"

#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

namespace scap_gvisor {
namespace parsers {

typedef std::function<parse_result(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)> Callback;

// In gVisor there's no concept of tid and tgid but only vtid and vtgid.
// However, to fit into sinsp we do need values for tid and tgid.
static uint64_t generate_tid_field(uint64_t tid, std::string container_id_hex)
{
	std::string container_id_64 = container_id_hex.length() > 16 ? container_id_hex.substr(0, 15) : container_id_hex;

	uint64_t tid_field = stoull(container_id_64, nullptr, 16);
	tid_field = tid_field ^ tid;
	return tid_field;
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
	struct parse_result ret;
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
		0, // child tid (0 in the child)
		gvisor_evt.args(0).c_str(), // actual exe is not currently sent
		scap_const_sized_buffer{args.data(), args.size()},
		tid_field, // tid
		tgid_field, // pid
		1,
		"", // cwd
		75000, // fdlimit
		0, // pgft_maj
		0, // pgft_min
		0, // vm_size
		0, // vm_rss
		0, // vm_swap
		gvisor_evt.args(0).c_str(), // comm
		scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
		0, // clone_flags
		context_data.credentials().real_uid(), // uid
		context_data.credentials().real_gid(), // gid
		1, // vtid
		1); // vpid

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
		0, // res
		gvisor_evt.args(0).c_str(), // actual exe missing
		scap_const_sized_buffer{args.data(), args.size()},
		tid_field, // tid
		tgid_field, // pid
		-1, // ptid is only needed if we don't have the corresponding clone event
		cwd.c_str(), // cwd
		75000, // fdlimit ?
		0, // pgft_maj
		0, // pgft_min
		0, // vm_size
		0, // vm_rss
		0, // vm_swap
		gvisor_evt.args(0).c_str(), // args.c_str() // comm
		scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
		scap_const_sized_buffer{env.data(), env.size()}, // env
		0, // tty
		0, // pgid
		0, // loginuid
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

static struct parse_result parse_execve(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	struct parse_result ret;
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
			-1, // ptid is only needed if we don't have the corresponding clone event
			cwd.c_str(), // cwd
			75000, // fdlimit
			0, // pgft_maj
			0, // pgft_min
			0, // vm_size
			0, // vm_rss
			0, // vm_swap
			comm.c_str(), // comm
			scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
			scap_const_sized_buffer{env.data(), env.size()}, // env
			0, // tty
			0, // pgid
			0, // loginuid
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

static struct parse_result parse_clone(const gvisor::syscall::Syscall &gvisor_evt, scap_sized_buffer scap_buf, bool is_fork)
{
	struct parse_result ret;
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
			0, // ptid
			context_data.cwd().c_str(), // cwd
			16,
			0,
			0,
			0,
			0,
			0,
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

static struct parse_result parse_sentry_clone(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	struct parse_result ret;
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
		16, 0, 0, 0, 0, 0,
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

static struct parse_result parse_read(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
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
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_READ_X, 3,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{gvisor_evt.data().data(),
								gvisor_evt.data().size()});
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

static struct parse_result parse_connect(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
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
		char targetbuf[17 + SCAP_MAX_PATH_SIZE];
		uint32_t size = 0;

		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();
		uint8_t sock_family;

		// TODO: source side of the connection
		switch(addr->sa_family)
		{
			case AF_INET: 
			{
				sockaddr_in *inet_addr = (sockaddr_in *)addr;
				uint16_t dport = ntohs(inet_addr->sin_port);
				sock_family = socket_family_to_scap(inet_addr->sin_family);
				memcpy(targetbuf, &sock_family, sizeof(uint8_t));
				memset(targetbuf + 1, 0, sizeof(uint32_t));
				memset(targetbuf + 5, 0, sizeof(uint16_t));
				memcpy(targetbuf + 7, &inet_addr->sin_addr.s_addr, sizeof(uint32_t));
				memcpy(targetbuf + 11, &dport, sizeof(uint16_t));

				size = sizeof(uint8_t) + (sizeof(uint32_t) + sizeof(uint16_t)) * 2;
				break;
			}
			case AF_INET6:
			{
				sockaddr_in6 *inet6_addr = (sockaddr_in6 *)addr;
				uint16_t dport = ntohs(inet6_addr->sin6_port);
				sock_family = socket_family_to_scap(inet6_addr->sin6_family);
				memcpy(targetbuf, &sock_family, sizeof(uint8_t));
				memset(targetbuf + 1, 0, 2 * sizeof(uint64_t)); //saddr
				memset(targetbuf + 17, 0, sizeof(uint16_t)); //sport
				memcpy(targetbuf + 19, &inet6_addr->sin6_addr, 2 * sizeof(uint64_t));
				memcpy(targetbuf + 35, &dport, sizeof(uint16_t));
				size = sizeof(uint8_t) + (2 * sizeof(uint64_t) + sizeof(uint16_t)) * 2;
				break;
			}
			case AF_UNIX:
			{
				sockaddr_un *unix_addr = (sockaddr_un *)addr;
				sock_family = socket_family_to_scap(unix_addr->sun_family);
				memcpy(targetbuf, &sock_family, sizeof(uint8_t));
				memset(targetbuf + 1, 0, sizeof(uint64_t)); // TODO: understand how to fill this 
				memset(targetbuf + 1 + 8, 0, sizeof(uint64_t));
				memcpy(targetbuf + 1 + 8 + 8, &unix_addr->sun_path, 108);
				memset(targetbuf + 1 + 8 + 8 + UNIX_PATH_MAX - 1, 0, sizeof(uint8_t));
				size = sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + UNIX_PATH_MAX;
				break;
			}
			default:
			ret.status = SCAP_TIMEOUT;
			return ret;
		}

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_CONNECT_X, 2,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{targetbuf, size});
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

static struct parse_result parse_socket(const char *proto, size_t proto_size, scap_sized_buffer event_buf)
{
	struct parse_result ret = {0};
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

static struct parse_result parse_generic_syscall(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
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
		case 56:
			return parse_clone(gvisor_evt, scap_buf, true);
		case 57:
			return parse_clone(gvisor_evt, scap_buf, false);
		default:
			ret.error = std::string("Unhandled syscall: ") + std::to_string(gvisor_evt.sysno());
			ret.status = SCAP_TIMEOUT;
			return ret;
	}
	
	ret.status = SCAP_TIMEOUT;
	return ret;
}


static struct parse_result parse_open(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)
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

// List of parsers. Indexes are based on MessageType enum values
std::vector<Callback> dispatchers = {
	nullptr, 				// MESSAGE_UNKNOWN
	parse_container_start,
	parse_sentry_clone, 
	nullptr, 				// MESSAGE_SENTRY_EXEC
	nullptr, 				// MESSAGE_SENTRY_EXIT_NOTIFY_PARENT
	nullptr, 				// MESSAGE_SENTRY_TASK_EXIT
	parse_generic_syscall,
	parse_open,
	nullptr, 				// MESSAGE_SYSCALL_CLOSE
	parse_read,
	parse_connect,
	parse_execve,
	parse_socket,
};

struct parse_result parse_gvisor_proto(struct scap_const_sized_buffer gvisor_buf, struct scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
	const char *buf = static_cast<const char*>(gvisor_buf.buf);

	const header *hdr = reinterpret_cast<const header *>(buf);
	if(hdr->header_size > gvisor_buf.size)
	{
		ret.error = std::string("Header size (") + std::to_string(hdr->header_size) + ") is larger than message " + std::to_string(gvisor_buf.size);
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	const char *proto = &buf[hdr->header_size];
	ssize_t proto_size = gvisor_buf.size - hdr->header_size;

	size_t message_type = hdr->message_type;
	if (message_type == 0 || message_type >= dispatchers.size()) {
		ret.error = std::string("Invalid message type " + std::to_string(message_type));
		ret.status = SCAP_TIMEOUT;
		return ret;
 	}

	Callback cb = dispatchers[message_type];
	if(cb == nullptr)
	{
		ret.error = std::string("No callback registered for message type: ") + std::to_string(message_type);
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	return cb(proto, proto_size, scap_buf);
}

} // namespace parsers
} // namespace scap_gvisor