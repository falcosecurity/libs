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

#include <vector>
#include <functional>

#include <libscap/engine/gvisor/gvisor.h>
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

namespace scap_gvisor {

namespace parsers {

struct event_parser {
	std::function<parse_result(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf)> parse_msg;
	std::function<std::string(scap_const_sized_buffer proto)> parse_container_id;
};

template<class T>
static std::string container_id_from_context(scap_const_sized_buffer proto)
{
	T gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size))
	{
		return "";
	}

    auto& context_data = gvisor_evt.context_data();
    return context_data.container_id();
}

static std::string container_id_from_container_start(scap_const_sized_buffer proto)
{
	gvisor::container::Start gvisor_evt;
	if(!gvisor_evt.ParseFromArray(proto.buf, proto.size))
	{
		return "";
	}

	return gvisor_evt.id();
}

static parse_result parse_container_start(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_sentry_clone(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_sentry_task_exit(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_generic_syscall(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_open(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_close(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_read(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_connect(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_execve(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_socket(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_chdir(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_setid(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_setresid(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_prlimit64(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_pipe(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_fcntl(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_dup(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_signalfd(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_chroot(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_eventfd(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_clone(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_bind(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_accept(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_timerfd_create(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_fork(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_inotify_init(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_socketpair(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);
static parse_result parse_write(uint32_t id, scap_const_sized_buffer proto, scap_sized_buffer scap_buf);

// List of parsers. Indexes are based on MessageType enum values
std::vector<event_parser> dispatchers = {
	{nullptr, nullptr}, 				// MESSAGE_UNKNOWN
	{parse_container_start, container_id_from_container_start},
	{parse_sentry_clone, container_id_from_context<gvisor::sentry::CloneInfo>},
	{nullptr, nullptr},                                // MESSAGE_SENTRY_EXEC
	{nullptr, nullptr},                                // MESSAGE_SENTRY_EXIT_NOTIFY_PARENT
	{parse_sentry_task_exit, container_id_from_context<gvisor::sentry::TaskExit>},
	{parse_generic_syscall, container_id_from_context<gvisor::syscall::Syscall>},
	{parse_open, container_id_from_context<gvisor::syscall::Open>},
	{parse_close, container_id_from_context<gvisor::syscall::Close>},
	{parse_read, container_id_from_context<gvisor::syscall::Read>},
	{parse_connect, container_id_from_context<gvisor::syscall::Connect>},
	{parse_execve, container_id_from_context<gvisor::syscall::Execve>},
	{parse_socket, container_id_from_context<gvisor::syscall::Socket>},
	{parse_chdir, container_id_from_context<gvisor::syscall::Chdir>},
	{parse_setid, container_id_from_context<gvisor::syscall::Setid>},
	{parse_setresid, container_id_from_context<gvisor::syscall::Setresid>},
	{parse_prlimit64, container_id_from_context<gvisor::syscall::Prlimit>},
  	{parse_pipe, container_id_from_context<gvisor::syscall::Pipe>},
  	{parse_fcntl, container_id_from_context<gvisor::syscall::Fcntl>},
  	{parse_dup, container_id_from_context<gvisor::syscall::Dup>},
   	{parse_signalfd, container_id_from_context<gvisor::syscall::Signalfd>},
  	{parse_chroot, container_id_from_context<gvisor::syscall::Chroot>},
  	{parse_eventfd, container_id_from_context<gvisor::syscall::Eventfd>},
  	{parse_clone, container_id_from_context<gvisor::syscall::Clone>},
  	{parse_bind, container_id_from_context<gvisor::syscall::Bind>},
  	{parse_accept, container_id_from_context<gvisor::syscall::Accept>},
  	{parse_timerfd_create, container_id_from_context<gvisor::syscall::TimerfdCreate>},
	{nullptr, nullptr},				// MESSAGE_SYSCALL_TIMERFD_SETTIME
	{nullptr, nullptr},				// MESSAGE_SYSCALL_TIMERFD_GETTIME
  	{parse_fork, container_id_from_context<gvisor::syscall::Fork>},
  	{parse_inotify_init, container_id_from_context<gvisor::syscall::Eventfd>},
	{nullptr, nullptr},				// MESSAGE_SYSCALL_INOTIFY_ADD_WATCH
	{nullptr, nullptr},				// MESSAGE_SYSCALL_INOTIFY_RM_WATCH
	{parse_socketpair, container_id_from_context<gvisor::syscall::SocketPair>},
	{parse_write, container_id_from_context<gvisor::syscall::Write>}
};

} // namespace parsers

} // namespace scap_gvisor
