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

#include <vector>
#include <functional>

#include "gvisor.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"

namespace scap_gvisor {

namespace parsers {

typedef std::function<parse_result(const char *proto, size_t proto_size, scap_sized_buffer scap_buf)> parser;

static parse_result parse_container_start(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_execve(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_clone(const gvisor::syscall::Syscall &gvisor_evt, scap_sized_buffer scap_buf, bool is_fork);
static parse_result parse_sentry_clone(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_read(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_connect(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_socket(const char *proto, size_t proto_size, scap_sized_buffer event_buf);
static parse_result parse_generic_syscall(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_open(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_chdir(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_setresid(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_setid(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_chroot(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_dup(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_task_exit(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_prlimit64(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_signalfd(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_pipe(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_fcntl(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_bind(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_accept(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);
static parse_result parse_eventfd(const char *proto, size_t proto_size, scap_sized_buffer scap_buf);

// List of parsers. Indexes are based on MessageType enum values
std::vector<parser> dispatchers = {
	nullptr, 				// MESSAGE_UNKNOWN
	parse_container_start,
	parse_sentry_clone, 
	nullptr, 				// MESSAGE_SENTRY_EXEC
	nullptr, 				// MESSAGE_SENTRY_EXIT_NOTIFY_PARENT
	parse_task_exit,
	parse_generic_syscall,
	parse_open,
	nullptr, 				// MESSAGE_SYSCALL_CLOSE
	parse_read,
	parse_connect,
	parse_execve,
	parse_socket,
	parse_chdir,
	parse_setid,
	parse_setresid,
	parse_prlimit64,
  	parse_pipe,
  	parse_fcntl,
  	parse_dup,
   	parse_signalfd,
  	parse_chroot,
  	parse_eventfd,
  	nullptr, 				// MESSAGE_SYSCALL_CLONE
  	parse_bind,
  	parse_accept,
};

} // namespace parsers

} // namespace scap_gvisor