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

#include <iostream>
#include <vector>
#include <json/json.h>

#include <libsinsp/gvisor_config.h>

namespace gvisor_config
{

struct gvisor_point_info_t {
	std::string m_name;
	std::vector<std::string> m_context_fields;
	std::vector<std::string> m_optional_fields;
};

static const std::string s_default_socket_path = "/tmp/gvisor.sock";

static const std::vector<gvisor_point_info_t> s_gvisor_points = {
	{"container/start",
         {"time", "thread_id", "container_id", "task_start_time", "credentials", "cwd"},
	 {"env"}},
	{"sentry/clone",
	 {"time", "thread_id", "container_id", "task_start_time",
	  "group_id", "credentials", "cwd", "process_name"},
	 {}},
	{"sentry/task_exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/open/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/open/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/openat/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/openat/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/creat/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/creat/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/close/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/close/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/read/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/read/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pread64/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pread64/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/readv/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/readv/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/preadv/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/preadv/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/connect/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/connect/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/execve/enter",
         {"time", "thread_id", "container_id", "cwd"},
	 {}},
	{"syscall/execve/exit",
         {"time", "thread_id", "container_id", "group_id", "credentials", "cwd"},
	 {"envv"}},
	{"syscall/execveat/enter",
         {"time", "thread_id", "container_id", "cwd"},
	 {}},
	{"syscall/execveat/exit",
         {"time", "thread_id", "container_id", "group_id", "credentials", "cwd"},
	 {"envv"}},
	{"syscall/socket/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/socket/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/chdir/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/chdir/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/fchdir/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/fchdir/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setuid/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setuid/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setgid/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setgid/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setsid/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setsid/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setresuid/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setresuid/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setresgid/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/setresgid/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/prlimit64/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/prlimit64/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pipe/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pipe/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pipe2/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pipe2/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/fcntl/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/fcntl/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/dup/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/dup/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/dup2/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/dup2/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/dup3/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/dup3/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/signalfd/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/signalfd/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/signalfd4/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/signalfd4/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/chroot/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/chroot/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/eventfd/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/eventfd/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/eventfd2/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/eventfd2/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/clone/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/clone/exit",
         {"time", "thread_id", "container_id", "task_start_time",
          "group_id", "credentials", "cwd", "process_name"},
	 {}},
	{"syscall/bind/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/bind/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/accept/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/accept/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/accept4/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/accept4/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/timerfd_create/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/timerfd_create/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/fork/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/fork/exit",
         {"time", "thread_id", "container_id", "task_start_time",
          "group_id", "credentials", "cwd", "process_name"},
	 {}},
	{"syscall/vfork/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/vfork/exit",
         {"time", "thread_id", "container_id", "task_start_time",
          "group_id", "credentials", "cwd", "process_name"},
	 {}},
	{"syscall/inotify_init/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/inotify_init/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/inotify_init1/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/inotify_init1/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/socketpair/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/socketpair/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/write/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/write/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pwrite64/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pwrite64/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/writev/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/writev/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pwritev/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/pwritev/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/sysno/9/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/sysno/9/exit",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/sysno/11/enter",
         {"time", "thread_id", "container_id"},
	 {}},
	{"syscall/sysno/11/exit",
         {"time", "thread_id", "container_id"},
	 {}}
};

constexpr unsigned int max_retries = 3;

std::string generate(std::string socket_path)
{
	Json::Value jpoints;
	for(const auto &point_info : s_gvisor_points)
	{
		Json::Value jpoint;
		jpoint["name"] = point_info.m_name;
		if (!point_info.m_context_fields.empty())
		{
			Json::Value jcontext_fields;
			for(const auto &context_field : point_info.m_context_fields)
			{
				jcontext_fields.append(context_field);
			}

			jpoint["context_fields"] = jcontext_fields;
		}

		if (!point_info.m_optional_fields.empty())
		{
			Json::Value joptional_fields;
			for(const auto &optional_field : point_info.m_optional_fields)
			{
				joptional_fields.append(optional_field);
			}

			jpoint["optional_fields"] = joptional_fields;
		}

		jpoints.append(jpoint);
	}

	Json::Value jsinks, jsink;
	jsink["name"] = "remote";
	jsink["config"]["endpoint"] = socket_path.empty() ? s_default_socket_path : socket_path;
	jsink["config"]["retries"] = max_retries;
	jsink["ignore_setup_error"] = true;
	jsinks.append(jsink);

	Json::Value jtrace_session;
	jtrace_session["name"] = "Default";
	jtrace_session["ignore_missing"] = true;
	jtrace_session["points"] = jpoints;
	jtrace_session["sinks"] = jsinks;

	Json::Value jroot;
	jroot["trace_session"] = jtrace_session;

	return jroot.toStyledString();
}

} // namespace gvisor_config
