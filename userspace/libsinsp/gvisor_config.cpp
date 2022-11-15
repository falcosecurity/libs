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

#include <iostream>
#include <vector>
#include <json/json.h>

#include "gvisor_config.h"

namespace gvisor_config
{

static const std::string s_default_socket_path = "/tmp/gvisor.sock";

static const std::vector<std::string> s_gvisor_points = {
	"container/start",
	"syscall/openat/enter",
	"syscall/openat/exit",
	"syscall/execve/enter",
	"syscall/execve/exit",
	"syscall/socket/enter",
	"syscall/socket/exit",
	"syscall/connect/enter",
	"syscall/connect/exit",
	"syscall/chdir/enter",
	"syscall/chdir/exit",
	"syscall/setuid/enter",
	"syscall/setuid/exit",
	"syscall/setgid/enter",
	"syscall/setgid/exit",
	"syscall/setresuid/enter",
	"syscall/setresuid/exit",
	"syscall/setresgid/enter",
	"syscall/setresgid/exit",
	"syscall/chroot/enter",
	"syscall/chroot/exit",
	"syscall/dup/enter",
	"syscall/dup/exit",
	"syscall/dup2/enter",
	"syscall/dup2/exit",
	"syscall/dup3/enter",
	"syscall/dup3/exit",
	"syscall/prlimit64/enter",
	"syscall/prlimit64/exit",
	"syscall/signalfd/enter",
	"syscall/signalfd/exit",
	"syscall/signalfd4/enter",
	"syscall/signalfd4/exit",
	"sentry/clone",
	"sentry/task_exit",
	"sentry/execve",
	"syscall/pipe/enter",
	"syscall/pipe/exit",
	"syscall/fcntl/enter",
	"syscall/fcntl/exit",
	"syscall/bind/enter",
	"syscall/bind/exit",
	"syscall/accept/enter",
	"syscall/accept/exit"
};

static const std::vector<std::string> s_context_fields = {
	"cwd",
	"credentials",
	"container_id",
	"thread_id",
	"task_start_time",
	"time",
};

constexpr unsigned int max_retries = 3;

std::string generate(std::string socket_path)
{
	Json::Value context_fields;
	for(const auto &field : s_context_fields)
	{
		context_fields.append(field);
	}

	Json::Value points;
	for(const auto &point_name : s_gvisor_points)
	{
		Json::Value point;
		point["name"] = point_name;
		point["context_fields"] = context_fields;
		points.append(point);
	}

	Json::Value sinks, sink;
	sink["name"] = "remote";
	sink["config"]["endpoint"] = socket_path.empty() ? s_default_socket_path : socket_path;
	sink["config"]["retries"] = max_retries;
	sink["ignore_setup_error"] = true;
	sinks.append(sink);

	Json::Value trace_session;
	trace_session["name"] = "Default";
	trace_session["ignore_missing"] = true;
	trace_session["points"] = points;
	trace_session["sinks"] = sinks;

	Json::Value root;
	root["trace_session"] = trace_session;

	return root.toStyledString();
}

} // namespace gvisor_config
