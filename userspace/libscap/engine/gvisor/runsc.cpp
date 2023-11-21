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

#include <unistd.h>
#include <sys/wait.h>
#include <ext/stdio_filebuf.h>
#include <iostream>
#include <fstream>
#include <string>

#include <libscap/engine/gvisor/gvisor.h>

namespace scap_gvisor {

namespace runsc {

result runsc(char *argv[])
{
	result res;
	int pipefds[2];

	int ret = pipe(pipefds);
	if(ret)
	{
		return res;
	}

	pid_t pid = vfork();
	if(pid > 0)
	{
		int status;

		close(pipefds[1]);
		wait(&status);
		if(!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		{
			res.error = status;
			return res;
		}

		__gnu_cxx::stdio_filebuf<char> filebuf(pipefds[0], std::ios::in);
		std::string line;
		std::istream is(&filebuf);

		while(std::getline(is, line))
		{
			res.output.emplace_back(std::string(line));
		}
	}
	else
	{
		close(pipefds[0]);
		dup2(pipefds[1], STDOUT_FILENO);
		execvp("runsc", argv);
		exit(1);
	}

	return res;
}

result version()
{
	const char *argv[] = {
		"runsc",
		"--version",
		NULL
	};

	return runsc((char **)argv);
}

result list(const std::string &root_path)
{
	result res;
	std::vector<std::string> running_sandboxes;

	const char *argv[] = {
		"runsc",
		"--root",
		root_path.c_str(),
		"list",
		NULL
	};

	res = runsc((char **)argv);
	if(res.error)
	{
		return res;
	}

	for(const auto &line : res.output)
	{
		if(line.find("running") != std::string::npos)
		{
			std::string sandbox = line.substr(0, line.find_first_of(" ", 0));
			running_sandboxes.emplace_back(sandbox);
		}
	}

	res.output = running_sandboxes;
	return res;
}

result trace_create(const std::string &root_path, const std::string &trace_session_path, const std::string &sandbox_id, bool force)
{
	const char *argv[] = {
		"runsc",
		"--root",
		root_path.c_str(),
		"trace",
		"create",
		force ? "--force" : "",
		"--config",
		trace_session_path.c_str(),
		sandbox_id.c_str(),
		NULL
	};

	return runsc((char **)argv);
}

result trace_delete(const std::string &root_path, const std::string &session_name, const std::string &sandbox_id)
{
	const char *argv[] = {
		"runsc",
		"--root",
		root_path.c_str(),
		"trace",
		"delete",
		"--name",
		session_name.c_str(),
		sandbox_id.c_str(),
		NULL
	};

	return runsc((char **)argv);
}

result trace_procfs(const std::string &root_path, const std::string &sandbox_id)
{
	const char *argv[] = {
		"runsc",
		"--root",
		root_path.c_str(),
		"trace",
		"procfs",
		sandbox_id.c_str(),
		NULL,
	};

	return runsc((char **)argv);
}

} // namespace runsc

} // namespace scap_gvisor
