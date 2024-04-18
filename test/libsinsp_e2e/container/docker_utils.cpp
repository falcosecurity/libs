// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include "docker_utils.h"

#include <gtest/gtest.h>

#include <stdio.h>
#include <stdlib.h>

#include <string>

using namespace std;

bool dutils_check_docker()
{
	if (system("service docker status > /dev/null 2>&1") != 0)
	{
		if (system("systemctl status docker > /dev/null 2>&1") != 0)
		{
			printf("Docker not running, skipping test\n");
			return false;
		}
	}

	// We depend on docker versions >= 1.10
	if (system("docker --version | grep -qE \"Docker version 1.[56789].\"") == 0)
	{
		printf("Docker version too old, skipping test\n");
		return false;
	}

	return true;
}

void dutils_create_tag(const char* tag, const char* image)
{
	std::string tag_cmd = string("docker tag ") + image + " " + tag + " > /dev/null 2>&1";
	std::string remove_tag_cmd = string("(docker rmi ") + tag + " || true) > /dev/null 2>&1";

	EXPECT_EQ(system(remove_tag_cmd.c_str()), 0);
	EXPECT_EQ(system(tag_cmd.c_str()), 0);
}

void dutils_kill_container_if_exists(const char* name)
{
	std::string kill_cmd = string("(docker kill --signal SIGKILL ") + name + " || true) 2>&1";
	std::string rm_cmd = string("(docker rm -fv ") + name + " || true) 2>&1";

	system(kill_cmd.c_str());
	system(rm_cmd.c_str());
}

void dutils_kill_container(const char* name)
{
	std::string kill_cmd =
	    string("(docker kill --signal SIGKILL ") + name + " || true) > /dev/null 2>&1";
	std::string rm_cmd = string("(docker rm -fv ") + name + " || true) > /dev/null 2>&1";

	EXPECT_EQ(system(kill_cmd.c_str()), 0);
	EXPECT_EQ(system(rm_cmd.c_str()), 0);
}

void dutils_kill_image(const char* image)
{
	std::string rmi_cmd = string("(docker rmi ") + image + " || true) > /dev/null 2>&1";

	EXPECT_EQ(system(rmi_cmd.c_str()), 0);
}

docker_helper::docker_helper(const std::string& dockerfile_path, const std::string& tagname,
							 const std::vector<std::string>& labels, const std::string& build_extra_args,
							 const std::string& run_extra_args, const bool& verbose):
	m_dockerfile_path(dockerfile_path),
	m_tagname(tagname),
	m_labels(labels),
	m_build_extra_args(build_extra_args),
	m_run_extra_args(run_extra_args),
	m_verbose(verbose) {}

int docker_helper::build_image() {
    std::string label_options;
    for (const auto& label : m_labels) {
        label_options += " --label " + label;
    }
    std::string command = "docker build " + m_build_extra_args + label_options + " -t " + m_tagname + " -f " + m_dockerfile_path + " .";
	if(!m_verbose)
	{
		command += "  > /dev/null 2>&1";

	}
    return system(command.c_str());
}

int docker_helper::run_container(const std::string& container_name, const std::string& cmd, const std::string& additional_options) {
    std::string command = "docker run " + additional_options + " " + m_run_extra_args + " --name " + container_name + " " + m_tagname + " " + cmd;
	if(!m_verbose)
	{
		command += "  > /dev/null 2>&1";

	}
    return system(command.c_str());
}
