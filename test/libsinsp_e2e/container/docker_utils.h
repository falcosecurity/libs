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

#pragma once

#include <string>
#include <vector>

bool dutils_check_docker();
void dutils_create_tag(const char* tag, const char* image);
void dutils_kill_container(const char* name);
void dutils_kill_container_if_exists(const char* name);
void dutils_kill_image(const char* image);

class docker_helper {
    public:
        docker_helper(const std::string& dockerfile_path, const std::string& tagname,
                                     const std::vector<std::string>& labels, const std::string& build_extra_args,
                                     const std::string& run_extra_args, const bool& verbose = false);
        int build_image();
        int run_container(const std::string& containerName, const std::string& cmd, const std::string& additional_options = "--rm --network=none");

    private:
        std::string m_dockerfile_path;
        std::string m_tagname;
        std::vector<std::string> m_labels;
        std::string m_build_extra_args;
        std::string m_run_extra_args;
        bool m_verbose;

};
