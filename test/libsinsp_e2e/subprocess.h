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

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ext/stdio_filebuf.h>

class subprocess {
    public:

        subprocess(std::string command, std::vector<std::string> arguments, bool start_now=true);
        ~subprocess();

        void wait_for_start();
        int wait();

        pid_t get_pid();

        std::ostream& in();
        std::string out();

        void start();

    private:
        std::string m_command;
        std::vector<std::string> m_args;
        pid_t m_pid;
        int m_in_pipe[2];
        int m_out_pipe[2];

        std::ostream* m_in_stream;
        std::istream* m_out_stream;

        __gnu_cxx::stdio_filebuf<char>* m_in_filebuf;
        __gnu_cxx::stdio_filebuf<char>* m_out_filebuf;
};
