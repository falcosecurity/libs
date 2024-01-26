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

#include "subprocess.h"

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

subprocess::subprocess(const std::string& command, const std::vector<std::string>& arguments)
    : m_pid(-1)
{
    if (pipe(m_in_pipe)  == -1 || pipe(m_out_pipe) == -1)
    {
        throw std::system_error(errno, std::system_category());
    }

    pid_t child_pid = fork();

    if (child_pid == -1)
    {
        std::cerr << "Failed to fork." << std::endl;
    }
    else if (child_pid == 0)
    {
        // child process
        dup2(m_in_pipe[0],  STDIN_FILENO);
        dup2(m_out_pipe[1], STDOUT_FILENO);

        close(m_in_pipe[0]);
        close(m_out_pipe[1]);
        if(m_out_pipe[0] != -1)
            close(m_out_pipe[0]);

        std::vector<char*> args;
        args.push_back(const_cast<char*>(command.c_str()));
        for (const auto& arg : arguments) {
            args.push_back(const_cast<char*>(arg.c_str()));
        }
        args.push_back(nullptr);

        execvp(command.c_str(), args.data());
        std::cerr << "Failed to execute the process." << std::endl;
        exit(EXIT_FAILURE);
    }
    else // Parent process
    {
        close(m_in_pipe[0]);
        close(m_out_pipe[1]);

        m_pid = child_pid;

        m_in_filebuf = new __gnu_cxx::stdio_filebuf<char>(m_in_pipe[1], std::ios_base::out, 1);
        m_in_stream  = new std::ostream(m_in_filebuf);

        if (m_out_pipe[0] != -1)
        {
            m_out_filebuf = new __gnu_cxx::stdio_filebuf<char>(m_out_pipe[0], std::ios_base::in, 1);
            m_out_stream  = new std::istream(m_out_filebuf);
        }

    }

}

subprocess::~subprocess()
{
    delete m_in_filebuf;
    delete m_out_filebuf;
    delete m_in_stream;
    delete m_out_stream;
}

void subprocess::wait_for_start()
{
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(m_out_pipe[0], &read_set);

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    int result = select(m_out_pipe[0] + 1, &read_set, nullptr, nullptr, &timeout);

    switch(result)
    {
        case -1:
            perror("select");
            break;
        case 0:
            std::cerr << "Timeout waiting for process to start." << std::endl;
            break;
        default:
            if (!FD_ISSET(m_out_pipe[0], &read_set)) {
                std::cerr << "Unexpected error during select." << std::endl;
            }
            break;
    }

}

pid_t subprocess::get_pid()
{
    return m_pid;
}

std::ostream& subprocess::in()
{
    return *m_in_stream;
}

std::string subprocess::out()
{
    std::string buf;
    std::getline(*m_out_stream, buf);
    return buf;
}

int subprocess::wait()
{
    int status;
    waitpid(get_pid(), &status, 0);
    return status;
}
