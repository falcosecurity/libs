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

#include "scoped_pipe.h"

#include "scoped_file_descriptor.h"

#include <unistd.h>

#include <cstring>
#include <exception>
#include <sstream>

using namespace test_helpers;

scoped_pipe::scoped_pipe() : m_read_end(), m_write_end()
{
	int fds[2] = {};

	if (pipe(fds) < 0)
	{
		std::stringstream out;

		out << "scoped_pipe: Failed to create pipe, error: " << strerror(errno);

		throw std::runtime_error(out.str());
	}

	m_read_end.reset(new scoped_file_descriptor(fds[0]));
	m_write_end.reset(new scoped_file_descriptor(fds[1]));
}

scoped_file_descriptor& scoped_pipe::read_end()
{
	return *m_read_end.get();
}

scoped_file_descriptor& scoped_pipe::write_end()
{
	return *m_write_end.get();
}

void scoped_pipe::close()
{
	m_read_end->close();
	m_write_end->close();
}
