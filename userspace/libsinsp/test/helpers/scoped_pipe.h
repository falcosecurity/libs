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

#include <memory>

namespace test_helpers
{

class scoped_file_descriptor;

/**
 * A scoped_pipe wraps the pipe() system call and exposes two scoped file
 * descriptors corresponding to the read- and write-ends of the pipe.
 */
class scoped_pipe
{
public:
	/**
	 * Creates a new pipe and initializes this scoped_pipe with its
	 * file descriptors.
	 *
	 * @throws std::runtime_error if the pipe system call fails.
	 */
	scoped_pipe();

	/** Returns a reference to the read-end of the pipe. */
	scoped_file_descriptor& read_end();

	/** Returns a reference to the write-end of the pipe. */
	scoped_file_descriptor& write_end();

	/** Close both the read- and write-ends of the pipe. */
	void close();

private:
	std::unique_ptr<scoped_file_descriptor> m_read_end;
	std::unique_ptr<scoped_file_descriptor> m_write_end;
};

}  // namespace test_helpers
