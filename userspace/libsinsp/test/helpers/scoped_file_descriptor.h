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

namespace test_helpers
{

/**
 * Wraps a file descriptor for the lifetime of the object, and closes the
 * file descriptor (if not already closed) when destroyed.
 */
class scoped_file_descriptor
{
public:
	scoped_file_descriptor(int fd);
	~scoped_file_descriptor();

	int get_fd() const;
	bool is_valid() const;
	void close();

private:
	int m_fd;
	bool m_closed;
};

}  // namespace test_helpers
