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

#if defined(__linux__)

#include "scoped_file_descriptor.h"

#include <unistd.h>

using namespace test_helpers;

scoped_file_descriptor::scoped_file_descriptor(const int fd): m_fd(fd), m_closed(false) {}

scoped_file_descriptor::~scoped_file_descriptor() {
	close();
}

int scoped_file_descriptor::get_fd() const {
	return m_fd;
}

bool scoped_file_descriptor::is_valid() const {
	return m_fd >= 0;
}

void scoped_file_descriptor::close() {
	if(is_valid() && !m_closed) {
		::close(m_fd);
		m_fd = -1;
	}
	m_closed = true;
}
#endif
