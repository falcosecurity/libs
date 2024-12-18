
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

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, LISTEN_parse_unix_socket) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 55;
	int64_t socket_fd = 77;
	int32_t backlog = 5;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SOCKET_LISTEN_X,
	                                      3,
	                                      return_value,
	                                      socket_fd,
	                                      backlog);

	// we want to check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// we want to check that `get_fd_info()->m_fd` returns the correct socket fd.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), socket_fd);

	// we want to check that the socket backlog is as expected.
	ASSERT_EQ(evt->get_param_by_name("backlog")->as<int32_t>(), backlog);
}
