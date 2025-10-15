
// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.
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
#include <vector>

TEST_F(sinsp_with_test_input, CLOSE_success) {
	add_default_init_thread();
	open_inspector();

	const sinsp_test_input::socket_params sock_params;

	// Verify the thread doesn't have any information associated with the fd.
	const auto tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true);
	ASSERT_NE(tinfo, nullptr);
	ASSERT_FALSE(tinfo->get_fd(sock_params.fd));

	const auto socket_evt = generate_socket_exit_event(sock_params, INIT_TID);

	// Verify that the event fd information are present and the file descriptor is coherent with the
	// created socket event. Moreover, verify that an entry for the file descriptor has been created
	// in the thread fd table.
	const auto fdinfo = socket_evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	const auto socket_fd = fdinfo->m_fd;
	ASSERT_EQ(socket_fd, sock_params.fd);
	ASSERT_TRUE(tinfo->get_fd(socket_fd));

	// Generate the close exit event.
	constexpr int64_t return_value = 0;
	const auto close_evt = add_event_advance_ts(increasing_ts(),
	                                            INIT_TID,
	                                            PPME_SYSCALL_CLOSE_X,
	                                            2,
	                                            return_value,
	                                            socket_fd);

	// Check that the returned value is as expected.
	ASSERT_EQ(close_evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the fd value is as expected.
	ASSERT_EQ(close_evt->get_param_by_name("fd")->as<int64_t>(), socket_fd);

	// Check that the exit event is associated with some thread information and the thread's fd
	// table has an entry for the file descriptor.
	// Notice: the fd information are still present, as their removal is delayed to the next
	// sinsp::next() invocation.
	const auto close_tinfo = close_evt->get_thread_info();
	ASSERT_TRUE(close_tinfo);
	ASSERT_TRUE(close_tinfo->get_fd(socket_fd));

	// Generate a dummy event to get sinsp::next() being invoked and do the scheduled fd removal.
	uint16_t dummy_syscall_id = 0;
	add_event_advance_ts(increasing_ts(),
	                     INIT_TID,
	                     PPME_GENERIC_X,
	                     2,
	                     dummy_syscall_id,
	                     dummy_syscall_id);

	// Verify that the fd removal was performed.
	ASSERT_FALSE(tinfo->get_fd(socket_fd));
}
