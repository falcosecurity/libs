
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

TEST_F(sinsp_with_test_input, COPY_FILE_RANGE_success) {
	add_default_init_thread();
	open_inspector();

	// Notice: we need to generate open events in order to let the parser logic populate the
	// socket fdinfos.
	constexpr int64_t fd_in = 4;
	constexpr int64_t fd_out = 5;
	sinsp_test_input::open_params open_params = {};  // Use default values.
	open_params.fd = fd_in;
	auto evt = generate_open_x_event(open_params);
	open_params.fd = fd_out;
	evt = generate_open_x_event(open_params);

	constexpr int64_t return_value = 10;
	constexpr uint64_t off_out = 53;
	constexpr uint64_t off_in = 63;
	constexpr uint64_t len = 10;
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SYSCALL_COPY_FILE_RANGE_X,
	                           6,
	                           return_value,
	                           fd_out,
	                           off_out,
	                           fd_in,
	                           off_in,
	                           len);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the fdout value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fdout")->as<int64_t>(), fd_out);
	// Check that the offout value is as expected.
	ASSERT_EQ(evt->get_param_by_name("offout")->as<uint64_t>(), off_out);
	// Check that the fdin value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fdin")->as<int64_t>(), fd_in);
	// Check that the offin value is as expected.
	ASSERT_EQ(evt->get_param_by_name("offin")->as<uint64_t>(), off_in);
	// Check that the len value is as expected.
	ASSERT_EQ(evt->get_param_by_name("len")->as<uint64_t>(), len);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(fd_out);
	ASSERT_TRUE(fdinfo);
}
