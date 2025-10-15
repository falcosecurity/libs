
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

TEST_F(sinsp_with_test_input, PREADV_success) {
	add_default_init_thread();
	open_inspector();

	// Notice: we need to generate a socket event in order to let the parser logic populate the
	// socket fdinfo. This is different from what we currently do with SEND_X event, in which case
	// the parser is able to create the fdinfo from the SEND_X event itself, even if the SOCKET_X
	// event has been dropped.
	const sinsp_test_input::open_params opn_params = {};  // Use default values.
	auto evt = generate_open_x_event(opn_params);

	int64_t return_value = 55;
	const std::string data{"hello"};
	const uint32_t data_size = data.size();
	const uint64_t pos = 50;

	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SYSCALL_PREADV_X,
	                           5,
	                           return_value,
	                           data_size,
	                           scap_const_sized_buffer{data.c_str(), data_size},
	                           opn_params.fd,
	                           pos);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the size value is as expected.
	ASSERT_EQ(evt->get_param_by_name("size")->as<uint32_t>(), data_size);
	// Check that `get_param_value_str` returns the correct read data.
	ASSERT_EQ(evt->get_param_value_str("data"), data);
	// Check that fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), opn_params.fd);
	// Check that the pos value is as expected.
	ASSERT_EQ(evt->get_param_by_name("pos")->as<uint64_t>(), pos);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(opn_params.fd);
	ASSERT_TRUE(fdinfo);
}
