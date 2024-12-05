
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

TEST_F(sinsp_with_test_input, parse_write_success) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_open_x_event();
	ASSERT_TRUE(evt->get_fd_info());

	std::string data = "hello";
	uint32_t size = data.size();
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SYSCALL_WRITE_X,
	                           4,
	                           (int64_t)size,
	                           scap_const_sized_buffer{data.c_str(), size},
	                           sinsp_test_input::open_params::default_fd,
	                           size);

	ASSERT_TRUE(evt->get_fd_info());
	assert_fd_fields(evt,
	                 sinsp_test_input::fd_info_fields{
	                         .fd_num = sinsp_test_input::open_params::default_fd,
	                         .fd_name = sinsp_test_input::open_params::default_path,
	                         .fd_name_raw = sinsp_test_input::open_params::default_path,
	                         .fd_directory = sinsp_test_input::open_params::default_directory,
	                         .fd_filename = sinsp_test_input::open_params::default_filename});

	assert_return_value(evt, size);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), data);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.data"), data);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"),
	          std::string("<f>") + sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd"),
	          std::to_string(sinsp_test_input::open_params::default_fd));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"), std::to_string(size));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.size"), std::to_string(size));
}

TEST_F(sinsp_with_test_input, parse_write_failure) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_open_x_event();

	std::string data = "hello";
	uint32_t size = data.size();
	int64_t errno_code = -3;
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SYSCALL_WRITE_X,
	                           4,
	                           errno_code,
	                           scap_const_sized_buffer{data.c_str(), size},
	                           sinsp_test_input::open_params::default_fd,
	                           size);

	// Check we have the correct fd info associated with the event
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_fd, sinsp_test_input::open_params::default_fd);

	// Assert return value filterchecks
	assert_return_value(evt, errno_code);
}
