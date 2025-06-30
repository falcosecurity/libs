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

TEST_F(sinsp_with_test_input, LSEEK_success) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 55;
	constexpr int64_t fd = 54;
	constexpr uint64_t offset = 1234;
	constexpr uint8_t whence = 100;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_LSEEK_X,
	                                      4,
	                                      return_value,
	                                      fd,
	                                      offset,
	                                      whence);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), fd);
	// Check that the offset value is as expected.
	ASSERT_EQ(evt->get_param_by_name("offset")->as<uint64_t>(), offset);
	// Check that the whence value is as expected.
	ASSERT_EQ(evt->get_param_by_name("whence")->as<uint8_t>(), whence);
}

TEST_F(sinsp_with_test_input, LSEEK_failure) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = -1;
	constexpr int64_t fd = -1;
	constexpr uint64_t offset = 0;
	constexpr uint8_t whence = 0;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_LSEEK_X,
	                                      4,
	                                      return_value,
	                                      fd,
	                                      offset,
	                                      whence);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), fd);
	// Check that the offset value is as expected.
	ASSERT_EQ(evt->get_param_by_name("offset")->as<uint64_t>(), offset);
	// Check that the whence value is as expected.
	ASSERT_EQ(evt->get_param_by_name("whence")->as<uint8_t>(), whence);
}
