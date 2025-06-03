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

TEST_F(sinsp_with_test_input, MKDIR_parse_mkdir_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 0;
	std::string pathname = "/hello";
	uint32_t mode = 0755;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_MKDIR_2_X,
	                                      3,
	                                      return_value,
	                                      pathname.c_str(),
	                                      mode);

	// we want to check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// we want to check that the pathname is as expected.
	ASSERT_EQ(evt->get_param_by_name("path")->as<std::string>(), pathname);

	// we want to check that the mode is as expected.
	ASSERT_EQ(evt->get_param_by_name("mode")->as<uint32_t>(), mode);
}
