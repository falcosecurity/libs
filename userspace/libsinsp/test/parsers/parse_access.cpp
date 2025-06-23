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
#include <sys/mount.h>

TEST_F(sinsp_with_test_input, ACCESS_parse) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 139631788478464;
	const std::string name{"/hello"};
	constexpr uint32_t mode = 1;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_ACCESS_X,
	                                      3,
	                                      return_value,
	                                      name.c_str(),
	                                      mode);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the name value is as expected.
	ASSERT_EQ(evt->get_param_by_name("name")->as<std::string_view>(), name);
	// Check that the mode value is as expected.
	ASSERT_EQ(evt->get_param_by_name("mode")->as<uint32_t>(), mode);
}
