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

TEST_F(sinsp_with_test_input, MOUNT_parse) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 139631788478464;
	const std::string dev{"/dev"};
	const std::string dir{"/dir"};
	const std::string fstype{"fstype"};
	constexpr uint32_t flags = 1;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_MOUNT_X,
	                                      5,
	                                      return_value,
	                                      dev.c_str(),
	                                      dir.c_str(),
	                                      fstype.c_str(),
	                                      flags);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the dev value is as expected.
	ASSERT_EQ(evt->get_param_by_name("dev")->as<std::string_view>(), dev);
	// Check that the dir value is as expected.
	ASSERT_EQ(evt->get_param_by_name("dir")->as<std::string_view>(), dir);
	// Check that the type value is as expected.
	ASSERT_EQ(evt->get_param_by_name("type")->as<std::string_view>(), fstype);
	// Check that the flags value is as expected.
	ASSERT_EQ(evt->get_param_by_name("flags")->as<uint32_t>(), flags);
}
