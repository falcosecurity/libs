
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

TEST_F(sinsp_with_test_input, SEMCTL_parse) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 55;
	constexpr int32_t semid = 50;
	constexpr int32_t semnum = 51;
	constexpr uint16_t cmd = 52;
	constexpr int32_t val = 53;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_SEMCTL_X,
	                                      5,
	                                      return_value,
	                                      semid,
	                                      semnum,
	                                      cmd,
	                                      val);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the semid value is as expected.
	ASSERT_EQ(evt->get_param_by_name("semid")->as<int32_t>(), semid);
	// Check that the semnum value is as expected.
	ASSERT_EQ(evt->get_param_by_name("semnum")->as<int32_t>(), semnum);
	// Check that the cmd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("cmd")->as<uint16_t>(), cmd);
	// Check that the val value is as expected.
	ASSERT_EQ(evt->get_param_by_name("val")->as<int32_t>(), val);
}
