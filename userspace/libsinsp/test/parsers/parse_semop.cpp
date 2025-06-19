
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

TEST_F(sinsp_with_test_input, SEMOP_parse) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 55;
	constexpr uint32_t nsops = 20;
	constexpr uint16_t sem_num_0 = 21;
	constexpr int16_t sem_op_0 = 22;
	constexpr uint16_t sem_flg_0 = 23;
	constexpr uint16_t sem_num_1 = 24;
	constexpr int16_t sem_op_1 = 25;
	constexpr uint16_t sem_flg_1 = 26;
	constexpr int32_t semid = 27;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_SEMOP_X,
	                                      9,
	                                      return_value,
	                                      nsops,
	                                      sem_num_0,
	                                      sem_op_0,
	                                      sem_flg_0,
	                                      sem_num_1,
	                                      sem_op_1,
	                                      sem_flg_1,
	                                      semid);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the nsops value is as expected.
	ASSERT_EQ(evt->get_param_by_name("nsops")->as<uint32_t>(), nsops);
	// Check that the sem_num_0 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sem_num_0")->as<uint16_t>(), sem_num_0);
	// Check that the sem_op_0 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sem_op_0")->as<int16_t>(), sem_op_0);
	// Check that the sem_flg_0 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sem_flg_0")->as<uint16_t>(), sem_flg_0);
	// Check that the sem_num_1 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sem_num_1")->as<uint16_t>(), sem_num_1);
	// Check that the sem_op_1 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sem_op_1")->as<int16_t>(), sem_op_1);
	// Check that the sem_flg_1 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sem_flg_1")->as<uint16_t>(), sem_flg_1);
	// Check that the semid value is as expected.
	ASSERT_EQ(evt->get_param_by_name("semid")->as<int32_t>(), semid);
}
