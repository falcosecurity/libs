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

#include "driver/ppm_events_public.h"
#include <helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, SETRESGID_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 0;
	uint32_t rgid = (uint32_t)-1;
	uint32_t egid = 1000;
	uint32_t sgid = (uint32_t)-1;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_SETRESGID_X,
	                                      4,
	                                      return_value,
	                                      rgid,
	                                      egid,
	                                      sgid);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the rgid value is as expected.
	ASSERT_EQ(evt->get_param_by_name("rgid")->as<uint32_t>(), rgid);

	// Check that the egid value is as expected.
	ASSERT_EQ(evt->get_param_by_name("egid")->as<uint32_t>(), egid);

	// Check that the sgid value is as expected.
	ASSERT_EQ(evt->get_param_by_name("sgid")->as<uint32_t>(), sgid);
}
