// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>
#include "test_utils.h"


// test user tracking with setuid
TEST_F(sinsp_with_test_input, setuid_setgid)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt;

	int64_t errno_success = 0, errno_failure = -1;

	// set a new user ID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_E, 1, 500);
	// check that upon entry we have the default user ID
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "0");

	// check that the user ID is updated if the call is successful
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_X, 1, errno_success);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "500");

	// set a new group ID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_E, 1, 600);
	// check that upon entry we have the default group ID
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "0");

	// check that the group ID is updated if the call is successful
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_X, 1, errno_success);
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");

	// check that the new user ID and group ID are retained
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_E, 1, 0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "500");
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");

	// check that the user ID is not updated after an unsuccessful setuid call
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_X, 1, errno_failure);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "500");

	// same for group ID
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_X, 1, errno_failure);
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");
}


// test user tracking with setresuid
TEST_F(sinsp_with_test_input, setresuid_setresgid)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt;

	int64_t errno_success = 0, errno_failure = -1;

	// set a new user ID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETRESUID_E, 3, 600, 600, 600);
	// check that upon entry we have the default user ID
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "0");

	// check that the user ID is updated if the call is successful. The expected user is the EUID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETRESUID_X, 1, errno_success);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "600");

	// check that the new user ID is retained
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETRESUID_E, 3, 0, 0, 0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "600");

	// check that the user ID is not updated after an unsuccessful setuid call
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETRESUID_X, 1, errno_failure);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "600");

	// set a new group ID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETRESGID_E, 3, 600, 600, 600);
	// check that upon entry we have the default user ID
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "0");

	// check that the group ID is updated if the call is successful. The expected user is the EGID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETRESGID_X, 1, errno_success);
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");
}
