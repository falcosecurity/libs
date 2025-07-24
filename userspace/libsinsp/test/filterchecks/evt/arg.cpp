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

#include <helpers/threads_helpers.h>
#include <filter_eval_test.h>

const auto arg_eq_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_eq_NA",
         "evt.arg.flags = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_UINT64_eq_NA",
         "evt.arg.cap_inheritable = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_ABSTIME_eq_NA",
         "evt.arg.exe_ino_ctime = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_UID_eq_NA",
         "evt.arg.uid = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_eq_NA",
         "evt.arg.trusted_exepath = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_PID_eq_NA",
         "evt.arg.pgid = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_GID_eq_NA",
         "evt.arg.gid = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
});

const auto arg_tolower_eq_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_eq_NA",
         "tolower(evt.arg.flags) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_UINT64_eq_NA",
         "tolower(evt.arg.cap_inheritable) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_ABSTIME_eq_NA",
         "tolower(evt.arg.exe_ino_ctime) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_UID_eq_NA",
         "tolower(evt.arg.uid) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_eq_NA",
         "tolower(evt.arg.trusted_exepath) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_PID_eq_NA",
         "tolower(evt.arg.pgid) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_GID_eq_NA",
         "tolower(evt.arg.gid) = <na>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
});

INSTANTIATE_TEST_CASE_P(arg_eq_op,
                        filter_eval_test,
                        arg_eq_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(arg_tolower_eq_op,
                        filter_eval_test,
                        arg_tolower_eq_op_test_cases,
                        filter_eval_test::test_case_name_gen);

TEST_F(sinsp_with_test_input, EVT_FILTER_arg_empty_params) {
	add_default_init_thread();

	open_inspector();

	// Use execve event type as it contains a multitude of parameters (specifically, in the range
	// 18-29) that can be set to empty by the scap-converter.
	const auto evt = generate_execve_exit_event_with_empty_params(1, "/bin/test-exe", "test-exe");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.flags"), "<NA>");            // PT_FLAGS32
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.cap_inheritable"), "<NA>");  // PT_UINT64
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.exe_ino_ctime"), "<NA>");    // PT_ABSTIME
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.uid"), "<NA>");              // PT_UID
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.trusted_exepath"), "<NA>");  // PT_FSPATH
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.pgid"), "<NA>");             // PT_PID
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.gid"), "<NA>");              // PT_GID
}
