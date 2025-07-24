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

#include <filter_eval_test.h>

TEST_P(filter_eval_test, execve_empty_params) {
	const auto tc = GetParam();

	add_default_init_thread();

	open_inspector();

	// Use execve event type as it contains a multitude of parameters (specifically, in the range
	// 18-29) that can be set to empty by the scap-converter.
	const auto evt = generate_execve_exit_event_with_empty_params(1, "/bin/test-exe", "test-exe");

	const auto filter_str = tc.filter_str.c_str();

	switch(tc.expected_result) {
	case filter_eval_test_case::EXPECT_TRUE: {
		EXPECT_TRUE(eval_filter(evt, filter_str));
		break;
	}
	case filter_eval_test_case::EXPECT_FALSE: {
		EXPECT_FALSE(eval_filter(evt, filter_str));
		break;
	}
	case filter_eval_test_case::EXPECT_THROW: {
		EXPECT_ANY_THROW(eval_filter(evt, filter_str));
		break;
	}
	default:
		ASSERT(false);
		break;
	}
}

/* On windows, the previous TEST_P definition would generate a synthetic failing test.
 * The correct solution, would be adding GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST here, but
 * this macro generates an error for some reason. Just add a dummy test case to fix the issue. */
INSTANTIATE_TEST_CASE_P(dummy,
                        filter_eval_test,
                        testing::ValuesIn(std::vector<filter_eval_test_case>{
                                {"dummy", "proc.pid exists", filter_eval_test_case::EXPECT_TRUE}}),
                        filter_eval_test::test_case_name_gen);
