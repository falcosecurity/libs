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

#include <libsinsp/container_info.h>
#include <gtest/gtest.h>
#include <tuple>
#include <vector>

class sinsp_container_lookup_test : public ::testing::TestWithParam<std::tuple<short, short, std::vector<short>>>
{
};

TEST(sinsp_container_lookup_test, default_values)
{
	sinsp_container_lookup lookup;
	lookup.set_status(sinsp_container_lookup::state::STARTED);
	EXPECT_TRUE(lookup.first_attempt());
	// Loop until retry attempt are exausted.
	int actual_retries = 0;
	while(lookup.should_retry() && actual_retries < 4)
	{
		lookup.attempt_increment();
		actual_retries++;
	}
	ASSERT_EQ(3, actual_retries);
	ASSERT_EQ(3, lookup.retry_no());
	ASSERT_EQ(500, lookup.delay());
}

TEST_P(sinsp_container_lookup_test, delays_match)
{
	short max_retry;
	short max_delay_ms;
	std::vector<short> expected_delays;
	std::tie(max_retry, max_delay_ms, expected_delays) = GetParam();
	auto lookup = sinsp_container_lookup(max_retry, max_delay_ms);
	lookup.set_status(sinsp_container_lookup::state::STARTED);
	for(size_t i = 0; i < expected_delays.size(); i++)
	{
		ASSERT_EQ(i == 0, lookup.first_attempt());
		lookup.attempt_increment();
		ASSERT_EQ(i < (expected_delays.size() - 1), lookup.should_retry());
		ASSERT_EQ(expected_delays[i], lookup.delay());
	}
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
INSTANTIATE_TEST_CASE_P(sinsp_container_lookup,
			 sinsp_container_lookup_test,
			 ::testing::Values(
				 std::tuple<short, short, std::vector<short>>{3, 500, {125, 250, 500}},
				 std::tuple<short, short, std::vector<short>>{5, 1000, {125, 250, 500, 1000, 1000}},
				 std::tuple<short, short, std::vector<short>>{2, 1, {1, 1}}));
#pragma GCC diagnostic pop
