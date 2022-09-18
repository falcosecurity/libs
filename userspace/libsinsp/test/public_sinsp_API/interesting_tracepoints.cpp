/*
Copyright (C) 2022 The Falco Authors.

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
#include <sinsp.h>
#include "../test_utils.h"

std::set<uint32_t> ordered_sinsp_state_tracepoint_set{
	SYS_ENTER,
	SYS_EXIT,
	SCHED_PROC_EXIT,
	SCHED_SWITCH,
	SCHED_PROC_FORK,
	SCHED_PROC_EXEC
};

/* This test asserts that `enforce_sinsp_state_tracepoints` correctly retrieves
 * the `libsinsp` state tracepoint set.
 */
TEST(InterestingTracepoints, enforce_sinsp_state_tracepoints_basic)
{
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::set<uint32_t> ordered_final_tracepoints_set = test_utils::unorderedToOrdered(inspector->enforce_sinsp_state_tracepoints());

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(ordered_sinsp_state_tracepoint_set.size(), ordered_final_tracepoints_set.size());

	auto final = ordered_final_tracepoints_set.begin();
	auto matching = ordered_sinsp_state_tracepoint_set.begin();

	for(; final != ordered_final_tracepoints_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}

TEST(InterestingTracepoints, enforce_sinsp_state_tracepoints_with_additions)
{
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::unordered_set<uint32_t> additional_tracepoints;
	auto ordered_tracepoint_matching_set = ordered_sinsp_state_tracepoint_set;

	additional_tracepoints.insert(PAGE_FAULT_USER);
	ordered_tracepoint_matching_set.insert(PAGE_FAULT_USER);

	additional_tracepoints.insert(SIGNAL_DELIVER);
	ordered_tracepoint_matching_set.insert(SIGNAL_DELIVER);

	std::set<uint32_t> ordered_final_tracepoints_set = test_utils::unorderedToOrdered(inspector->enforce_sinsp_state_tracepoints(additional_tracepoints));

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(ordered_tracepoint_matching_set.size(), ordered_final_tracepoints_set.size());

	auto final = ordered_final_tracepoints_set.begin();
	auto matching = ordered_tracepoint_matching_set.begin();

	for(; final != ordered_final_tracepoints_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}

/* This test asserts that `get_all_tp` correctly retrieves all the available tracepoints
 */
TEST(InterestingSyscalls, get_all_tp)
{
	std::unique_ptr<sinsp> inspector(new sinsp());
	auto tp_set = inspector->get_all_tp();

	/* Assert that all the tracepoints are taken */
	ASSERT_EQ(tp_set.size(), TP_VAL_MAX);
}

/* This test asserts that `get_tracepoint_names` correctly retrieves all the tracepoints names
 */
TEST(InterestingSyscalls, get_tracepoint_names)
{
	std::unique_ptr<sinsp> inspector(new sinsp());
	std::set<std::string> orderd_tracepoints_names_matching_set;
	std::unordered_set<uint32_t> tp_set;

	tp_set.insert(SYS_ENTER);
	orderd_tracepoints_names_matching_set.insert("sys_enter");

	tp_set.insert(SCHED_PROC_FORK);
	orderd_tracepoints_names_matching_set.insert("sched_process_fork");

	auto orderd_tracepoints_names_final_set = test_utils::unorderedToOrdered(inspector->get_tracepoint_names(tp_set));

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(orderd_tracepoints_names_matching_set.size(), orderd_tracepoints_names_final_set.size());

	auto final = orderd_tracepoints_names_final_set.begin();
	auto matching = orderd_tracepoints_names_matching_set.begin();

	for(; final != orderd_tracepoints_names_final_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}
