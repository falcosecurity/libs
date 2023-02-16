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
#include <sinsp.h>
#include "../test_utils.h"

/* Please note this set must be kept in sync if we update the sinsp internal state set
 * otherwise some of the following checks will fail.
 */
libsinsp::events::set<ppm_tp_code> expected_sinsp_state_tp_set = {
	SYS_ENTER,
	SYS_EXIT,
	SCHED_PROC_EXIT,
	SCHED_SWITCH,
	SCHED_PROC_FORK,
	SCHED_PROC_EXEC
};

/* This test asserts that `sinsp_state_tp_set` correctly retrieves
 * the `libsinsp` state tracepoint set.
 */
TEST(interesting_tracepoints, enforce_sinsp_state_tracepoints_basic)
{
	auto final_tracepoints_set = libsinsp::events::sinsp_state_tp_set();

	ASSERT_TRUE(expected_sinsp_state_tp_set.equals(final_tracepoints_set));
}

TEST(interesting_tracepoints, enforce_sinsp_state_tracepoints_with_additions)
{
	libsinsp::events::set<ppm_tp_code> additional_tracepoints;
	auto tracepoint_matching_set = expected_sinsp_state_tp_set;

	additional_tracepoints.insert(PAGE_FAULT_USER);
	tracepoint_matching_set.insert(PAGE_FAULT_USER);

	additional_tracepoints.insert(SIGNAL_DELIVER);
	tracepoint_matching_set.insert(SIGNAL_DELIVER);

	auto sinsp_state_tp = libsinsp::events::sinsp_state_tp_set();
	auto final_tracepoints_set = additional_tracepoints.merge(sinsp_state_tp);

	ASSERT_TRUE(final_tracepoints_set.equals(tracepoint_matching_set));
}

/* This test asserts that `get_all_tp` correctly retrieves all the available tracepoints
 */
TEST(interesting_tracepoints, get_all_tp)
{
	auto tp_set = libsinsp::events::all_tp_set();

	/* Assert that all the tracepoints are taken */
	ASSERT_EQ(tp_set.size(), TP_VAL_MAX);
}

/* This test asserts that `get_tp_names` correctly retrieves all the tracepoints names
 */
TEST(interesting_tracepoints, get_tp_names)
{
	std::set<std::string> tracepoints_names_matching_set;
	libsinsp::events::set<ppm_tp_code> tp_set;

	tp_set.insert(SYS_ENTER);
	tracepoints_names_matching_set.insert("sys_enter");

	tp_set.insert(SCHED_PROC_FORK);
	tracepoints_names_matching_set.insert("sched_process_fork");

	auto tracepoints_names_final_set = libsinsp::events::tp_set_to_names(tp_set);

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(tracepoints_names_final_set.size(), tracepoints_names_matching_set.size());

	auto ordered_tracepoints_names_final_set = test_utils::unordered_set_to_ordered(tracepoints_names_final_set);

	auto final = ordered_tracepoints_names_final_set.begin();
	auto matching = tracepoints_names_matching_set.begin();

	for(; final != ordered_tracepoints_names_final_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}
