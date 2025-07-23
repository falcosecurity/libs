// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <cstdint>
#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>
#include <test_utils.h>

TEST_F(sinsp_with_test_input, suppress_comm) {
	//
	// init (pid 1)
	//   └── sh (pid 17)
	//

	add_default_init_thread();

	m_inspector.clear_suppress_events_comm();
	m_inspector.suppress_events_comm("sh");

	open_inspector();

	uint64_t pid = 17;
	generate_clone_x_event(pid, INIT_TID, INIT_TID, INIT_TID);

	const char* file_to_run = "/bin/sh";

	add_event_advance_ts(increasing_ts(), pid, PPME_SYSCALL_EXECVE_19_E, 1, file_to_run);

	// Whenever we try to add an event to sinsp_with_test_input, if
	// the event is suppressed we get an exception.
	EXPECT_ANY_THROW(generate_execve_exit_event_with_default_params(pid, file_to_run, "sh"));

	const auto& thread_manager = m_inspector.m_thread_manager;

	EXPECT_NE(thread_manager->get_thread_ref(pid), nullptr);

	add_event_advance_ts(increasing_ts(), pid, PPME_PROCEXIT_1_E, 0);

	// dummy event to actually delete the thread from the threadtable.
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_RENAME_E, 0);

	EXPECT_EQ(thread_manager->get_thread_ref(pid), nullptr);

	scap_stats st;
	m_inspector.get_capture_stats(&st);
	EXPECT_EQ(st.n_suppressed, 1);
	EXPECT_EQ(st.n_tids_suppressed, 0);
}

TEST_F(sinsp_with_test_input, suppress_comm_execve) {
	//
	// init (pid 1)
	//   └── sh (pid 17)
	//
	// then sh calls execve
	//
	// init (pid 1)
	//   └── /bin/test-exe (pid 17)
	//

	add_default_init_thread();

	m_inspector.clear_suppress_events_comm();
	m_inspector.suppress_events_comm("sh");

	open_inspector();

	uint64_t pid = 17;
	generate_clone_x_event(pid, INIT_TID, INIT_TID, INIT_TID);

	const char* file_to_run = "/bin/sh";
	add_event_advance_ts(increasing_ts(), pid, PPME_SYSCALL_EXECVE_19_E, 1, file_to_run);

	// Whenever we try to add an event to sinsp_with_test_input, if
	// the event is suppressed we get an exception.
	EXPECT_ANY_THROW(generate_execve_exit_event_with_default_params(pid, file_to_run, "sh"));

	EXPECT_ANY_THROW(add_event_advance_ts(increasing_ts(),
	                                      pid,
	                                      PPME_SYSCALL_EXECVE_19_E,
	                                      1,
	                                      "/bin/test-exe"));
	EXPECT_ANY_THROW(
	        generate_execve_exit_event_with_default_params(pid, "/bin/test-exe", "test-exe"));

	const auto& thread_manager = m_inspector.m_thread_manager;

	EXPECT_NE(thread_manager->get_thread_ref(pid), nullptr);

	add_event_advance_ts(increasing_ts(), pid, PPME_PROCEXIT_1_E, 0);

	// dummy event to actually delete the thread from the threadtable.
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_RENAME_E, 0);

	EXPECT_EQ(thread_manager->get_thread_ref(pid), nullptr);

	scap_stats st;
	m_inspector.get_capture_stats(&st);
	EXPECT_EQ(st.n_suppressed, 3);
	EXPECT_EQ(st.n_tids_suppressed, 0);
}
