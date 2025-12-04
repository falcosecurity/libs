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

#include <helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, EVT_FILTER_is_open_create) {
	add_default_init_thread();

	open_inspector();

	std::string path = "/home/file.txt";
	int64_t fd = 3;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      fd,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDWR | PPM_O_CREAT | PPM_O_F_CREATED,
	                                      (uint32_t)0,
	                                      (uint32_t)5,
	                                      (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_open_create"), "true");
	ASSERT_TRUE(evt->get_fd_info());

	ASSERT_EQ(evt->get_fd_info()->m_openflags, PPM_O_RDWR | PPM_O_CREAT | PPM_O_F_CREATED);
}

TEST_F(sinsp_with_test_input, EVT_FILTER_is_lower_layer) {
	add_default_init_thread();

	open_inspector();

	std::string path = "/home/file.txt";
	int64_t fd = 3;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      fd,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDONLY | PPM_FD_LOWER_LAYER,
	                                      (uint32_t)0,
	                                      (uint32_t)5,
	                                      (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_lower_layer"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.is_upper_layer"), "false");
	ASSERT_TRUE(evt->get_fd_info());

	ASSERT_EQ(evt->get_fd_info()->is_overlay_lower(), true);
	ASSERT_EQ(evt->get_fd_info()->is_overlay_upper(), false);
}

TEST_F(sinsp_with_test_input, EVT_FILTER_is_upper_layer) {
	add_default_init_thread();

	open_inspector();

	std::string path = "/home/file.txt";
	int64_t fd = 3;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      fd,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDONLY | PPM_FD_UPPER_LAYER,
	                                      (uint32_t)0,
	                                      (uint32_t)5,
	                                      (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_lower_layer"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.is_upper_layer"), "true");
	ASSERT_TRUE(evt->get_fd_info());

	ASSERT_EQ(evt->get_fd_info()->is_overlay_lower(), false);
	ASSERT_EQ(evt->get_fd_info()->is_overlay_upper(), true);
}

TEST_F(sinsp_with_test_input, EVT_FILTER_cmd_str) {
	add_default_init_thread();

	open_inspector();

	uint64_t fd = 1;

	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_BPF_2_X,
	                                      2,
	                                      fd,
	                                      PPM_BPF_PROG_LOAD);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.cmd"), "BPF_PROG_LOAD");
}

TEST_F(sinsp_with_test_input, EVT_FILTER_check_evt_arg_uid) {
	add_default_init_thread();
	open_inspector();

	uint64_t res = 0;
	uint32_t user_id = 5;
	std::string container_id = "";
	auto evt =
	        add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_SETUID_X, 2, res, user_id);
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "setuid");

	// The rawarg provides the field directly from the table.
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.uid"), std::to_string(user_id));

	// we are adding a user on the host so the `pid` parameter is not considered
	ASSERT_TRUE(m_inspector.m_usergroup_manager
	                    ->add_user(container_id, 0, user_id, 6, "test", "/test", "/bin/test"));

	// Now we should have the necessary info
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.uid"), "test");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), "test");
	ASSERT_EQ(get_field_as_string(evt, "evt.args"), "res=0 uid=5(test)");

	// We remove the user, and the fields should be empty again
	m_inspector.m_usergroup_manager->rm_user(container_id, user_id);
	ASSERT_FALSE(m_inspector.m_usergroup_manager->get_user(container_id, user_id));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.uid"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "evt.args"), "res=0 uid=5(<NA>)");
}

TEST_F(sinsp_with_test_input, EVT_FILTER_execve_evt_arg_filename_comm_trusted_exepath) {
	add_default_init_thread();
	open_inspector();

	const std::string filename{"/usr/../usr/./bin/python3"};
	const std::string comm{"python3"};
	const std::string trusted_exepath{"/usr/bin/python3"};
	const auto evt = generate_execve_enter_and_exit_event(0,
	                                                      INIT_TID,
	                                                      INIT_TID,
	                                                      INIT_PID,
	                                                      INIT_PTID,
	                                                      filename,
	                                                      comm,
	                                                      trusted_exepath);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.filename"), filename.c_str());
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.comm"), comm.c_str());
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.trusted_exepath"), trusted_exepath.c_str());
}

TEST_F(sinsp_with_test_input, EVT_FILTER_thread_proc_info) {
	DEFAULT_TREE

	// Random event on the init process (main thread) the field should be 0. This field are used
	// only when the event is `PPME_PROCINFO_E`
	auto evt = generate_random_event(INIT_TID);
	ASSERT_EQ(get_field_as_string(evt, "evt.count.procinfo"), "0");
	ASSERT_EQ(get_field_as_string(evt, "evt.count.threadinfo"), "0");

	// Same for a secondary thread
	evt = generate_random_event(p1_t2_tid);
	ASSERT_EQ(get_field_as_string(evt, "evt.count.procinfo"), "0");
	ASSERT_EQ(get_field_as_string(evt, "evt.count.threadinfo"), "0");

	// Now both field shoul be 1
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_PROCINFO_E,
	                           2,
	                           (uint64_t)0,
	                           (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "evt.count.procinfo"), "1");
	ASSERT_EQ(get_field_as_string(evt, "evt.count.threadinfo"), "1");

	// Since this is not a main thread only `evt.count.threadinfo` should be 1
	evt = add_event_advance_ts(increasing_ts(),
	                           p1_t2_tid,
	                           PPME_PROCINFO_E,
	                           2,
	                           (uint64_t)0,
	                           (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "evt.count.procinfo"), "0");
	ASSERT_EQ(get_field_as_string(evt, "evt.count.threadinfo"), "1");
}

TEST_F(sinsp_with_test_input, EVT_FILTER_data_buffer_str) {
	add_default_init_thread();

	open_inspector();

	uint64_t fd = 0;
	uint8_t read_buf[] = {'g', 'i', 'g', 'i'};
	uint32_t read_size = sizeof(read_buf);

	auto evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_READ_E, 2, fd, read_size);

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_READ_X,
	                           4,
	                           (int64_t)0,
	                           scap_const_sized_buffer{read_buf, read_size},
	                           fd,
	                           read_size);

	EXPECT_TRUE(eval_filter(evt, "evt.arg.data = gigi"));

	// changing the output format must not affect the filter
	m_inspector.set_buffer_format(sinsp_evt::PF_BASE64);
	EXPECT_TRUE(eval_filter(evt, "evt.arg.data = gigi"));
}
