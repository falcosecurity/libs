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

#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, USER_FILTER_extract_from_existent_user_entry) {
	add_default_init_thread();

	auto& thread = m_threads.front();
	thread.uid = 1000;
	thread.gid = 1000;
	thread.loginuid = 0;

	open_inspector();

	m_inspector.m_usergroup_manager->add_user("", INIT_TID, 1000, 1000, "foo", "/foo", "/bin/bash");

	std::string path = "/home/file.txt";

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                (int64_t)3,
	                                path.c_str(),
	                                (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                (uint32_t)0,
	                                (uint32_t)0,
	                                (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "1000");
	ASSERT_EQ(get_field_as_string(evt, "user.loginuid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "user.name"), "foo");
	ASSERT_EQ(get_field_as_string(evt, "user.homedir"), "/foo");
	ASSERT_EQ(get_field_as_string(evt, "user.shell"), "/bin/bash");
	// Loginname default at root for 0 uid without an user entry in user group manager.
	ASSERT_EQ(get_field_as_string(evt, "user.loginname"), "root");

	// Now remove the user
	m_inspector.m_usergroup_manager->rm_user("", 1000);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "1000");
	ASSERT_EQ(get_field_as_string(evt, "user.loginuid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "user.name"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "user.homedir"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "user.shell"), "<NA>");
	// Loginname default at root for 0 uid without an user entry in user group manager.
	ASSERT_EQ(get_field_as_string(evt, "user.loginname"), "root");

	// Add back a new user
	m_inspector.m_usergroup_manager->add_user("", INIT_TID, 1000, 1000, "bar", "/bar", "/bin/bash");
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "1000");
	ASSERT_EQ(get_field_as_string(evt, "user.loginuid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "user.name"), "bar");
	ASSERT_EQ(get_field_as_string(evt, "user.homedir"), "/bar");
	ASSERT_EQ(get_field_as_string(evt, "user.shell"), "/bin/bash");
	// Loginname default at root for 0 uid without an user entry in user group manager.
	ASSERT_EQ(get_field_as_string(evt, "user.loginname"), "root");
}

TEST_F(sinsp_with_test_input, USER_FILTER_extract_from_default_user_entry) {
	add_default_init_thread();

	open_inspector();

	// The entry gets created when the inspector is opened and its threadtable created.
	// Since default thread uid is 0, the entry is created with "root" name and "/root" homedir.
	ASSERT_NE(m_inspector.m_usergroup_manager->get_user("", 0), nullptr);

	// remove the loaded "root" user to test defaults for uid 0
	m_inspector.m_usergroup_manager->rm_user("", 0);
	ASSERT_EQ(m_inspector.m_usergroup_manager->get_user("", 0), nullptr);

	std::string path = "/home/file.txt";

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                (int64_t)3,
	                                path.c_str(),
	                                (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                (uint32_t)0,
	                                (uint32_t)0,
	                                (uint64_t)0);

	// For non-existent entries whose uid is 0, "root" and "/root"
	// are automatically filled by threadinfo::get_user() method.
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "user.name"), "root");
	ASSERT_EQ(get_field_as_string(evt, "user.homedir"), "/root");
	ASSERT_EQ(get_field_as_string(evt, "user.shell"), "<NA>");
}

TEST_F(sinsp_with_test_input, USER_FILTER_extract_from_existent_user_entry_without_metadata) {
	add_default_init_thread();

	open_inspector();

	// Creating the entry in the user group manager will override
	// the one created by the inspector threadtable initial load.
	// Since we set "" metadatas, we don't expect any metadata in the output fields.
	m_inspector.m_usergroup_manager->add_user("", INIT_TID, 0, 0, "", "", "");

	std::string path = "/home/file.txt";

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                (int64_t)3,
	                                path.c_str(),
	                                (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                (uint32_t)0,
	                                (uint32_t)0,
	                                (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "user.name"), "");
	ASSERT_EQ(get_field_as_string(evt, "user.homedir"), "");
	ASSERT_EQ(get_field_as_string(evt, "user.shell"), "");
}

TEST_F(sinsp_with_test_input, USER_FILTER_extract_from_loaded_user_entry) {
	add_default_init_thread();

	open_inspector();

	// Creating the entry in the user group manager will override
	// the one created by the inspector threadtable initial load.
	// Since we set **empty** metadata, we expect metadata to be loaded from the system.
	m_inspector.m_usergroup_manager->add_user("", INIT_TID, 0, 0, {}, {}, {});

	std::string path = "/home/file.txt";

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                (int64_t)3,
	                                path.c_str(),
	                                (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                (uint32_t)0,
	                                (uint32_t)0,
	                                (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "user.name"), "root");
	ASSERT_EQ(get_field_as_string(evt, "user.homedir"), "/root");
}
