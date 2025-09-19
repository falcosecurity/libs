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
#include <sinsp_errno.h>
#include "test_utils.h"

TEST_F(sinsp_with_test_input, event_category) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;
	std::string syscall_source_name = sinsp_syscall_event_source_name;

	int64_t fd = 4, mountfd = 5, test_errno = 0;

	/* Check that `EC_SYSCALL` category is not considered */
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	                           4,
	                           fd,
	                           mountfd,
	                           PPM_O_RDWR,
	                           "/tmp/the_file.txt");
	ASSERT_EQ(evt->get_category(), EC_FILE);
	ASSERT_EQ(get_field_as_string(evt, "evt.category"), "file");
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "false");
	ASSERT_EQ(get_field_as_string(evt, "evt.num"), "1");

	/* Check that `EC_TRACEPOINT` category is not considered */
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_PROCEXIT_1_E,
	                           5,
	                           test_errno,   // status
	                           test_errno,   // ret
	                           (uint8_t)0,   // sig
	                           (uint8_t)0,   // core
	                           (int64_t)0);  // reaper_tid
	ASSERT_EQ(evt->get_category(), EC_PROCESS);
	ASSERT_EQ(get_field_as_string(evt, "evt.category"), "process");
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "false");
	ASSERT_EQ(get_field_as_string(evt, "evt.num"), "2");

	/* Check that `EC_METAEVENT` category is not considered */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_NOTIFICATION_E, 2, NULL, "data");
	ASSERT_EQ(evt->get_category(), EC_OTHER);
	ASSERT_EQ(get_field_as_string(evt, "evt.category"), "other");
	ASSERT_EQ(get_field_as_string(evt, "evt.source"), syscall_source_name);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_async"), "true");
	ASSERT_EQ(get_field_as_string(evt, "evt.num"), "3");
}

TEST_F(sinsp_with_test_input, event_res) {
	add_default_init_thread();

	open_inspector();

	sinsp_evt *evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_EPOLL_CREATE_X,
	                                      2,
	                                      (int64_t)-SE_EINVAL,
	                                      (int32_t)0);

	EXPECT_EQ(get_field_as_string(evt, "evt.res"), "EINVAL");
	EXPECT_EQ(get_field_as_string(evt, "evt.rawres"), "-22");
	EXPECT_TRUE(eval_filter(evt, "evt.rawres < 0"));
	EXPECT_EQ(get_field_as_string(evt, "evt.failed"), "true");
	EXPECT_EQ(get_field_as_string(evt, "evt.count.error"), "1");

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_EPOLL_CREATE_X,
	                           2,
	                           (uint64_t)0,
	                           (int32_t)100);

	EXPECT_EQ(get_field_as_string(evt, "evt.res"), "SUCCESS");
	EXPECT_EQ(get_field_as_string(evt, "evt.rawres"), "0");
	EXPECT_EQ(get_field_as_string(evt, "evt.failed"), "false");

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_E,
	                           3,
	                           "/tmp/the_file.txt",
	                           0,
	                           0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           (int64_t)123,
	                           "/tmp/the_file.txt",
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);

	EXPECT_EQ(get_field_as_string(evt, "evt.res"), "SUCCESS");
	EXPECT_EQ(get_field_as_string(evt, "evt.rawres"), "123");
	EXPECT_EQ(get_field_as_string(evt, "evt.failed"), "false");

	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_E,
	                           3,
	                           "/tmp/the_file.txt",
	                           0,
	                           0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           (int64_t)-SE_EACCES,
	                           "/tmp/the_file.txt",
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);

	EXPECT_EQ(get_field_as_string(evt, "evt.res"), "EACCES");
	EXPECT_EQ(get_field_as_string(evt, "evt.rawres"), std::to_string(-SE_EACCES).c_str());
	EXPECT_EQ(get_field_as_string(evt, "evt.failed"), "true");
	EXPECT_EQ(get_field_as_string(evt, "evt.count.error"), "1");
	EXPECT_EQ(get_field_as_string(evt, "evt.count.error.file"), "1");
}

TEST_F(sinsp_with_test_input, event_hostname) {
#ifdef __linux__
	/* Set temporary env variable for hostname.
	 * libscap cmake defaults to `set(SCAP_HOSTNAME_ENV_VAR "SCAP_HOSTNAME")`
	 */
	const char *hostname = "testbox";
	const char *libscap_default_env_hostname = "SCAP_HOSTNAME";
	int success1 = setenv(libscap_default_env_hostname, hostname, 1);
	ASSERT_EQ(0, success1);

	add_default_init_thread();

	open_inspector(SINSP_MODE_LIVE);
	sinsp_evt *evt = NULL;

	/* Toy event example from a previous test. */
	int64_t dirfd = 3;
	const char *file_to_run = "/tmp/file_to_run";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, file_to_run, 0, 0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           dirfd,
	                           file_to_run,
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);

	/* Assert correct custom hostname. */
	ASSERT_EQ(get_field_as_string(evt, "evt.hostname"), hostname);

	/* Unset temporary env variable for hostname. */
	int success2 = unsetenv(libscap_default_env_hostname);
	ASSERT_EQ(0, success2);
#endif
}
