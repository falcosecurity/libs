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

/*
	Tests that check proper parameter parsing from kmod/ebpf
*/

/* Assert that empty (`PT_CHARBUF`, `PT_FSPATH`, `PT_FSRELPATH`) params are converted to `<NA>` */
TEST_F(sinsp_with_test_input, charbuf_empty_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t test_errno = 0;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	 * A `NULL` `PT_CHARBUF` param is always converted to `<NA>`.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, NULL);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.path"), "<NA>");

	// this, and the following similar checks, verify that the internal state is set as we need right now.
	// if the internal state changes we can remove or update this check
	ASSERT_STREQ(evt->get_param(1)->as<std::string_view>().data(), "<NA>");

	/* `PPME_SYSCALL_CREAT_E` is a simple event that uses a `PT_FSPATH`
	 * A `NULL` `PT_FSPATH` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CREAT_E, 2, NULL, 0);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), "<NA>");

	ASSERT_STREQ(evt->get_param(0)->as<std::string_view>().data(), "<NA>");

	int64_t dirfd = 0;

	/* `PPME_SYSCALL_EXECVEAT_E` is a simple event that uses a `PT_FSRELPATH`
	 * A `NULL` `PT_FSRELPATH` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, NULL, 0);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.pathname"), "<NA>");

	ASSERT_STREQ(evt->get_param(1)->as<std::string_view>().data(), "<NA>");
}

/* Assert that a `PT_CHARBUF` with `len==1` (just the `\0`) is not changed. */
TEST_F(sinsp_with_test_input, param_charbuf_len_1)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t test_errno = 0;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	 * An empty `PT_CHARBUF` param ("") is not converted to `<NA>` since the length is 1.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, "");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.path"), "");

	ASSERT_STREQ(evt->get_param(1)->as<std::string_view>().data(), "");
}

/* Assert that a "(NULL)" `PT_CHARBUF` param is converted to `<NA>`
 * Only scap-file could send a `PT_CHARBUF` with "(NULL)", in our
 * actual drivers this value is no more supported.
 */
TEST_F(sinsp_with_test_input, charbuf_NULL_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t test_errno = 0;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF` */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, "(NULL)");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.path"), "<NA>");

	ASSERT_STREQ(evt->get_param(1)->as<std::string_view>().data(), "<NA>");
}

/* Assert that an empty `PT_BYTEBUF` param is NOT converted to `<NA>` */
TEST_F(sinsp_with_test_input, bytebuf_empty_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	const sinsp_evt_param* param = NULL;

	int64_t test_errno = 0;

	/* `PPME_SYSCALL_PWRITE_X` is a simple event that uses a `PT_BYTEBUF` */
	scap_const_sized_buffer bytebuf_param;
	bytebuf_param.buf = NULL;
	bytebuf_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PWRITE_X, 2, test_errno, bytebuf_param);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.data"), "NULL"); // "NULL" is the string representation output of the empty buffer

	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);
}

/* Assert that empty (`PT_SOCKADDR`, `PT_SOCKTUPLE`, `PT_FDLIST`) params are NOT converted to `<NA>` */
TEST_F(sinsp_with_test_input, sockaddr_empty_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	const sinsp_evt_param* param = NULL;

	int64_t fd = 0;

	/* `PPME_SOCKET_CONNECT_E` is a simple event that uses a `PT_SOCKADDR` */
	scap_const_sized_buffer sockaddr_param;
	sockaddr_param.buf = NULL;
	sockaddr_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, fd, sockaddr_param);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);

	/* `PPME_SOCKET_CONNECT_X` is a simple event that uses a `PT_SOCKTUPLE` */
	scap_const_sized_buffer socktuple_param;
	socktuple_param.buf = NULL;
	socktuple_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, fd, socktuple_param, fd);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);

	/* `PPME_SYSCALL_POLL_X` is a simple event that uses a `PT_FDLIST` */
	scap_const_sized_buffer fdlist_param;
	fdlist_param.buf = NULL;
	fdlist_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_POLL_X, 2, fd, fdlist_param);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);
}

TEST_F(sinsp_with_test_input, filename_toctou)
{
	// for more information see https://github.com/falcosecurity/falco/security/advisories/GHSA-6v9j-2vm2-ghf7

	add_default_init_thread();

	sinsp_evt *evt;
	open_inspector();

	int64_t fd = 1, dirfd = 3;

	add_event(increasing_ts(), 3, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", 0, 0);
	evt = add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, fd, "/tmp/some_other_file", 0, 0, 0, (uint64_t) 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");

	fd = 2;
	add_event(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_E, 4, dirfd, "/tmp/the_file", 0, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_X, 7, fd, dirfd, "/tmp/some_other_file", 0, 0, 0, (uint64_t) 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");

	fd = 4;
	add_event(increasing_ts(), 2, PPME_SYSCALL_CREAT_E, 2, "/tmp/the_file", 0);
	evt = add_event_advance_ts(increasing_ts(), 2, PPME_SYSCALL_CREAT_X, 5, fd, "/tmp/some_other_file", 0, 0, (uint64_t) 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
}

/* Assert that invalid params in enter events are not considered in the TOCTOU prevention logic. */
TEST_F(sinsp_with_test_input, enter_event_retrieval)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	const char* expected_string = "/tmp/the_file";
	uint64_t dirfd = 3;
	uint64_t new_fd = 100;

	std::vector<const char*> invalid_inputs = {"<NA>", "(NULL)", NULL};

	/* Check `openat` syscall.
	 * `(NULL)` should be converted to `<NA>` and recognized as an invalid param.
	 */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("openat with filename ") + test_utils::describe_string(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_E, 4, dirfd, enter_filename, 0, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_X, 7, new_fd, dirfd, expected_string, 0, 0, 0, (uint64_t) 0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		dirfd++;
		new_fd++;
	}

	/* Check `openat2` syscall. */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("openat2 with filename ") + test_utils::describe_string(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_E, 5, dirfd, "<NA>", 0, 0, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_X, 6, new_fd, dirfd, expected_string, 0, 0, 0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		dirfd++;
		new_fd++;
	}

	/* Check `open` syscall. */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("open with filename ") + test_utils::describe_string(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, NULL, 0, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, new_fd, expected_string, 0, 0, 0, (uint64_t) 0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		new_fd++;
	}

	/* Check `creat` syscall. */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("creat with filename ") + test_utils::describe_string(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CREAT_E, 3, NULL, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CREAT_X, 5, new_fd, expected_string, 0, 0, (uint64_t) 0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		new_fd++;
	}

}

// Check that the path in case of execve is correctly overwritten in case it was not possible to collect it from the
// entry event but it is possible to collect it from the exit event
TEST_F(sinsp_with_test_input, execve_invalid_path_entry)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_E, 1, "<NA>");

	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, (int64_t) 0, "/bin/test-exe", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "test-exe", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "test-exe");
}

/* Check that enum flags are correctly handled,
 * even when a single enum value is matched by multiple flags.
 */
TEST_F(sinsp_with_test_input, enumparams)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	/* `PPME_SOCKET_SOCKET_E` is a simple event that uses a PT_ENUMFLAGS32 (param 1) */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, PPM_AF_UNIX, 0, 0);

	ASSERT_EQ(evt->get_param(0)->as<uint32_t>(), PPM_AF_UNIX);

	const char *val_str = NULL;
	evt->get_param_as_str(0, &val_str);
	// Since the enum value "1" matches multiple flags values,
	// we expect a space-separated list of them
	ASSERT_STREQ(val_str, "AF_LOCAL|AF_UNIX");
}

TEST_F(sinsp_with_test_input, enumparams_fcntl_dupfd)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	/* `PPME_SYSCALL_FCNTL_E` is a simple event that uses a PT_ENUMFLAGS32 (param 2) */
	uint8_t flag = PPM_FCNTL_F_DUPFD;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCNTL_E, 2, (int64_t) 0, flag);

	ASSERT_EQ(evt->get_param(1)->as<uint8_t>(), PPM_FCNTL_F_DUPFD);

	const char *val_str = NULL;
	evt->get_param_as_str(1, &val_str);
	ASSERT_STREQ(val_str, "F_DUPFD");
}

/* Check that bitmask flags are correctly handled
 */
TEST_F(sinsp_with_test_input, bitmaskparams)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t dirfd = 0;
	/* `PPME_SYSCALL_OPENAT_E` is a simple event that uses a PT_FLAGS32 (param 3) */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_E, 4, dirfd, "/tmp/foo", PPM_O_RDONLY|PPM_O_CLOEXEC, 0);

	ASSERT_EQ(evt->get_param(2)->as<uint32_t>(), PPM_O_RDONLY|PPM_O_CLOEXEC);

	const char *val_str = NULL;
	evt->get_param_as_str(2, &val_str);
	ASSERT_STREQ(val_str, "O_RDONLY|O_CLOEXEC");
}
