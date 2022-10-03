/*
Copyright (C) 2021 The Falco Authors.

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

#include "sinsp_with_test_input.h"
#include "test_utils.h"

using namespace libsinsp;

class sinsp_external_processor_dummy : public event_processor
{
	void on_capture_start() override {}
	void process_event(sinsp_evt* evt, event_return rc) override {}
	void add_chisel_metric(statsd_metric* metric) override {}
};

TEST(sinsp, external_event_processor_initialization)
{
	sinsp my_sinsp;
	EXPECT_EQ(my_sinsp.get_external_event_processor(), nullptr);
	sinsp_external_processor_dummy processor;
	my_sinsp.register_external_event_processor(processor);
	EXPECT_EQ(my_sinsp.get_external_event_processor(), &processor);
}

TEST_F(sinsp_with_test_input, file_open)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	// since adding and reading events happens on a single thread they can be interleaved.
	// tests may need to change if that will not be the case anymore
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_RDWR, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, 3, "/tmp/the_file", PPM_O_RDWR, 0, 5, 123);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
}

TEST_F(sinsp_with_test_input, dup_dup2_dup3)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/test", PPM_O_TRUNC | PPM_O_CREAT | PPM_O_WRONLY, 0666);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, 3, "/tmp/test", PPM_O_TRUNC | PPM_O_CREAT | PPM_O_WRONLY, 0666, 0xCA02, 123);

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_E, 1, 3);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_X, 1, 1);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "1");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP2_E, 1, 3);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP2_X, 3, 123, 1, 123);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "123");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP3_E, 1, 3);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP3_X, 4, 123, 1, 123, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "123");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_1_E, 1, 3);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_1_X, 2, 1, 3);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "1");
}

/* Assert that empty (`PT_CHARBUF`, `PT_FSPATH`, `PT_FSRELPATH`) params are converted to `<NA>` */
TEST_F(sinsp_with_test_input, check_charbuf_empty_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_evt_param* param = NULL;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	 * A `NULL` `PT_CHARBUF` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, 0, NULL);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 5);
	ASSERT_STREQ(param->m_val, "<NA>");

	/* `PPME_SYSCALL_CREAT_E` is a simple event that uses a `PT_FSPATH`
	 * A `NULL` `PT_FSPATH` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CREAT_E, 2, NULL, 0);
	param = evt->get_param(0);
	ASSERT_EQ(param->m_len, 5);
	ASSERT_STREQ(param->m_val, "<NA>");

	/* `PPME_SYSCALL_EXECVEAT_E` is a simple event that uses a `PT_FSRELPATH`
	 * A `NULL` `PT_FSRELPATH` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, 0, NULL, 0);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 5);
	ASSERT_STREQ(param->m_val, "<NA>");
}

/* Assert that a `PT_CHARBUF` with `len==1` (just the `\0`) is not changed. */
TEST_F(sinsp_with_test_input, check_charbuf_len_1)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_evt_param* param = NULL;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	 * An empty `PT_CHARBUF` param ("") is not converted to `<NA>` since the length is 1.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, 0, "");
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 1);
	ASSERT_STREQ(param->m_val, "");
}

/* Assert that a "(NULL)" `PT_CHARBUF` param is converted to `<NA>`
 * Only scap-file could send a `PT_CHARBUF` with "(NULL)", in our
 * actual drivers this value is no more supported.
 */
TEST_F(sinsp_with_test_input, check_charbuf_NULL_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_evt_param* param = NULL;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF` */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, 0, "(NULL)");
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 5);
	ASSERT_STREQ(param->m_val, "<NA>");
}

/* Assert that an empty `PT_BYTEBUF` param is NOT converted to `<NA>` */
TEST_F(sinsp_with_test_input, check_bytebuf_empty_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_evt_param* param = NULL;

	/* `PPME_SYSCALL_PWRITE_X` is a simple event that uses a `PT_BYTEBUF` */
	struct scap_const_sized_buffer bytebuf_param;
	bytebuf_param.buf = NULL;
	bytebuf_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PWRITE_X, 2, 0, bytebuf_param);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);
}

/* Assert that empty (`PT_SOCKADDR`, `PT_SOCKTUPLE`, `PT_FDLIST`) params are NOT converted to `<NA>` */
TEST_F(sinsp_with_test_input, check_sockaddr_empty_param)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_evt_param* param = NULL;

	/* `PPME_SOCKET_CONNECT_E` is a simple event that uses a `PT_SOCKADDR` */
	struct scap_const_sized_buffer sockaddr_param;
	sockaddr_param.buf = NULL;
	sockaddr_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, 0, sockaddr_param);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);

	/* `PPME_SOCKET_CONNECT_X` is a simple event that uses a `PT_SOCKTUPLE` */
	struct scap_const_sized_buffer socktuple_param;
	socktuple_param.buf = NULL;
	socktuple_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 2, 0, socktuple_param);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);

	/* `PPME_SYSCALL_POLL_X` is a simple event that uses a `PT_FDLIST` */
	struct scap_const_sized_buffer fdlist_param;
	fdlist_param.buf = NULL;
	fdlist_param.size = 0;
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_POLL_X, 2, 0, fdlist_param);
	param = evt->get_param(1);
	ASSERT_EQ(param->m_len, 0);
}

/* Assert that invalid params in enter events are not considered in the TOCTOU prevention logic. */
TEST_F(sinsp_with_test_input, enter_event_retrieval)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	const char* expected_string = "/tmp/the_file";
	int dirfd = 3;
	int new_fd = 100;

	std::vector<const char*> invalid_inputs = {"<NA>", "(NULL)", NULL};

	auto describe_filename = [](const char* filename)
	{
		std::string description;
		if (filename == NULL) {
			description.append("with literal NULL (0) as filename");
		} else {
			description.append("with filename: \"");
			description.append(filename);
			description.append("\"");
		}

		return description;
	};

	/* Check `openat` syscall.
	 * `(NULL)` should be converted to `<NA>` and recognized as an invalid param.
	 */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("openat ") + describe_filename(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_E, 4, dirfd, enter_filename, 0, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_X, 7, new_fd, dirfd, expected_string, 0, 0, 0, 0);
		if(evt->get_thread_info() && evt->get_thread_info()->get_fd(new_fd))
		{
			ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
			ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;
		}
		else
		{
			FAIL() << test_context;
		}

		dirfd++;
		new_fd++;
	}

	/* Check `openat2` syscall. */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("openat2 ") + describe_filename(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_E, 5, dirfd, "<NA>", 0, 0, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_X, 6, new_fd, dirfd, expected_string, 0, 0, 0);
		if(evt->get_thread_info() && evt->get_thread_info()->get_fd(new_fd))
		{
			ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
			ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;
		}
		else
		{
			FAIL() << test_context;
		}

		dirfd++;
		new_fd++;
	}

	/* Check `open` syscall. */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("open ") + describe_filename(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, NULL, 0, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, new_fd, expected_string, 0, 0, 0, 0);
		if(evt->get_thread_info() && evt->get_thread_info()->get_fd(new_fd))
		{
			ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
			ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;
		}
		else
		{
			FAIL() << test_context;
		}

		new_fd++;
	}

	/* Check `creat` syscall. */
	for (const char *enter_filename : invalid_inputs)
	{
		std::string test_context = std::string("creat ") + describe_filename(enter_filename);

		add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CREAT_E, 3, NULL, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CREAT_X, 5, new_fd, expected_string, 0, 0, 0);
		if(evt->get_thread_info() && evt->get_thread_info()->get_fd(new_fd))
		{
			ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
			ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;
		}
		else
		{
			FAIL() << test_context;
		}

		new_fd++;
	}

}

TEST_F(sinsp_with_test_input, test_file_name_toctou)
{
	// for more information see https://github.com/falcosecurity/falco/security/advisories/GHSA-6v9j-2vm2-ghf7

	add_default_init_thread();

	sinsp_evt *evt;
	open_inspector();

	add_event(increasing_ts(), 3, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", 0, 0);
	evt = add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, 1, "/tmp/some_other_file", 0, 0, 0, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");

	add_event(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_E, 4, 3, "/tmp/the_file", 0, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT_2_X, 7, 2, 2, "/tmp/some_other_file", 0, 0, 0, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");

	add_event(increasing_ts(), 2, PPME_SYSCALL_CREAT_E, 2, "/tmp/the_file", 0);
	evt = add_event_advance_ts(increasing_ts(), 2, PPME_SYSCALL_CREAT_X, 5, 4, "/tmp/some_other_file", 0, 0, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
}

/* Assert if the thread `exepath` is set to the right value
 * if we call `execveat` in the following way:
 * - valid `dirfd` that points to the file to run.
 * - `AT_EMPTY_PATH` flag
 * - an invalid `pathname` (<NA>), this is not considered if `AT_EMPTY_PATH` is specified
 */
TEST_F(sinsp_with_test_input, execveat_empty_path_flag)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* We generate a `dirfd` associated with the file that
	 * we want to run with the `execveat`,
	 */
	int64_t dirfd = 3;
	const char *file_to_run = "/tmp/file_to_run";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, file_to_run, 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, file_to_run, 0, 0, 0, 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "<NA>", PPM_EXVAT_AT_EMPTY_PATH);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	struct scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, 0, "<NA>", empty_bytebuf, 1, 1, 1, "<NA>", 0, 0, 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, 0, 0, 0, 0, 0, 0);

	/* The `exepath` should be the file pointed by the `dirfd` since `execveat` is called with
	 * `AT_EMPTY_PATH` flag.
	 */
	if(evt->get_thread_info())
	{
		ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), file_to_run);
	}
	else
	{
		FAIL();
	}
}

/* Assert if the thread `exepath` is set to the right value
 * if we call `execveat` in the following way:
 * - valid `dirfd` that points to the directory that contains the file we want to run.
 * - flags=0.
 * - a valid `pathname` relative to dirfd.
 */
TEST_F(sinsp_with_test_input, execveat_relative_path)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* We generate a `dirfd` associated with the directory that contains the file that
	 * we want to run with the `execveat`,
	 */
	int64_t dirfd = 3;
	const char *directory = "/tmp/dir";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, directory, 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, directory, 0, 0, 0, 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "file", 0);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	struct scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, 0, "<NA>", empty_bytebuf, 1, 1, 1, "<NA>", 0, 0, 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, 0, 0, 0, 0, 0, 0);

	/* The `exepath` should be the directory pointed by the `dirfd` + the pathname
	 * specified in the `execveat` enter event.
	 */
	if(evt->get_thread_info())
	{
		ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "/tmp/dir/file");
	}
	else
	{
		FAIL();
	}
}

/* Assert if the thread `exepath` is set to the right value
 * if we call `execveat` in the following way:
 * - invalid `dirfd`, it shouldn't be considered if the `pathname` is absolute.
 * - flags=0.
 * - a valid absolute `pathname`.
 */
TEST_F(sinsp_with_test_input, execveat_absolute_path)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	int invalid_dirfd = 0;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, invalid_dirfd, "/tmp/file", 0);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	struct scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, 0, "<NA>", empty_bytebuf, 1, 1, 1, "<NA>", 0, 0, 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, 0, 0, 0, 0, 0, 0);

	/* The `exepath` should be the absolute file path that we passed in the
	 * `execveat` enter event.
	 */
	if(evt->get_thread_info())
	{
		ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "/tmp/file");
	}
	else
	{
		FAIL();
	}
}

/* Assert if the thread `exepath` is set to the right value
 * if we call `execveat` in the following way:
 * - valid `dirfd` that points to the directory that contains the file we want to run.
 * - flags=0.
 * - an invalid `pathname` (<NA>).
 *
 * This test simulates the case in which we are not able to retrieve the path from the syscall
 * in the kernel.
 */
TEST_F(sinsp_with_test_input, execveat_invalid_path)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* We generate a `dirfd` associated with the directory that contains the file that
	 * we want to run with the `execveat`,
	 */
	int64_t dirfd = 3;
	const char *directory = "/tmp/dir";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, directory, 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, directory, 0, 0, 0, 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "<NA>", 0);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	struct scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, 0, "<NA>", empty_bytebuf, 1, 1, 1, "<NA>", 0, 0, 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, 0, 0, 0, 0, 0, 0);

	/* The `exepath` should be `<NA>`, sinsp should recognize that the `pathname`
	 * is invalid and should set `<NA>`.
	 */
	if(evt->get_thread_info())
	{
		ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "<NA>");
	}
	else
	{
		FAIL();
	}
}

TEST_F(sinsp_with_test_input, creates_fd_generic)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_E, 3, -1, NULL, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_X, 1, 5);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "signalfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "s");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "5");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_TIMERFD_CREATE_E, 2, 0, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_TIMERFD_CREATE_X, 1, 6);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "timerfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "t");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "6");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT_X, 1, 7);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "7");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_X, 1, 8);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "bpf");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "b");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "8");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_USERFAULTFD_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_USERFAULTFD_X, 2, 9, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "userfaultfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "u");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "9");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_IO_URING_SETUP_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_IO_URING_SETUP_X, 8, 10, 0, 0, 0, 0, 0, 0, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "io_uring");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "r");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "10");
}

TEST_F(sinsp_with_test_input, spawn_process)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	uint64_t parent_pid = 1, parent_tid = 1, child_pid = 20, child_tid = 20;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	std::vector<std::string> cgroups = {"cpuset=/", "cpu=/user.slice", "cpuacct=/user.slice", "io=/user.slice", "memory=/user.slice/user-1000.slice/session-1.scope", "devices=/user.slice", "freezer=/", "net_cls=/", "perf_event=/", "net_prio=/", "hugetlb=/", "pids=/user.slice/user-1000.slice/session-1.scope", "rdma=/", "misc=/"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::vector<std::string> env = {"SHELL=/bin/bash", "PWD=/home/user", "HOME=/home/user"};
	std::string envv = test_utils::to_null_delimited(env);
	std::vector<std::string> args = {"--help"};
	std::string argsv = test_utils::to_null_delimited(args);
	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, parent_pid, parent_tid, 0, "", 1024, 0, 68633, 12088, 7208, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, parent_pid, parent_tid);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, 0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", 1024, 0, 1, 12088, 3764, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, child_pid, child_tid);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 20, 0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", 1024, 0, 28, 29612, 4, 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, 34818, parent_pid, 1000, 1);

	// check that the cwd is inherited from the parent (default process has /root/)
	ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/root/");
	// check that the name is updated
	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "test-exe");
	// check that pname is taken from the parent process
	ASSERT_EQ(get_field_as_string(evt, "proc.pname"), "init");
}

// test user tracking with setuid
TEST_F(sinsp_with_test_input, setuid_setgid)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt;

	// set a new user ID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_E, 1, 500);
	// check that upon entry we have the default user ID
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "0");

	// check that the user ID is updated if the call is successful
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_X, 1, 0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "500");

	// set a new group ID
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_E, 1, 600);
	// check that upon entry we have the default group ID
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "0");

	// check that the group ID is updated if the call is successful
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_X, 1, 0);
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");

	// check that the new user ID and group ID are retained
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_E, 1, 0);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "500");
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");

	// check that the user ID is not updated after an unsuccessful setuid call
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_X, 1, (int64_t) -1);
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "500");

	// same for group ID
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETGID_X, 1, (int64_t) -1);
	ASSERT_EQ(get_field_as_string(evt, "group.gid"), "600");
}

// Falco libs allow pid over 32bit, those are used to hold extra values in the high bits.
// For example, this is used in gVisor to save the sandbox ID.
// These PIDs are not meaningful to the user and should not be displayed
TEST_F(sinsp_with_test_input, pid_over_32bit)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	uint64_t parent_pid = 1, parent_tid = 1;
	uint64_t child_pid = 0x0000000100000010, child_tid = 0x0000000100000010;
	uint64_t child_vpid = 2, child_vtid = 2;
	uint64_t child2_pid = 0x0000000100000100, child2_tid = 0x0000000100000100;
	uint64_t child2_vpid = 3, child2_vtid = 3;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	std::vector<std::string> cgroups = {"cpuset=/", "cpu=/user.slice", "cpuacct=/user.slice", "io=/user.slice", "memory=/user.slice/user-1000.slice/session-1.scope", "devices=/user.slice", "freezer=/", "net_cls=/", "perf_event=/", "net_prio=/", "hugetlb=/", "pids=/user.slice/user-1000.slice/session-1.scope", "rdma=/", "misc=/"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::vector<std::string> env = {"SHELL=/bin/bash", "PWD=/home/user", "HOME=/home/user"};
	std::string envv = test_utils::to_null_delimited(env);
	std::vector<std::string> args = {"--help"};
	std::string argsv = test_utils::to_null_delimited(args);
	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, parent_pid, parent_tid, 0, "", 1024, 0, 68633, 12088, 7208, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, parent_pid, parent_tid);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, 0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", 1024, 0, 1, 12088, 3764, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, child_vpid, child_vtid);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 20, 0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", 1024, 0, 28, 29612, 4, 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, 34818, parent_pid, 1000, 1);

	ASSERT_FALSE(field_exists(evt, "proc.pid"));
	ASSERT_FALSE(field_exists(evt, "thread.tid"));
	ASSERT_EQ(get_field_as_string(evt, "proc.vpid"), "2");
	ASSERT_EQ(get_field_as_string(evt, "thread.vtid"), "2");

	// spawn a child process to verify ppid/apid
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_E, 0);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, child2_tid, "/bin/test-exe", empty_bytebuf, child_pid, child_tid, child_tid, "", 1024, 0, 68633, 12088, 7208, 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, child_vpid, child_vtid);
	add_event_advance_ts(increasing_ts(), child2_tid, PPME_SYSCALL_CLONE_20_X, 20, 0, "/bin/test-exe", empty_bytebuf, child2_pid, child2_tid, child_tid, "", 1024, 0, 1, 12088, 3764, 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, child2_vpid, child2_vtid);
	add_event_advance_ts(increasing_ts(), child2_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe2");
	evt = add_event_advance_ts(increasing_ts(), child2_tid, PPME_SYSCALL_EXECVE_19_X, 20, 0, "/bin/test-exe2", scap_const_sized_buffer{argsv.data(), argsv.size()}, child2_tid, child2_pid, child_tid, "", 1024, 0, 28, 29612, 4, 0, "test-exe2", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, 34818, child_pid, 1000, 1);

	ASSERT_FALSE(field_exists(evt, "proc.pid"));
	ASSERT_FALSE(field_exists(evt, "thread.tid"));
	ASSERT_FALSE(field_exists(evt, "proc.ppid"));
	ASSERT_FALSE(field_exists(evt, "proc.apid[1]"));
	ASSERT_EQ(get_field_as_string(evt, "proc.vpid"), "3");
	ASSERT_EQ(get_field_as_string(evt, "thread.vtid"), "3");
}

TEST_F(sinsp_with_test_input, open_by_handle_at)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, 4, 5, PPM_O_RDWR, "/tmp/the_file.txt");

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file.txt");
	ASSERT_EQ(get_field_as_string(evt, "evt.abspath"), "/tmp/the_file.txt");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, 6, 7, PPM_O_RDWR, "<NA>");

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "<NA>");
}

TEST_F(sinsp_with_test_input, path_too_long)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	std::stringstream long_path_ss;
	long_path_ss << "/";
	long_path_ss << std::string(1000, 'A');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'B');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'C');

	std::string long_path = long_path_ss.str();

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, long_path.c_str(), PPM_O_RDWR, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, 3, long_path.c_str(), PPM_O_RDWR, 0, 5, 123);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, 4, 5, PPM_O_RDWR, long_path.c_str());

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");
	ASSERT_EQ(get_field_as_string(evt, "evt.abspath"), "/PATH_TOO_LONG");
}
