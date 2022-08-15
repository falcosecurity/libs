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
	add_event(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_RDWR, 0);
	evt = next_event();

	add_event(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, 3, "/tmp/the_file", PPM_O_RDWR, 0, 5, 123);
	// every subsequent call to next_event() will invalidate any previous event
	evt = next_event();

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

/* Assert that an empty `PT_BYTEBUF` param is converted to `<NA>` */
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
	ASSERT_EQ(param->m_len, 5);
	ASSERT_STREQ(param->m_val, "<NA>");
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
