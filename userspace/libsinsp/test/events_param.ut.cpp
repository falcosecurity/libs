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

#include <libsinsp/memmem.h>

#include <sinsp_with_test_input.h>
#include "test_utils.h"

/*
    Tests that check proper parameter parsing from kmod/ebpf
*/

/* Assert that empty (`PT_CHARBUF`, `PT_FSPATH`, `PT_FSRELPATH`) params are converted to `<NA>` */
TEST_F(sinsp_with_test_input, charbuf_empty_param) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t test_errno = 0;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	 * A `NULL` `PT_CHARBUF` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, NULL);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.path"), "<NA>");

	// this, and the following similar checks, verify that the internal state is set as we need
	// right now. if the internal state changes we can remove or update this check
	ASSERT_EQ(evt->get_param(1)->as<std::string>(), "<NA>");

	/* `PPME_SYSCALL_CREAT_X` is a simple event that uses a `PT_FSPATH`
	 * A `NULL` `PT_FSPATH` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_CREAT_X,
	                           6,
	                           (int64_t)0,
	                           NULL,
	                           (uint32_t)0,
	                           (uint32_t)0,
	                           (uint64_t)0,
	                           (uint16_t)0);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), "<NA>");

	ASSERT_EQ(evt->get_param(1)->as<std::string>(), "<NA>");

	int64_t dirfd = 0;

	/* `PPME_SYSCALL_UNLINKAT_2_X` is a simple event that uses a `PT_FSRELPATH`
	 * A `NULL` `PT_FSRELPATH` param is always converted to `<NA>`.
	 */
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_UNLINKAT_2_X,
	                           4,
	                           (int64_t)0,
	                           dirfd,
	                           nullptr,
	                           (uint32_t)0);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), "<NA>");

	ASSERT_EQ(evt->get_param(2)->as<std::string>(), "<NA>");
}

/* Assert that a `PT_CHARBUF` with `len==1` (just the `\0`) is not changed. */
TEST_F(sinsp_with_test_input, param_charbuf_len_1) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t test_errno = 0;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	 * An empty `PT_CHARBUF` param ("") is not converted to `<NA>` since the length is 1.
	 */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, "");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.path"), "");

	ASSERT_EQ(evt->get_param(1)->as<std::string>(), "");
}

/* Assert that a "(NULL)" `PT_CHARBUF` param is converted to `<NA>`
 * Only scap-file could send a `PT_CHARBUF` with "(NULL)", in our
 * actual drivers this value is no more supported.
 */
TEST_F(sinsp_with_test_input, charbuf_NULL_param) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t test_errno = 0;

	/* `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF` */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, "(NULL)");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.path"), "<NA>");

	ASSERT_EQ(evt->get_param(1)->as<std::string>(), "<NA>");
}

/* Assert that an empty `PT_BYTEBUF` param is NOT converted to `<NA>` */
TEST_F(sinsp_with_test_input, bytebuf_empty_param) {
	add_default_init_thread();

	open_inspector();

	scap_const_sized_buffer bytebuf_param;
	bytebuf_param.buf = NULL;
	bytebuf_param.size = 0;
	int64_t test_errno = 0;
	uint32_t size = 0;
	int64_t fd = 0;
	uint64_t pos = 0;

	/* `PPME_SYSCALL_PWRITE_X` is a simple event that uses a `PT_BYTEBUF` */
	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_PWRITE_X,
	                                5,
	                                test_errno,
	                                bytebuf_param,
	                                fd,
	                                size,
	                                pos);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.data"),
	          "NULL");  // "NULL" is the string representation output of the empty buffer
	ASSERT_TRUE(evt->get_param(1));
	ASSERT_EQ(evt->get_param(1)->len(), 0);
}

/* Assert that empty (`PT_SOCKADDR`, `PT_SOCKTUPLE`, `PT_FDLIST`) params are NOT converted to `<NA>`
 */
TEST_F(sinsp_with_test_input, sockaddr_empty_param) {
	add_default_init_thread();

	open_inspector();

	/* `PPME_SOCKET_CONNECT_X` is a simple event that uses a `PT_SOCKTUPLE` and a `PT_SOCKADDR` */
	constexpr int64_t res = 0;
	scap_const_sized_buffer sockaddr_param{nullptr, 0};
	constexpr int64_t fd = 3;
	scap_const_sized_buffer socktuple_param{nullptr, 0};
	auto* evt = add_event_advance_ts(increasing_ts(),
	                                 1,
	                                 PPME_SOCKET_CONNECT_X,
	                                 4,
	                                 res,
	                                 socktuple_param,
	                                 fd,
	                                 sockaddr_param);
	ASSERT_TRUE(evt->get_param(1)->empty());  // Check tuple emptiness.
	ASSERT_TRUE(evt->get_param(3)->empty());  // Check addr emptiness.

	/* `PPME_SYSCALL_POLL_X` is a simple event that uses a `PT_FDLIST` */
	scap_const_sized_buffer fdlist_param{nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_POLL_X, 2, res, fdlist_param);
	ASSERT_TRUE(evt->get_param(1)->empty());  // // Check fds emptiness.
}

TEST_F(sinsp_with_test_input, filename_toctou) {
	// for more information see
	// https://github.com/falcosecurity/falco/security/advisories/GHSA-6v9j-2vm2-ghf7

	add_default_init_thread();

	sinsp_evt* evt;
	open_inspector();

	int64_t fd = 1, dirfd = 3;

	add_event(increasing_ts(),
	          3,
	          PPME_SYSCALL_OPEN_E,
	          3,
	          "/tmp/the_file",
	          (uint32_t)0,
	          (uint32_t)0);
	evt = add_event_advance_ts(increasing_ts(),
	                           3,
	                           PPME_SYSCALL_OPEN_X,
	                           6,
	                           fd,
	                           "/tmp/some_other_file",
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");

	fd = 2;
	add_event(increasing_ts(),
	          1,
	          PPME_SYSCALL_OPENAT_2_E,
	          4,
	          dirfd,
	          "/tmp/the_file",
	          (uint32_t)0,
	          (uint32_t)0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPENAT_2_X,
	                           7,
	                           fd,
	                           dirfd,
	                           "/tmp/some_other_file",
	                           0,
	                           0,
	                           0,
	                           (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");

	fd = 4;
	add_event(increasing_ts(), 2, PPME_SYSCALL_CREAT_E, 2, "/tmp/the_file", (uint32_t)0);
	evt = add_event_advance_ts(increasing_ts(),
	                           2,
	                           PPME_SYSCALL_CREAT_X,
	                           6,
	                           fd,
	                           "/tmp/some_other_file",
	                           0,
	                           0,
	                           (uint64_t)0,
	                           (uint16_t)PPM_FD_LOWER_LAYER_CREAT);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
}

/* Assert that invalid params in enter events are not considered in the TOCTOU prevention logic. */
TEST_F(sinsp_with_test_input, enter_event_retrieval) {
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
	for(const char* enter_filename : invalid_inputs) {
		std::string test_context =
		        std::string("openat with filename ") + test_utils::describe_string(enter_filename);

		add_filtered_event_advance_ts(increasing_ts(),
		                              1,
		                              PPME_SYSCALL_OPENAT_2_E,
		                              4,
		                              dirfd,
		                              enter_filename,
		                              (uint32_t)0,
		                              (uint32_t)0);
		evt = add_event_advance_ts(increasing_ts(),
		                           1,
		                           PPME_SYSCALL_OPENAT_2_X,
		                           7,
		                           new_fd,
		                           dirfd,
		                           expected_string,
		                           0,
		                           0,
		                           0,
		                           (uint64_t)0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		dirfd++;
		new_fd++;
	}

	/* Check `openat2` syscall. */
	for(const char* enter_filename : invalid_inputs) {
		std::string test_context =
		        std::string("openat2 with filename ") + test_utils::describe_string(enter_filename);

		add_filtered_event_advance_ts(increasing_ts(),
		                              1,
		                              PPME_SYSCALL_OPENAT2_E,
		                              5,
		                              dirfd,
		                              "<NA>",
		                              (uint32_t)0,
		                              (uint32_t)0,
		                              (uint32_t)0);
		evt = add_event_advance_ts(increasing_ts(),
		                           1,
		                           PPME_SYSCALL_OPENAT2_X,
		                           8,
		                           new_fd,
		                           dirfd,
		                           expected_string,
		                           (uint32_t)0,
		                           (uint32_t)0,
		                           (uint32_t)0,
		                           (uint32_t)0,
		                           (uint64_t)0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		dirfd++;
		new_fd++;
	}

	/* Check `open` syscall. */
	for(const char* enter_filename : invalid_inputs) {
		std::string test_context =
		        std::string("open with filename ") + test_utils::describe_string(enter_filename);

		add_filtered_event_advance_ts(increasing_ts(),
		                              1,
		                              PPME_SYSCALL_OPEN_E,
		                              3,
		                              NULL,
		                              (uint32_t)0,
		                              (uint32_t)0);
		evt = add_event_advance_ts(increasing_ts(),
		                           1,
		                           PPME_SYSCALL_OPEN_X,
		                           6,
		                           new_fd,
		                           expected_string,
		                           0,
		                           0,
		                           0,
		                           (uint64_t)0);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		new_fd++;
	}

	/* Check `creat` syscall. */
	for(const char* enter_filename : invalid_inputs) {
		std::string test_context =
		        std::string("creat with filename ") + test_utils::describe_string(enter_filename);

		add_filtered_event_advance_ts(increasing_ts(),
		                              1,
		                              PPME_SYSCALL_CREAT_E,
		                              2,
		                              NULL,
		                              (uint32_t)0);
		evt = add_event_advance_ts(increasing_ts(),
		                           1,
		                           PPME_SYSCALL_CREAT_X,
		                           6,
		                           new_fd,
		                           expected_string,
		                           0,
		                           0,
		                           (uint64_t)0,
		                           (uint16_t)PPM_FD_LOWER_LAYER_CREAT);

		ASSERT_NE(evt->get_thread_info(), nullptr) << test_context;
		ASSERT_NE(evt->get_thread_info()->get_fd(new_fd), nullptr) << test_context;

		ASSERT_EQ(evt->get_thread_info()->get_fd(new_fd)->m_name, expected_string) << test_context;
		ASSERT_EQ(get_field_as_string(evt, "fd.name"), expected_string) << test_context;

		new_fd++;
	}
}

// Check that the path in case of execve is correctly overwritten in case it was not possible to
// collect it from the entry event but it is possible to collect it from the exit event
TEST_F(sinsp_with_test_input, execve_invalid_path_entry) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	const std::string filename{"/bin/test-exe"};
	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_EXECVE_19_X,
	                           30,
	                           (int64_t)0,
	                           filename.c_str(),
	                           empty_bytebuf,
	                           (uint64_t)1,
	                           (uint64_t)1,
	                           (uint64_t)1,
	                           "<NA>",
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           0,
	                           0,
	                           0,
	                           "test-exe",
	                           empty_bytebuf,
	                           empty_bytebuf,
	                           0,
	                           (uint64_t)0,
	                           0,
	                           0,
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           (uint64_t)0,
	                           (uint32_t)0,
	                           filename.c_str(),
	                           (int64_t)0,
	                           (uint32_t)0);

	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "test-exe");
}

/* Check that enum flags are correctly handled,
 * even when a single enum value is matched by multiple flags.
 */
TEST_F(sinsp_with_test_input, enumparams) {
	add_default_init_thread();

	open_inspector();

	auto evt = generate_socket_exit_event(sinsp_test_input::socket_params(PPM_AF_UNIX, SOCK_DGRAM));

	ASSERT_EQ(evt->get_param(1)->as<uint32_t>(), PPM_AF_UNIX);

	const char* val_str = NULL;
	evt->get_param_as_str(1, &val_str);
	// Since the enum value "1" matches multiple flags values,
	// we expect a space-separated list of them
	ASSERT_STREQ(val_str, "AF_LOCAL|AF_UNIX");
}

TEST_F(sinsp_with_test_input, enumparams_fcntl_dupfd) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = nullptr;

	/* `PPME_SYSCALL_FCNTL_X` is a simple event that uses a PT_ENUMFLAGS8 (param 3) */
	uint8_t cmd = PPM_FCNTL_F_DUPFD;
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_FCNTL_X,
	                           3,
	                           (int64_t)0,
	                           (int64_t)0,
	                           cmd);

	ASSERT_EQ(evt->get_param(2)->as<uint8_t>(), PPM_FCNTL_F_DUPFD);

	const char* val_str = nullptr;
	evt->get_param_as_str(2, &val_str);
	ASSERT_STREQ(val_str, "F_DUPFD");
}

/* Check that bitmask flags are correctly handled
 */
TEST_F(sinsp_with_test_input, bitmaskparams) {
	add_default_init_thread();

	open_inspector();

	/* `PPME_SYSCALL_OPENAT_2_X` is a simple event that uses a PT_FLAGS32 (param 4) */
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPENAT_2_X,
	                                      7,
	                                      (int64_t)3,                    // fd
	                                      (int64_t)4,                    // dirfd
	                                      "/tmp/foo",                    // name
	                                      PPM_O_RDONLY | PPM_O_CLOEXEC,  // flags
	                                      (uint32_t)0,                   // mode
	                                      (uint32_t)0,                   // dev
	                                      (uint64_t)0);                  // ino

	ASSERT_EQ(evt->get_param(3)->as<uint32_t>(), PPM_O_RDONLY | PPM_O_CLOEXEC);

	const char* val_str = nullptr;
	evt->get_param_as_str(3, &val_str);
	ASSERT_STREQ(val_str, "O_RDONLY|O_CLOEXEC");
}

TEST_F(sinsp_with_test_input, invalid_string_len) {
	add_default_init_thread();

	open_inspector();
	int64_t test_errno = 0;

	const char* content = "01234567890123456789";
	size_t content_len = strlen(content);

	// `PPME_SYSCALL_CHDIR_X` is a simple event that uses a `PT_CHARBUF`.
	scap_evt* sevt = add_event(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, test_errno, content);

	// corrupt the event by overwriting a \0 in the middle of the string
	void* content_ptr = memmem(sevt, sevt->len, content, content_len);
	static_cast<char*>(content_ptr)[10] = '\0';

	// allow this test to print its own debug logs
	libsinsp_logger()->add_stderr_log();
	libsinsp_logger()->set_severity(sinsp_logger::SEV_DEBUG);

	libsinsp_logger()->log("An error message and data dump is expected in this test.",
	                       sinsp_logger::SEV_DEBUG);
	// process the event and generate an error. It will be printed.
	EXPECT_THROW(advance_ts_get_event(sevt->ts), sinsp_exception);
}
