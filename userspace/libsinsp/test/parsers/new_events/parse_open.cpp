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

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, parse_open_success) {
	add_default_init_thread();
	open_inspector();

	int32_t fd = 5;
	uint32_t flags = PPM_O_APPEND | PPM_O_CREAT | PPM_O_RDWR;
	uint32_t mode = PPM_S_IRUSR | PPM_S_IWUSR | PPM_S_IRGRP | PPM_S_IROTH;
	uint32_t dev = 324;
	uint64_t ino = 534;

	auto evt = generate_open_event(
	        sinsp_test_input::open_params{.fd = fd,
	                                      .path = sinsp_test_input::open_params::default_path,
	                                      .flags = flags,
	                                      .mode = mode,
	                                      .dev = dev,
	                                      .ino = ino});

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);

	// The default one + the one just opened
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 2);

	sinsp_fdinfo* fdinfo = init_tinfo->get_fd(fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, sinsp_test_input::open_params::default_path);

	// Assert path filterchecks
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"),
	          sinsp_test_input::open_params::default_directory);
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"),
	          sinsp_test_input::open_params::default_filename);
	EXPECT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(fd));
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "f");

	// Assert parameters filterchecks
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"),
	          std::string("<f>") + sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd32_rename"), std::to_string(fd));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.name"),
	          sinsp_test_input::open_params::default_path);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"), "O_APPEND|O_CREAT|O_RDWR");
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.flags"), "F");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"),
	          "0644");  // octal notation of 420 formatted as string.
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.mode"), "644");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[4]"), "144");  // hexadecimal notation
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.dev"), "144");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[5]"), std::to_string(ino));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.ino"), std::to_string(ino));
}

TEST_F(sinsp_with_test_input, parse_open_failure) {
	add_default_init_thread();
	open_inspector();

	int32_t fd = -3;

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);

	// At the beginning we have only the default file descriptor opened.
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 1);

	auto evt = generate_open_event(sinsp_test_input::open_params{.fd = fd});

	// We should have only the default file descriptor opened, the event failed so no new file
	// descriptor should be created
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 1);

	// Assert path filterchecks
	// we expect `-1` because m_lastevent_fd is set to -1 when the syscall fails.
	EXPECT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(-1));
	// we recover these parameters directly from the syscall even if it fails.
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"),
	          sinsp_test_input::open_params::default_directory);

	// We don't recover the filename
	ASSERT_FALSE(field_has_value(evt, "fd.filename"));
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "f");

	// Assert return value filterchecks
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "ESRCH");
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd32_rename"), std::to_string(fd));
}

TEST_F(sinsp_with_test_input, parse_open_path_too_long) {
	add_default_init_thread();

	open_inspector();

	std::stringstream long_path_ss;
	long_path_ss << "/";
	long_path_ss << std::string(1000, 'A');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'B');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'C');

	std::string long_path = long_path_ss.str();

	auto evt =
	        generate_open_event(sinsp_test_input::open_params{.fd = 3, .path = long_path.c_str()});
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");

	int64_t fd = 4, mountfd = 5;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	                           4,
	                           fd,
	                           mountfd,
	                           PPM_O_RDWR,
	                           long_path.c_str());

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");
	ASSERT_EQ(get_field_as_string(evt, "evt.abspath"), "/PATH_TOO_LONG");
}
