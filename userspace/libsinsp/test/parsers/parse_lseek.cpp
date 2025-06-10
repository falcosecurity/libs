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

TEST_F(sinsp_with_test_input, parse_lseek_e_success)
{
	add_default_init_thread();
	open_inspector();

	// Open a dummy file to get a valid FD
	auto open_evt = generate_open_x_event();
	ASSERT_TRUE(open_evt->get_fd_info());
	int64_t dummy_fd = sinsp_test_input::open_params::default_fd;

	uint64_t offset = 1024;
	uint8_t whence_raw = SEEK_SET;
	// The event table stores the scap_lseek_whence converted value for lseek_e
	uint8_t whence_scap = lseek_whence_to_scap(whence_raw);


	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_LSEEK_E,
	                                3,
	                                dummy_fd,
	                                offset,
	                                whence_scap);

	ASSERT_TRUE(evt->get_fd_info());
	ASSERT_EQ(evt->get_fd_info()->m_fd, dummy_fd);

	ASSERT_PARAM_VALUE_EQ(evt, "fd", dummy_fd);
	ASSERT_PARAM_VALUE_EQ(evt, "offset", offset);
	ASSERT_PARAM_VALUE_EQ(evt, "whence", (uint64_t)PPM_SEEK_SET); // Check against the resolved enum
	ASSERT_PARAM_VALUE_STR(evt, "whence", "SEEK_SET");
}

TEST_F(sinsp_with_test_input, parse_lseek_x_success)
{
	add_default_init_thread();
	open_inspector();

	// Open a dummy file to get a valid FD
	auto open_evt = generate_open_x_event();
	ASSERT_TRUE(open_evt->get_fd_info());
	int64_t dummy_fd = sinsp_test_input::open_params::default_fd;

	int64_t res = 1024; // mock return value for lseek
	uint64_t offset = 1024;
	uint8_t whence_raw = SEEK_CUR; // Use a different whence for variety
	// The event table stores the scap_lseek_whence converted value for lseek_x
	uint8_t whence_scap = lseek_whence_to_scap(whence_raw);

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_LSEEK_X,
	                                4,
	                                res,
	                                dummy_fd,
	                                offset,
	                                whence_scap);

	ASSERT_TRUE(evt->get_fd_info());
	ASSERT_EQ(evt->get_fd_info()->m_fd, dummy_fd);

	assert_return_value(evt, res);
	ASSERT_PARAM_VALUE_EQ(evt, "fd", dummy_fd);
	ASSERT_PARAM_VALUE_EQ(evt, "offset", offset);
	ASSERT_PARAM_VALUE_EQ(evt, "whence", (uint64_t)PPM_SEEK_CUR); // Check against the resolved enum
	ASSERT_PARAM_VALUE_STR(evt, "whence", "SEEK_CUR");
}

TEST_F(sinsp_with_test_input, parse_lseek_x_failure)
{
	add_default_init_thread();
	open_inspector();

	// Open a dummy file to get a valid FD
	auto open_evt = generate_open_x_event();
	ASSERT_TRUE(open_evt->get_fd_info());
	int64_t dummy_fd = sinsp_test_input::open_params::default_fd;
	int64_t invalid_fd = -1; // Use an invalid FD for the lseek call itself for failure case

	int64_t res = -EBADF; // mock return value for lseek failure
	uint64_t offset = 1024;
	uint8_t whence_raw = SEEK_END;
	uint8_t whence_scap = lseek_whence_to_scap(whence_raw);

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_LSEEK_X,
	                                4,
	                                res,
	                                invalid_fd, // This is the fd param in the event
	                                offset,
	                                whence_scap);

	// For a failed lseek, fdinfo might not be relevant or might be the invalid_fd
	// Depending on how `get_fd_info` handles errors or invalid fds, this might need adjustment
	// If `invalid_fd` is used, it shouldn't find a valid fd_info unless `-1` is specially handled
	// For now, let's assume we expect no valid fd_info if the fd in event is -1
	if (invalid_fd >= 0) {
		ASSERT_TRUE(evt->get_fd_info());
		ASSERT_EQ(evt->get_fd_info()->m_fd, invalid_fd);
	} else {
		// If fd is < 0, get_fd_info() might return null or a dummy. Test current behavior.
		// This often depends on whether the parser attempts to look up negative FDs.
		// For now, let's be flexible or check specific behavior if known.
		// If fd is -1, it typically means "no fd" or "error", so fd_info might be nullptr.
		ASSERT_FALSE(evt->get_fd_info());
	}


	assert_return_value(evt, res);
	ASSERT_PARAM_VALUE_EQ(evt, "fd", invalid_fd); // Check the raw fd value from the event
	ASSERT_PARAM_VALUE_EQ(evt, "offset", offset);
	ASSERT_PARAM_VALUE_EQ(evt, "whence", (uint64_t)PPM_SEEK_END);
	ASSERT_PARAM_VALUE_STR(evt, "whence", "SEEK_END");
}
