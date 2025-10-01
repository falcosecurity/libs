// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
#include <filter_eval_test.h>

// Test that for rawarg.X we are correctly retrieving the correct field type/format.
TEST_F(sinsp_with_test_input, EVT_FILTER_rawarg_madness) {
	add_default_init_thread();
	open_inspector();

	// [PPME_SYSCALL_EPOLL_CREATE_X] = {"epoll_create",EC_WAIT | EC_SYSCALL, EF_CREATES_FD |
	// EF_MODIFIES_STATE | EF_CONVERTER_MANAGED, 2, {{"res", PT_ERRNO, PF_DEC}, {"size",
	// PT_INT32, PF_DEC}}}
	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_EPOLL_CREATE_X,
	                                      2,
	                                      (int64_t)0,
	                                      (int32_t)-22);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.size"), "-22");
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.size < -20"));

	// [PPME_SYSCALL_SIGNALFD4_X] = {"signalfd4", EC_SIGNAL | EC_SYSCALL, EF_CREATES_FD |
	// EF_MODIFIES_STATE, 2, {{"res", PT_FD, PF_DEC}, {"flags", PT_FLAGS16, PF_HEX, file_flags}}},
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_SIGNALFD4_X,
	                           4,
	                           (int64_t)-1,
	                           (uint16_t)512,
	                           (int64_t)9,
	                           (uint32_t)0);
	// 512 in hex is 200
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.flags"), "200");
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.flags < 515"));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd"), "9");

	// [PPME_SYSCALL_TIMERFD_CREATE_X] = {"timerfd_create", EC_TIME | EC_SYSCALL, EF_CREATES_FD |
	// EF_MODIFIES_STATE | EF_CONVERTER_MANAGED, 3, {{"res", PT_FD, PF_DEC}, {"clockid",
	// PT_UINT8, PF_DEC}, {"flags", PT_UINT8, PF_HEX}}}
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_TIMERFD_CREATE_X,
	                           3,
	                           (int64_t)0,
	                           (uint8_t)-1,
	                           (uint8_t)255);
	// 255 in hex is FF
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.flags"), "FF");
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.flags <= 255"));

	/*
	 * Now test the bugged case where `find_longest_matching_evt_param` returns a size,
	 * but then real event has a size that is bigger than that.
	 * In this case, `find_longest_matching_evt_param` will find `size` param
	 * from PPME_SYSCALL_READ_X that is {"size", PT_UINT32, PF_DEC},
	 * but then we call evt.rawarg.size on a PPME_SYSCALL_SPLICE_X,
	 * whose `size` param is 64bit: {"size", PT_UINT64, PF_DEC}.
	 */
	// [PPME_SYSCALL_SPLICE_X] = {"splice", EC_IO_OTHER | EC_SYSCALL, EF_USES_FD, 4, {
	// {"res", PT_ERRNO, PF_DEC}, {"fd_in", PT_FD, PF_DEC}, {"fd_out", PT_FD, PF_DEC}, {"size",
	// PT_UINT64, PF_DEC}, {"flags", PT_FLAGS32, PF_HEX, splice_flags}}}
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_SPLICE_X,
	                           5,
	                           (int64_t)-1,
	                           (int64_t)-1,
	                           (int64_t)-1,
	                           (uint64_t)512,
	                           (uint32_t)0);
	// Size is PF_DEC, 512 is 512
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.size"), "512");
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.size < 515"));

	evt = generate_execve_exit_event_with_default_params(1, "/bin/test-exe", "test-exe");
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.uid = 0"));   // PT_UID
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.pgid = 0"));  // PT_PID
	ASSERT_TRUE(eval_filter(evt, "evt.rawarg.gid = 0"));   // PT_GID

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
	evt = generate_connect_exit_event();
	ASSERT_ANY_THROW(eval_filter(evt, "evt.rawarg.addr > 0"));   // PT_SOCKADDR is not comparable
	ASSERT_ANY_THROW(eval_filter(evt, "evt.rawarg.tuple > 0"));  // PT_TUPLE is not comparable
#endif
}

TEST_F(sinsp_with_test_input, EVT_FILTER_rawarg_int) {
	add_default_init_thread();

	open_inspector();

	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_SETUID_X,
	                                      2,
	                                      (uint64_t)0,
	                                      (uint32_t)1000);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.uid"), "1000");
}

TEST_F(sinsp_with_test_input, EVT_FILTER_rawarg_str) {
	add_default_init_thread();

	open_inspector();

	std::string path = "/home/file.txt";

	// In the enter event we don't send the `PPM_O_F_CREATED`
	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      (int64_t)0,
	                                      path.c_str(),
	                                      (uint32_t)0,
	                                      (uint32_t)0,
	                                      (uint32_t)0,
	                                      (uint64_t)0);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.name"), path);
}

const auto rawarg_eq_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_eq_0", "evt.rawarg.flags = 0", filter_eval_test_case::EXPECT_FALSE},
        {"PT_UINT64_eq_0", "evt.rawarg.cap_inheritable = 0", filter_eval_test_case::EXPECT_FALSE},
        {"PT_ABSTIME_eq_0", "evt.rawarg.exe_ino_ctime = 0", filter_eval_test_case::EXPECT_FALSE},
        {"PT_UID_eq_0", "evt.rawarg.uid = 0", filter_eval_test_case::EXPECT_FALSE},
        {"PT_FSPATH_eq_NA",
         "evt.rawarg.trusted_exepath = <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false? Actually,
                                               // trusted_exepath is set to <NA>.
        {"PT_PID_eq_0", "evt.rawarg.pgid = 0", filter_eval_test_case::EXPECT_FALSE},
        {"PT_GID_eq_0", "evt.rawarg.gid = 0", filter_eval_test_case::EXPECT_FALSE},
});

const auto rawarg_contains_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_contains_str",
         "evt.rawarg.flags contains 'str'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UINT64_contains_str",
         "evt.rawarg.cap_inheritable contains 'str'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_ABSTIME_contains_str",
         "evt.rawarg.exe_ino_ctime contains 'str'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UID_contains_str",
         "evt.rawarg.uid contains 'str'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_FSPATH_contains_str",
         "evt.rawarg.trusted_exepath contains 'str'",
         filter_eval_test_case::EXPECT_FALSE},  // Should this always return false?
        {"PT_FSPATH_contains_NA",
         "evt.rawarg.trusted_exepath contains <NA>",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_contains_empty",
         "evt.rawarg.trusted_exepath contains ''",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_PID_contains_str",
         "evt.rawarg.pgid contains 'str'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_GID_contains_str",
         "evt.rawarg.gid contains 'str'",
         filter_eval_test_case::EXPECT_THROW},
});

const auto rawarg_exists_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_exists", "evt.rawarg.flags exists", filter_eval_test_case::EXPECT_FALSE},
        {"PT_UINT64_exists",
         "evt.rawarg.cap_inheritable exists",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_ABSTIME_exists",
         "evt.rawarg.exe_ino_ctime exists",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_UID_exists", "evt.rawarg.uid exists", filter_eval_test_case::EXPECT_FALSE},
        {"PT_FSPATH_exists",
         "evt.rawarg.trusted_exepath exists",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false? Actually,
                                               // trusted_exepath is set to <NA>, so it exists
        {"PT_PID_exists", "evt.rawarg.pgid exists", filter_eval_test_case::EXPECT_FALSE},
        {"PT_GID_exists", "evt.rawarg.gid exists", filter_eval_test_case::EXPECT_FALSE},
});

const auto rawarg_glob_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_glob_path",
         "evt.rawarg.flags glob '/path/*'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UINT64_glob_path",
         "evt.rawarg.cap_inheritable glob '/path/*'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_ABSTIME_glob_path",
         "evt.rawarg.exe_ino_ctime glob '/path/*'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UID_glob_path", "evt.rawarg.uid glob '/path/*'", filter_eval_test_case::EXPECT_THROW},
        {"PT_FSPATH_glob_path",
         "evt.rawarg.trusted_exepath glob '/path/*'",
         filter_eval_test_case::EXPECT_FALSE},  // Should this always return false?
        {"PT_FSPATH_glob_NA",
         "evt.rawarg.trusted_exepath glob '<NA>'",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_glob_empty",
         "evt.rawarg.trusted_exepath glob ''",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_PID_glob_path", "evt.rawarg.pgid glob '/path/*'", filter_eval_test_case::EXPECT_THROW},
        {"PT_GID_glob_path", "evt.rawarg.gid glob '/path/*'", filter_eval_test_case::EXPECT_THROW},
});

const auto rawarg_pmatch_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_pmatch_path",
         "evt.rawarg.flags pmatch (/path)",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UINT64_pmatch_path",
         "evt.rawarg.cap_inheritable pmatch (/path)",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_ABSTIME_pmatch_path",
         "evt.rawarg.exe_ino_ctime pmatch (/path)",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UID_pmatch_path",
         "evt.rawarg.uid pmatch (/path)",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_FSPATH_pmatch_NA",
         "evt.rawarg.trusted_exepath pmatch (<NA>)",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_pmatch_empty_str",
         "evt.rawarg.trusted_exepath pmatch ('')",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_pmatch_empty",
         "evt.rawarg.trusted_exepath pmatch ()",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_PID_pmatch_path",
         "evt.rawarg.pgid pmatch (/path)",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_GID_pmatch_path",
         "evt.rawarg.gid pmatch (/path)",
         filter_eval_test_case::EXPECT_THROW},
});

const auto rawarg_regex_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_regex", "evt.rawarg.flags regex '[0-9]+'", filter_eval_test_case::EXPECT_THROW},
        {"PT_UINT64_regex",
         "evt.rawarg.cap_inheritable regex '[0-9]+'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_ABSTIME_regex",
         "evt.rawarg.exe_ino_ctime regex '[0-9]+'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UID_regex", "evt.rawarg.uid regex '[0-9]+'", filter_eval_test_case::EXPECT_THROW},
        {"PT_FSPATH_regex_NA",
         "evt.rawarg.trusted_exepath regex '<NA>'",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_regex_everything",
         "evt.rawarg.trusted_exepath regex '.*'",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_regex_empty_str",
         "evt.rawarg.trusted_exepath regex ''",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_PID_regex", "evt.rawarg.pgid regex '[0-9]+'", filter_eval_test_case::EXPECT_THROW},
        {"PT_GID_regex", "evt.rawarg.gid regex '[0-9]+'", filter_eval_test_case::EXPECT_THROW},
});

const auto rawarg_startswith_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_startswith_0",
         "evt.rawarg.flags startswith 0'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UINT64_startswith_0",
         "evt.rawarg.cap_inheritable startswith 0'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_ABSTIME_startswith_0",
         "evt.rawarg.exe_ino_ctime startswith 0'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_UID_startswith_0",
         "evt.rawarg.uid startswith 0'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_FSPATH_startswith_NA",
         "evt.rawarg.trusted_exepath startswith '<NA>'",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_startswith_empty_str",
         "evt.rawarg.trusted_exepath startswith ''",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_PID_startswith_0",
         "evt.rawarg.pgid startswith 0'",
         filter_eval_test_case::EXPECT_THROW},
        {"PT_GID_startswith_0",
         "evt.rawarg.gid startswith 0'",
         filter_eval_test_case::EXPECT_THROW},
});

const auto rawarg_in_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_in_set_with_0", "evt.rawarg.flags in (0)", filter_eval_test_case::EXPECT_FALSE},
        {"PT_UINT64_in_set_with_0",
         "evt.rawarg.cap_inheritable in (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_ABSTIME_in_set_with_0",
         "evt.rawarg.exe_ino_ctime in (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_UID_in_set_with_0", "evt.rawarg.uid in (0)", filter_eval_test_case::EXPECT_FALSE},
        {"PT_FSPATH_in_set_with_NA",
         "evt.rawarg.trusted_exepath in ('<NA>')",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_in_set_with_empty_str",
         "evt.rawarg.trusted_exepath in ('')",
         filter_eval_test_case::EXPECT_FALSE},  // Should this always return false?
        {"PT_FSPATH_in_empty_set",
         "evt.rawarg.trusted_exepath in ()",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_PID_in_set_with_0", "evt.rawarg.pgid in (0)", filter_eval_test_case::EXPECT_FALSE},
        {"PT_GID_in_set_with_0", "evt.rawarg.gid in (0)", filter_eval_test_case::EXPECT_FALSE},
});

const auto rawarg_intersects_op_test_cases = testing::ValuesIn(std::vector<filter_eval_test_case>{
        {"PT_FLAGS_intersects_set_with_0",
         "evt.rawarg.flags intersects (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_UINT64_intersects_set_with_0",
         "evt.rawarg.cap_inheritable intersects (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_ABSTIME_intersects_set_with_0",
         "evt.rawarg.exe_ino_ctime intersects (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_UID_intersects_set_with_0",
         "evt.rawarg.uid intersects (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_FSPATH_intersects_set_with_NA",
         "evt.rawarg.trusted_exepath intersects ('<NA>')",
         filter_eval_test_case::EXPECT_TRUE},  // Should this always return false?
        {"PT_FSPATH_intersects_set_with_empty_str",
         "evt.rawarg.trusted_exepath intersects ('')",
         filter_eval_test_case::EXPECT_FALSE},  // Should this always return false?
        {"PT_FSPATH_intersects_empty_set",
         "evt.rawarg.trusted_exepath intersects ()",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_PID_intersects_set_with_0",
         "evt.rawarg.pgid intersects (0)",
         filter_eval_test_case::EXPECT_FALSE},
        {"PT_GID_intersects_set_with_0",
         "evt.rawarg.gid intersects (0)",
         filter_eval_test_case::EXPECT_FALSE},
});

INSTANTIATE_TEST_CASE_P(rawarg_eq_op,
                        filter_eval_test,
                        rawarg_eq_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_contains_op,
                        filter_eval_test,
                        rawarg_contains_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_exists_op,
                        filter_eval_test,
                        rawarg_exists_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_glob_op,
                        filter_eval_test,
                        rawarg_glob_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_pmatch_op,
                        filter_eval_test,
                        rawarg_pmatch_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_regex_op,
                        filter_eval_test,
                        rawarg_regex_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_startswith_op,
                        filter_eval_test,
                        rawarg_startswith_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_in_op,
                        filter_eval_test,
                        rawarg_in_op_test_cases,
                        filter_eval_test::test_case_name_gen);
INSTANTIATE_TEST_CASE_P(rawarg_intersects_op,
                        filter_eval_test,
                        rawarg_intersects_op_test_cases,
                        filter_eval_test::test_case_name_gen);

TEST_F(sinsp_with_test_input, EVT_FILTER_rawarg_empty_params) {
	add_default_init_thread();

	open_inspector();

	// Use execve event type as it contains a multitude of parameters (specifically, in the range
	// 18-29) that can be set to empty by the scap-converter.
	const auto evt = generate_execve_exit_event_with_empty_params(1, "/bin/test-exe", "test-exe");

	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.flags"), "0");               // PT_FLAGS32
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.cap_inheritable"), "0");     // PT_UINT64
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.exe_ino_ctime"), "0");       // PT_ABSTIME
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.uid"), "0");                 // PT_UID
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.trusted_exepath"), "<NA>");  // PT_FSPATH
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.pgid"), "0");                // PT_PID
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.gid"), "0");                 // PT_GID
}
