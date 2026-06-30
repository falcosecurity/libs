// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

TEST_F(sinsp_with_test_input, fd_fields_invalid_utf8_match) {
	add_default_init_thread();

	open_inspector();

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      (uint64_t)3,
	                                      "/p\xff/q\xff",
	                                      (uint32_t)PPM_O_RDWR,
	                                      (uint32_t)0,
	                                      (uint32_t)5,
	                                      (uint64_t)123);

	EXPECT_TRUE(eval_filter(evt, "fd.name = \"/p\\xff/q\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "fd.name contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "fd.name glob \"/p?/q?\""));
	EXPECT_TRUE(eval_filter(evt, "fd.name in (\"/p\\xff/q\\xff\")"));
	EXPECT_TRUE(eval_filter(evt, "fd.directory contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "fd.filename endswith \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "fs.path.name contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "evt.arg.name contains \"\\xff\""));
	EXPECT_FALSE(eval_filter(evt, "fd.name contains \"\\xfe\""));
	// regex input is UTF-8-sanitized: the invalid byte becomes U+FFFD, matched by `.`.
	EXPECT_TRUE(eval_filter(evt, "fd.name regex \"/p./q.\""));
	EXPECT_FALSE(eval_filter(evt, "fd.name regex \"/p./q\""));
}

TEST_F(sinsp_with_test_input, proc_fields_invalid_utf8_match) {
	add_default_init_thread();

	open_inspector();

	const auto evt = generate_execve_exit_event_with_default_params(1, "/bin/bad\xff", "bad\xff");

	EXPECT_TRUE(eval_filter(evt, "proc.name contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "proc.name glob \"bad?\""));
	EXPECT_TRUE(eval_filter(evt, "proc.exe contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "proc.exe endswith \"\\xff\""));
	EXPECT_FALSE(eval_filter(evt, "proc.name contains \"\\xfe\""));
}

TEST_F(sinsp_with_test_input, fspath_fields_invalid_utf8_match) {
	add_default_init_thread();

	open_inspector();

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_RENAME_X,
	                                      3,
	                                      (int64_t)0,
	                                      "/tmp/s\xff",
	                                      "/tmp/t\xff");

	EXPECT_TRUE(eval_filter(evt, "fs.path.source contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "fs.path.target contains \"\\xff\""));
}

TEST_F(sinsp_with_test_input, evt_abspath_invalid_utf8_match) {
	add_default_init_thread();

	open_inspector();

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	                                      4,
	                                      (int64_t)4,
	                                      (int64_t)5,
	                                      PPM_O_RDWR,
	                                      "/tmp/a\xff");

	EXPECT_TRUE(eval_filter(evt, "evt.abspath contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "evt.abspath glob \"/tmp/a?\""));
}

TEST_F(sinsp_with_test_input, proc_cwd_invalid_utf8_match) {
	add_default_init_thread();

	open_inspector();

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_CHDIR_X,
	                                      2,
	                                      (int64_t)0,
	                                      "/tmp/c\xff");

	EXPECT_TRUE(eval_filter(evt, "proc.cwd contains \"\\xff\""));
	EXPECT_TRUE(eval_filter(evt, "proc.cwd glob \"/tmp/c?/\""));
}
