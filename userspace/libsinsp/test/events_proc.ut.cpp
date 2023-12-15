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
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, file_to_run, 0, 0, 0, (uint64_t) 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "<NA>", PPM_EXVAT_AT_EMPTY_PATH);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be the file pointed by the `dirfd` since `execveat` is called with
	 * `AT_EMPTY_PATH` flag.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), file_to_run);

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), file_to_run);
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
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, directory, 0, 0, 0, (uint64_t) 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "file", 0);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be the directory pointed by the `dirfd` + the pathname
	 * specified in the `execveat` enter event.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "/tmp/dir/file");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/tmp/dir/file");
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
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, directory, 0, 0, 0, (uint64_t) 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "<NA>", 0);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be `<NA>`, sinsp should recognize that the `pathname`
	 * is invalid and should set `<NA>`.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "<NA>");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "<NA>");
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
	uint64_t invalid_dirfd = 0;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, invalid_dirfd, "/tmp/file", (uint32_t) 0);

	/* Please note the exit event for an `execveat` is an `execve` if the syscall succeeds. */
	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVE_19_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be the absolute file path that we passed in the
	 * `execveat` enter event.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "/tmp/file");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/tmp/file");
}

/* Same as `execveat_empty_path_flag` but with `PPME_SYSCALL_EXECVEAT_X` as exit event
 * since on s390x architectures the `execveat` syscall correctly returns a `PPME_SYSCALL_EXECVEAT_X`
 * exit event in case of success.
 */
TEST_F(sinsp_with_test_input, execveat_empty_path_flag_s390)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* We generate a `dirfd` associated with the file that
	 * we want to run with the `execveat`,
	 */
	int64_t dirfd = 3;
	const char *file_to_run = "/tmp/s390x/file_to_run";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, file_to_run, 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, file_to_run, 0, 0, 0, (uint64_t) 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "<NA>", PPM_EXVAT_AT_EMPTY_PATH);

	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be the file pointed by the `dirfd` since `execveat` is called with
	 * `AT_EMPTY_PATH` flag.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), file_to_run);

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), file_to_run);
}

/* Same as `execveat_relative_path` but with `PPME_SYSCALL_EXECVEAT_X` as exit event
 * since on s390x architectures the `execveat` syscall correctly returns a `PPME_SYSCALL_EXECVEAT_X`
 * exit event in case of success.
 */
TEST_F(sinsp_with_test_input, execveat_relative_path_s390)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* We generate a `dirfd` associated with the directory that contains the file that
	 * we want to run with the `execveat`,
	 */
	int64_t dirfd = 3;
	const char *directory = "/tmp/s390x/dir";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, directory, 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, directory, 0, 0, 0, (uint64_t) 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "file", 0);

	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be the directory pointed by the `dirfd` + the pathname
	 * specified in the `execveat` enter event.
	 */

	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "/tmp/s390x/dir/file");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/tmp/s390x/dir/file");
}

/* Same as `execveat_absolute_path` but with `PPME_SYSCALL_EXECVEAT_X` as exit event
 * since on s390x architectures the `execveat` syscall correctly returns a `PPME_SYSCALL_EXECVEAT_X`
 * exit event in case of success.
 */
TEST_F(sinsp_with_test_input, execveat_absolute_path_s390)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	uint64_t invalid_dirfd = 0;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, invalid_dirfd, "/tmp/s390/file", 0);

	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be the absolute file path that we passed in the
	 * `execveat` enter event.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "/tmp/s390/file");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/tmp/s390/file");
}

/* Same as `execveat_invalid_path` but with `PPME_SYSCALL_EXECVEAT_X` as exit event
 * since on s390x architectures the `execveat` syscall correctly returns a `PPME_SYSCALL_EXECVEAT_X`
 * exit event in case of success.
 */
TEST_F(sinsp_with_test_input, execveat_invalid_path_s390)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	/* We generate a `dirfd` associated with the directory that contains the file that
	 * we want to run with the `execveat`,
	 */
	int64_t dirfd = 3;
	const char *directory = "/tmp/s390/dir";
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, directory, 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, directory, 0, 0, 0, (uint64_t) 0);

	/* Now we call the `execveat_e` event,`sinsp` will store this enter
	 * event in the thread storage, in this way the exit event can use it.
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_E, 3, dirfd, "<NA>", 0);

	scap_const_sized_buffer empty_bytebuf = {nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EXECVEAT_X, 23, (int64_t) 0, "<NA>", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 1, "<NA>", (uint64_t) 0, (uint64_t) 0, (uint64_t) 0, 0, 0, 0, "<NA>", empty_bytebuf, empty_bytebuf, 0, (uint64_t) 0, 0, 0, (uint64_t) 0, (uint64_t) 0, (uint64_t) 0);

	/* The `exepath` should be `<NA>`, sinsp should recognize that the `pathname`
	 * is invalid and should set `<NA>`.
	 */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	ASSERT_STREQ(evt->get_thread_info()->m_exepath.c_str(), "<NA>");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "<NA>");
}

TEST_F(sinsp_with_test_input, spawn_process)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	uint64_t parent_pid = 1, parent_tid = 1, child_pid = 20, child_tid = 20, null_pid = 0;
	uint64_t fdlimit = 1024, pgft_maj = 0, pgft_min = 1;
	uint64_t exe_ino = 242048, ctime = 1676262698000004588, mtime = 1676262698000004577;
	uint32_t loginuid = UINT32_MAX - 1, euid = 2000U;

	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	std::vector<std::string> cgroups = {"cpuset=/", "cpu=/user.slice", "cpuacct=/user.slice", "io=/user.slice", "memory=/user.slice/user-1000.slice/session-1.scope", "devices=/user.slice", "freezer=/", "net_cls=/", "perf_event=/", "net_prio=/", "hugetlb=/", "pids=/user.slice/user-1000.slice/session-1.scope", "rdma=/", "misc=/"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::vector<std::string> env = {"SHELL=/bin/bash", "SHELL_NEW=/bin/sh", "PWD=/home/user", "HOME=/home/user"};
	std::string envv = test_utils::to_null_delimited(env);
	std::vector<std::string> args = {"-c", "'echo aGVsbG8K | base64 -d'"};
	std::string argsv = test_utils::to_null_delimited(args);

	/* Parent clone exit event */
	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, parent_pid, parent_tid, null_pid, "", fdlimit, pgft_maj, pgft_min, 12088, 7208, 0, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, parent_pid, parent_tid);

	/* Child clone exit event */
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, 0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", fdlimit, pgft_maj, pgft_min, 12088, 3764, 0, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, child_pid, child_tid);

	/* Execve enter event */
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");

	/* Execve exit event */
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t) 0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 29612, (uint32_t) 4, (uint32_t) 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, (int32_t) 34818, parent_pid, loginuid, (int32_t) PPM_EXE_WRITABLE, parent_pid, parent_pid, parent_pid, exe_ino, ctime, mtime, euid);

	// check that the cwd is inherited from the parent (default process has /root/)
	ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/root/");
	// check that the name is updated
	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "test-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.aname[0]"), "test-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.aname"), "test-exe");

	// check that the pid is updated
	ASSERT_EQ(get_field_as_string(evt, "proc.pid"), "20");
	ASSERT_EQ(get_field_as_string(evt, "proc.vpid"), "20");
	ASSERT_EQ(get_field_as_string(evt, "proc.apid[0]"), "20");
	ASSERT_EQ(get_field_as_string(evt, "proc.apid"), "20");

	// check that the exe is updated (first arg given in this test setup is same as full exepath)
	ASSERT_EQ(get_field_as_string(evt, "proc.exe"), "/bin/test-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexe[0]"), "/bin/test-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexe"), "/bin/test-exe");

	// check that the exepath is updated
	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/bin/test-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[0]"), "/bin/test-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath"), "/bin/test-exe");

	// check session leader (sid) related fields
	ASSERT_EQ(get_field_as_string(evt, "proc.sid"), "0");
	ASSERT_EQ(get_field_as_string(evt, "proc.sname"), "init");
	ASSERT_EQ(get_field_as_string(evt, "proc.sid.exe"), "/sbin/init");
	ASSERT_EQ(get_field_as_string(evt, "proc.sid.exepath"), "/sbin/init");
	ASSERT_EQ(get_field_as_string(evt, "proc.is_sid_leader"), "false");

	//check process group leader (vpgid) related fields
	ASSERT_EQ(get_field_as_string(evt, "proc.vpgid"), "1");
	ASSERT_EQ(get_field_as_string(evt, "proc.is_vpgid_leader"), "false");
	ASSERT_EQ(get_field_as_string(evt, "proc.vpgid.name"), "init");
	ASSERT_EQ(get_field_as_string(evt, "proc.vpgid.exe"), "/sbin/init");
	ASSERT_EQ(get_field_as_string(evt, "proc.vpgid.exepath"), "/sbin/init");

	// check that parent/ancestor info retrieved from the parent process lineage
	ASSERT_EQ(get_field_as_string(evt, "proc.pname"), "init");

	ASSERT_EQ(get_field_as_string(evt, "proc.pexepath"), "/sbin/init");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[1]"), "/sbin/init");
	ASSERT_FALSE(field_has_value(evt, "proc.aexepath[2]"));
	ASSERT_FALSE(field_has_value(evt, "proc.aexepath[3]"));

	ASSERT_EQ(get_field_as_string(evt, "proc.pexe"), "/sbin/init");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexe[1]"), "/sbin/init");
	ASSERT_FALSE(field_has_value(evt, "proc.aexe[2]"));
	ASSERT_FALSE(field_has_value(evt, "proc.aexe[3]"));

	ASSERT_EQ(get_field_as_string(evt, "proc.aname[1]"), "init");
	ASSERT_FALSE(field_has_value(evt, "proc.aname[2]"));
	ASSERT_EQ(get_field_as_string(evt, "proc.ppid"), "1");
	ASSERT_EQ(get_field_as_string(evt, "proc.apid[1]"), "1");
	ASSERT_EQ(get_field_as_string(evt, "proc.pvpid"), "1");
	ASSERT_FALSE(field_has_value(evt, "proc.apid[2]"));
	ASSERT_EQ(get_field_as_string(evt, "proc.cmdline"), "test-exe -c 'echo aGVsbG8K | base64 -d'");
	ASSERT_EQ(get_field_as_string(evt, "proc.pcmdline"), "init");
	ASSERT_EQ(get_field_as_string(evt, "proc.acmdline[0]"), "test-exe -c 'echo aGVsbG8K | base64 -d'");
	ASSERT_EQ(get_field_as_string(evt, "proc.acmdline"), "test-exe -c 'echo aGVsbG8K | base64 -d'");
	ASSERT_EQ(get_field_as_string(evt, "proc.acmdline[1]"), "init");
	ASSERT_FALSE(field_has_value(evt, "proc.acmdline[2]"));

	// check more fields
	ASSERT_EQ(get_field_as_string(evt, "proc.args"), "-c 'echo aGVsbG8K | base64 -d'");
	ASSERT_EQ(get_field_as_string(evt, "proc.exeline"), "/bin/test-exe -c 'echo aGVsbG8K | base64 -d'");
	ASSERT_EQ(get_field_as_string(evt, "proc.tty"), "34818");
	ASSERT_EQ(get_field_as_string(evt, "proc.vpgid"), "1");
	ASSERT_EQ(get_field_as_string(evt, "user.loginuid"), "4294967294");
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "2000");
	ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/root/");
	ASSERT_EQ(get_field_as_string(evt, "proc.vmsize"), "29612");
	ASSERT_EQ(get_field_as_string(evt, "proc.vmrss"), "4");
	ASSERT_EQ(get_field_as_string(evt, "proc.vmswap"), "0");
	ASSERT_EQ(get_field_as_string(evt, "proc.fdlimit"), "1024");
	ASSERT_EQ(get_field_as_string(evt, "thread.pfmajor"), "0");
	ASSERT_EQ(get_field_as_string(evt, "thread.pfminor"), "1");
	ASSERT_EQ(get_field_as_string(evt, "proc.is_exe_writable"), "true");
	ASSERT_EQ(get_field_as_string(evt, "proc.exe_ino"), "242048");
	ASSERT_EQ(get_field_as_string(evt, "proc.exe_ino.ctime"), "1676262698000004588");
	ASSERT_EQ(get_field_as_string(evt, "proc.exe_ino.mtime"), "1676262698000004577");
	ASSERT_EQ(get_field_as_string(evt, "proc.cmdnargs"), "2");
	ASSERT_EQ(get_field_as_string(evt, "proc.cmdlenargs"), "29");
	ASSERT_EQ(get_field_as_string(evt, "proc.sname"), "init");

	ASSERT_EQ(get_field_as_string(evt, "proc.env"), "SHELL=/bin/bash SHELL_NEW=/bin/sh PWD=/home/user HOME=/home/user");
	ASSERT_EQ(get_field_as_string(evt, "proc.env[HOME]"), "/home/user");
	ASSERT_EQ(get_field_as_string(evt, "proc.env[SHELL]"), "/bin/bash");
	ASSERT_EQ(get_field_as_string(evt, "proc.env[SHELL_NEW]"), "/bin/sh"); // test for prefix similarity
	ASSERT_EQ(get_field_as_string(evt, "proc.aenv"), "SHELL=/bin/bash SHELL_NEW=/bin/sh PWD=/home/user HOME=/home/user");
	ASSERT_EQ(get_field_as_string(evt, "proc.aenv[0]"), "SHELL=/bin/bash SHELL_NEW=/bin/sh PWD=/home/user HOME=/home/user");
	ASSERT_EQ(get_field_as_string(evt, "proc.aenv[1]"), "TEST_ENV_PARENT_LINEAGE=secret HOME=/home/user/parent");
	ASSERT_EQ(get_field_as_string(evt, "proc.aenv[HOME]"), "/home/user/parent"); // the parent has /home/user/parent vs /home/user in the same named HOME env variable of the current proc
	ASSERT_EQ(get_field_as_string(evt, "proc.aenv[SHELL]"), "");
	ASSERT_EQ(get_field_as_string(evt, "proc.aenv[TEST_ENV_PARENT_LINEAGE]"), "secret");
}

// check parsing of container events (possibly from capture files)
#if !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__) // MINIMAL_BUILD and emscripten don't support containers at all
TEST_F(sinsp_with_test_input, spawn_process_container)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	uint64_t parent_pid = 1, parent_tid = 1, child_pid = 20, child_tid = 20;
	uint64_t fdlimit = 1024, pgft_maj = 0, pgft_min = 1;
	uint64_t exe_ino = 242048, ctime = 1676262698000004577, mtime = 1676262698000004588;
	uint32_t loginuid = UINT32_MAX, euid = UINT32_MAX;

	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	std::vector<std::string> cgroups = {"cgroups=cpuset=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "cpu=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "cpuacct=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "io=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "memory=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "devices=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "freezer=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "net_cls=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "perf_event=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "net_prio=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "hugetlb=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "pids=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "rdma=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "misc=/"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::vector<std::string> env = {"SHELL=/bin/bash", "PWD=/home/user", "HOME=/home/user"};
	std::string envv = test_utils::to_null_delimited(env);
	std::vector<std::string> args = {"-c", "'echo aGVsbG8K | base64 -d'"};
	std::string argsv = test_utils::to_null_delimited(args);

	std::string container = R"({"container":{"Mounts":[],"cpu_period":100000,"cpu_quota":0,"cpu_shares":1024,"cpuset_cpu_count":0,"created_time":1663770709,"env":[],"full_id":"f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066","id":"f9c7a020960a","image":"ubuntu","imagedigest":"sha256:a0d9e826ab87bd665cfc640598a871b748b4b70a01a4f3d174d4fb02adad07a9","imageid":"597ce1600cf4ac5f449b66e75e840657bb53864434d6bd82f00b172544c32ee2","imagerepo":"ubuntu","imagetag":"latest","ip":"172.17.0.2","is_pod_sandbox":false,"labels":null,"lookup_state":1,"memory_limit":0,"metadata_deadline":0,"name":"eloquent_mirzakhani","port_mappings":[],"privileged":false,"swap_limit":0,"type":0}})";

	/* Caller clone exit event.
	 * The child is in a container the caller event won't generate the child thread info
	 */
	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, (uint64_t) 1, (uint64_t) 1, (uint64_t) 0, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 12088, (uint32_t) 7208, (uint32_t) 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t) (PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID | PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS), (uint32_t) 1000, (uint32_t) 1000, (uint64_t) parent_tid, (uint64_t) parent_pid);

	/* Child clone exit event */
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, (uint64_t) 0, "bash", empty_bytebuf, child_tid, child_pid, (uint64_t) 1, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 12088, (uint32_t) 3764, (uint32_t) 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t) (PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID | PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS), (uint32_t) 1000, (uint32_t) 1000, (uint64_t) 1, (uint64_t) 1);
	add_event_advance_ts(increasing_ts(), -1, PPME_CONTAINER_JSON_2_E, 1, container.c_str());

	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t) 0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 29612, (uint32_t) 4, (uint32_t) 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, (int32_t) 34818, parent_pid, loginuid, (int32_t) PPM_EXE_UPPER_LAYER, parent_pid, parent_pid, parent_pid, exe_ino, ctime, mtime, euid);

	// check that the container has been correctly detected and the short ID is correct
	ASSERT_EQ(get_field_as_string(evt, "container.id"), "f9c7a020960a");
	// check that metadata is correctly parsed from the container event
	ASSERT_EQ(get_field_as_string(evt, "container.image"), "ubuntu");
	// check vpid reflecting container pid namespace
	ASSERT_EQ(get_field_as_string(evt, "proc.vpid"), "1");
	ASSERT_EQ(get_field_as_string(evt, "thread.vtid"), "1");
	// check more fields
	ASSERT_EQ(get_field_as_string(evt, "user.loginuid"), "-1");
	ASSERT_EQ(get_field_as_string(evt, "proc.is_exe_upper_layer"), "true");
	ASSERT_EQ(get_field_as_string(evt, "user.uid"), "4294967295");
}
#endif // MINIMAL_BUILD

TEST_F(sinsp_with_test_input, chdir_fchdir)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt *evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_CHDIR_X, 2, (int64_t) 0, "/tmp/target-directory");
	ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/tmp/target-directory/");

	// generate a fd associated with the directory we wish to change to
	int64_t dirfd = 3, test_errno = 0;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/target-directory-fd", 0, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, dirfd, "/tmp/target-directory-fd", 0, 0, 0, (uint64_t) 0);

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCHDIR_E, 1, dirfd);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCHDIR_X, 1, test_errno);
	ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/tmp/target-directory-fd/");
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
	uint64_t fdlimit = 1024, pgft_maj = 0, pgft_min = 1;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	std::vector<std::string> cgroups = {"cpuset=/", "cpu=/user.slice", "cpuacct=/user.slice", "io=/user.slice", "memory=/user.slice/user-1000.slice/session-1.scope", "devices=/user.slice", "freezer=/", "net_cls=/", "perf_event=/", "net_prio=/", "hugetlb=/", "pids=/user.slice/user-1000.slice/session-1.scope", "rdma=/", "misc=/"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::vector<std::string> env = {"SHELL=/bin/bash", "PWD=/home/user", "HOME=/home/user"};
	std::string envv = test_utils::to_null_delimited(env);
	std::vector<std::string> args = {"--help"};
	std::string argsv = test_utils::to_null_delimited(args);

	/* Parent clone exit event */
	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, parent_pid, parent_tid, (int64_t) 0, "", fdlimit, pgft_maj, pgft_min, 12088, 7208, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t) (PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID), (uint32_t) 1000, (uint32_t) 1000, parent_pid, parent_tid);

	/* Child clone exit event */
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, (int64_t) 0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", fdlimit, pgft_maj, pgft_min, 12088, 3764, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t) (PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID), (uint32_t) 1000, (uint32_t) 1000, child_vpid, child_vtid);

	/* Execve enter event */
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");

	/* Execve exit event */
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 20, (int64_t) 0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", (uint64_t) 1024, (uint64_t) 0, (uint64_t) 28, (uint32_t) 29612, (uint32_t) 4, (uint32_t) 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, (uint32_t) 34818, parent_pid, (int32_t) 1000, (uint32_t) 1);

	ASSERT_FALSE(field_has_value(evt, "proc.pid"));
	ASSERT_FALSE(field_has_value(evt, "thread.tid"));

	/* In the clone caller exit event we set `vtid=tid` and `vpid=pid` since we are never in a container. */
	ASSERT_EQ(get_field_as_string(evt, "proc.vpid"), "4294967312");
	ASSERT_EQ(get_field_as_string(evt, "thread.vtid"), "4294967312");

	// spawn a child process to verify ppid/apid
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_E, 0);

	/* Child clone exit event
	 * Please note that now we are calling the child exit event before the parent one.
	 */
	add_event_advance_ts(increasing_ts(), child2_tid, PPME_SYSCALL_CLONE_20_X, 20, (int64_t) 0, "/bin/test-exe", empty_bytebuf, child2_pid, child2_tid, child_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 12088, (uint32_t) 3764, (uint32_t) 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t) (PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID), (uint32_t) 1000, (uint32_t) 1000, child2_vpid, child2_vtid);

	/* Parent clone exit event */
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, child2_tid, "/bin/test-exe", empty_bytebuf, child_pid, child_tid, child_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 12088, (uint32_t) 7208, (uint32_t) 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t) (PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID), (uint32_t) 1000, (uint32_t) 1000, child_vpid, child_vtid);

	/* Execve enter event */
	add_event_advance_ts(increasing_ts(), child2_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe2");

	/* Execve exit event */
	evt = add_event_advance_ts(increasing_ts(), child2_tid, PPME_SYSCALL_EXECVE_19_X, 20, (int64_t) 0, "/bin/test-exe2", scap_const_sized_buffer{argsv.data(), argsv.size()}, child2_tid, child2_pid, child_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t) 29612, (uint32_t) 4, (uint32_t) 0, "test-exe2", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, (uint32_t) 34818, child_pid, (int32_t) 1000, (uint32_t) 1);

	ASSERT_FALSE(field_has_value(evt, "proc.pid"));
	ASSERT_FALSE(field_has_value(evt, "thread.tid"));
	ASSERT_FALSE(field_has_value(evt, "proc.ppid"));
	ASSERT_FALSE(field_has_value(evt, "proc.apid[1]"));

	/* Now in the clone child exit event we use vtid and vpid of the event */
	ASSERT_EQ(get_field_as_string(evt, "proc.vpid"), "3");
	ASSERT_EQ(get_field_as_string(evt, "thread.vtid"), "3");
}

TEST_F(sinsp_with_test_input, existing_proc)
{
	add_default_init_thread();

	open_inspector();

	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 1);
}

TEST_F(sinsp_with_test_input, last_exec_ts)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	uint64_t parent_pid = 1, parent_tid = 1;
	uint64_t child_pid = 0x0000000100000010, child_tid = 0x0000000100000010;
	uint64_t child_vpid = 2, child_vtid = 2;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	std::vector<std::string> cgroups = {"cpuset=/", "cpu=/user.slice", "cpuacct=/user.slice", "io=/user.slice", "memory=/user.slice/user-1000.slice/session-1.scope", "devices=/user.slice", "freezer=/", "net_cls=/", "perf_event=/", "net_prio=/", "hugetlb=/", "pids=/user.slice/user-1000.slice/session-1.scope", "rdma=/", "misc=/"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::vector<std::string> env = {"SHELL=/bin/bash", "PWD=/home/user", "HOME=/home/user"};
	std::string envv = test_utils::to_null_delimited(env);
	std::vector<std::string> args = {"--help"};
	std::string argsv = test_utils::to_null_delimited(args);
	evt = add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, parent_pid, parent_tid, 0, "", 1024, 0, 68633, 12088, 7208, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, parent_pid, parent_tid);

	ASSERT_TRUE(evt->get_thread_info());
	// Check we initialize lastexec time to zero
	ASSERT_EQ(evt->get_thread_info()->m_lastexec_ts, 0);

	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, 0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", 1024, 0, 1, 12088, 3764, 0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID, 1000, 1000, child_vpid, child_vtid);

	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");

	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 20, (int64_t) 0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", 1024, 0, 28, 29612, 4, 0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, 34818, parent_pid, 1000, 1);

	// Check last exec was recorded
	ASSERT_GT(evt->get_thread_info()->m_lastexec_ts, 0);
	// Check we execed after the last clone
	ASSERT_GT(evt->get_thread_info()->m_lastexec_ts, evt->get_thread_info()->m_clone_ts);
}
