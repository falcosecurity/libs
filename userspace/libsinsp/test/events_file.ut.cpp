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
#include <arpa/inet.h>
#include <netinet/in.h>

#define ASSERT_FD_FILTER_CHECK_NOT_FILE()                                \
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");              \
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "<NA>");       \
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "false");    \
	ASSERT_EQ(get_field_as_string(evt, "fd.containername"), ":");    \
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");    \
	ASSERT_EQ(get_field_as_string(evt, "fd.name_changed"), "false"); \
	ASSERT_EQ(get_field_as_string(evt, "fd.dev"), "0");              \
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.major"), "0");        \
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.minor"), "0");        \
	ASSERT_EQ(get_field_as_string(evt, "fd.nameraw"), "");

#define ASSERT_FD_GETTERS_NOT_FILE(x)        \
	ASSERT_EQ(x->m_name, "");            \
	ASSERT_EQ(x->m_name_raw, "");        \
	ASSERT_EQ(x->m_oldname, "");         \
	ASSERT_EQ(x->get_device(), 0);       \
	ASSERT_EQ(x->tostring_clean(), "");  \
	ASSERT_EQ(x->get_device_major(), 0); \
	ASSERT_EQ(x->get_device_minor(), 0); \
	ASSERT_FALSE(x->is_unix_socket());   \
	ASSERT_FALSE(x->is_ipv4_socket());   \
	ASSERT_FALSE(x->is_ipv6_socket());   \
	ASSERT_FALSE(x->is_udp_socket());    \
	ASSERT_FALSE(x->is_tcp_socket());    \
	ASSERT_FALSE(x->is_file());          \
	ASSERT_FALSE(x->is_directory());

TEST_F(sinsp_with_test_input, file_open)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	// since adding and reading events happens on a single thread they can be interleaved.
	// tests may need to change if that will not be the case anymore
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", (uint32_t) PPM_O_RDWR, (uint32_t) 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file", (uint32_t) PPM_O_RDWR, (uint32_t) 0, (uint32_t) 5, (uint64_t)123);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"), "/tmp");
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"), "the_file");
}

TEST_F(sinsp_with_test_input, dup_dup2_dup3)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t fd = 3, res = 1, oldfd = 3, newfd = 123;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/test", (uint32_t) (PPM_O_TRUNC | PPM_O_CREAT | PPM_O_WRONLY), (uint32_t) 0666);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, "/tmp/test", (uint32_t) (PPM_O_TRUNC | PPM_O_CREAT | PPM_O_WRONLY), (uint32_t) 0666, (uint32_t) 0xCA02, (uint64_t)123);

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_E, 1, fd);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_X, 1, newfd);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "123");

	res = 123;
	oldfd = 1;
	newfd = 123;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP2_E, 1, fd);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP2_X, 3, res, oldfd, newfd);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "123");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP3_E, 1, fd);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP3_X, 4, res, oldfd, newfd, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "123");

	res = 1;
	oldfd = 3;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_1_E, 1, fd);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_DUP_1_X, 2, res, oldfd);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "1");
}

TEST_F(sinsp_with_test_input, open_by_handle_at)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t fd = 4, mountfd = 5;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, fd, mountfd, PPM_O_RDWR, "/tmp/the_file.txt");

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file.txt");
	ASSERT_EQ(get_field_as_string(evt, "evt.abspath"), "/tmp/the_file.txt");

	fd = 6;
	mountfd = 7;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, fd, mountfd, PPM_O_RDWR, "<NA>");

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
	int64_t fd = 3, mountfd = 5;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, long_path.c_str(), (uint32_t) PPM_O_RDWR, (uint32_t) 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, long_path.c_str(), (uint32_t) PPM_O_RDWR, (uint32_t) 0, (uint32_t) 5, (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");

	fd = 4;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 4, fd, mountfd, PPM_O_RDWR, long_path.c_str());

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");
	ASSERT_EQ(get_field_as_string(evt, "evt.abspath"), "/PATH_TOO_LONG");
}

TEST_F(sinsp_with_test_input, creates_fd_generic)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t fd = 5;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_E, 3, (uint64_t)-1, NULL, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "signalfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "s");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "5");

	fd = 2;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD4_E, 2, (uint64_t)0, (uint32_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD4_X, 2, fd, (uint16_t)67);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "signalfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "s");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "2");

	fd = 6;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_TIMERFD_CREATE_E, 2, 0, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_TIMERFD_CREATE_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "timerfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "t");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "6");

	fd = 7;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "7");

	fd = 8;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, (int64_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "bpf");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "b");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "8");

	fd = 9;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_USERFAULTFD_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_USERFAULTFD_X, 2, fd, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "userfaultfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "u");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "9");

	fd = 10;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_IO_URING_SETUP_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_IO_URING_SETUP_X, 8, fd, 0, 0, 0, 0, 0, 0, 0);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "io_uring");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "r");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "10");

	fd = 11;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "eventpoll");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "l");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "11");

	fd = 12;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE1_E, 1, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE1_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "eventpoll");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "l");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "12");

	int64_t fd1 = 3, fd2 = 4;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_X, 4, (int64_t) 0, fd1, fd2, (uint64_t)81976492);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "4");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_X, 5, (int64_t) 0, (int64_t)6, (int64_t)7, (uint64_t)81976492, (uint32_t)17);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "7");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, (int64_t)12, (uint16_t)32);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "12");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD_E, 2, (uint64_t)0, (uint16_t)45);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD_X, 1, (int64_t)34);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "event");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "e");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "34");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD2_E, 1, (uint64_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD2_X, 2, (int64_t)31, (uint16_t)34);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "event");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "e");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "31");
}

TEST_F(sinsp_with_test_input, umount)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 0;
	const char* name = "/target_name";

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT_1_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT_1_X, 2, res, name);
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "umount");
	ASSERT_EQ(get_field_as_string(evt, "evt.category"), "file");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.res"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), name);

	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_EQ(fdinfo, nullptr);
}

TEST_F(sinsp_with_test_input, umount2)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;
	uint32_t flags = 10;
	int64_t res = 0;
	const char* name = "/target_name";

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT2_E, 1, flags);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT2_X, 2, res, name);
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "umount2");
	ASSERT_EQ(get_field_as_string(evt, "evt.category"), "file");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.res"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), name);

	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_EQ(fdinfo, nullptr);
}

TEST_F(sinsp_with_test_input, pipe)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t res = 0;
	int64_t fd1 = 3, fd2 = 4;
	uint64_t ino = 7479253124;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_X, 4, res, fd1, fd2, ino);

	/* `pipe` is particular because it generates 2 file descriptors but a single event can have at most one `fdinfo` associated.
	 * So in this case the associated file descriptor is the second one (`4`). Please note that both file descriptors are added to
	 * thread info, but in the `m_fdinfo` field we find only the second file descriptor.
	 */

	/* Here we assert some info regarding the second file descriptor `4` through filter-checks */
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(fd2));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	/* `14` where `1` is the thread-id and `4` is the fd */
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "14");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), std::to_string(ino));
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check the `openflags` field of the fdinfo2, it should be 0 since pipe has no flags */
	sinsp_fdinfo* fdinfo2 = evt->get_fd_info();
	ASSERT_NE(fdinfo2, nullptr);
	ASSERT_EQ(fdinfo2->m_openflags, 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo2)

	/* Now we get the first file descriptor (`3`) and we assert some fields directly through the `fdinfo` pointer. */

	ASSERT_NE(evt->get_thread_info(), nullptr);
	sinsp_fdinfo* fdinfo1 = evt->get_thread_info()->get_fd(fd1);
	ASSERT_NE(fdinfo1, nullptr);
	ASSERT_STREQ(fdinfo1->get_typestring(), "pipe");
	ASSERT_EQ(fdinfo1->get_typechar(), 'p');
	ASSERT_EQ(fdinfo1->m_openflags, 0);
	ASSERT_TRUE(fdinfo1->is_pipe());
	ASSERT_EQ(fdinfo1->get_ino(), ino);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo1)
}

TEST_F(sinsp_with_test_input, pipe2)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t res = 0;
	int64_t fd1 = 5, fd2 = 6;
	uint64_t ino = 7479253124;
	uint32_t flags = 17;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_X, 5, res, fd1, fd2, ino, flags);

	/* `pipe2` is particular because it generates 2 file descriptors but a single event can have at most one `fdinfo` associated.
	 * So in this case the associated file descriptor is the second one (`4`). Please note that both file descriptors are added to
	 * thread info, but in the `m_fdinfo` field we find only the second file descriptor.
	 */

	/* Here we assert some info regarding the second file descriptor `6` through filter-checks */
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(fd2));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	/* `16` where `1` is the thread-id and `6` is the fd */
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "16");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), std::to_string(ino));
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check the `openflags` field of the fdinfo2, it should be 17 since pipe2 has flags field */
	sinsp_fdinfo* fdinfo2 = evt->get_fd_info();
	ASSERT_NE(fdinfo2, nullptr);
	ASSERT_EQ(fdinfo2->m_openflags, flags);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo2)

	/* Now we get the first file descriptor (`3`) and we assert some fields directly through the `fdinfo` pointer. */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	sinsp_fdinfo* fdinfo1 = evt->get_thread_info()->get_fd(fd1);
	ASSERT_NE(fdinfo1, nullptr);
	ASSERT_STREQ(fdinfo1->get_typestring(), "pipe");
	ASSERT_EQ(fdinfo1->get_typechar(), 'p');
	ASSERT_EQ(fdinfo1->m_openflags, flags);
	ASSERT_TRUE(fdinfo1->is_pipe());
	ASSERT_EQ(fdinfo1->get_ino(), ino);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo1)
}

TEST_F(sinsp_with_test_input, inotify_init)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 15;
	uint8_t flags = 79;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT_E, 1, flags);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT_X, 1, res);

	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "115");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "inotify");
	ASSERT_EQ(fdinfo->get_typechar(), 'i');
	/* In the parsers we don't set any flags in the fdinfo */
	ASSERT_EQ(fdinfo->m_openflags, 0);
	ASSERT_EQ(fdinfo->get_ino(), 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo)
}

TEST_F(sinsp_with_test_input, inotify_init1)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 14;
	uint16_t flags = 89;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, res, flags);

	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "114");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "inotify");
	ASSERT_EQ(fdinfo->get_typechar(), 'i');
	ASSERT_EQ(fdinfo->m_openflags, flags);
	ASSERT_EQ(fdinfo->get_ino(), 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo)
}

TEST_F(sinsp_with_test_input, eventfd)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 21;
	uint16_t flags = 6;
	uint64_t initval = 0;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD_E, 2, initval, flags);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD_X, 1, res);

	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "event");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "e");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "121");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "event");
	ASSERT_EQ(fdinfo->get_typechar(), 'e');
	/* In the parsers we don't set any flags in the fdinfo */
	ASSERT_EQ(fdinfo->m_openflags, 0);
	ASSERT_EQ(fdinfo->get_ino(), 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo)
}

TEST_F(sinsp_with_test_input, eventfd2)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 22;
	uint16_t flags = 54;
	uint64_t initval = 0;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD2_E, 1, initval);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EVENTFD2_X, 2, res, flags);

	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "event");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "e");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "122");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "event");
	ASSERT_EQ(fdinfo->get_typechar(), 'e');
	ASSERT_EQ(fdinfo->m_openflags, flags);
	ASSERT_EQ(fdinfo->get_ino(), 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo)
}

TEST_F(sinsp_with_test_input, signalfd)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 5;
	int64_t fd = -1;
	uint32_t mask = 0;
	uint8_t flags = 12;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_E, 3, fd, mask, flags);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_X, 1, res);

	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "signalfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "s");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "15");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "signalfd");
	ASSERT_EQ(fdinfo->get_typechar(), 's');
	ASSERT_EQ(fdinfo->m_openflags, 0);
	ASSERT_EQ(fdinfo->get_ino(), 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo)
}

TEST_F(sinsp_with_test_input, signalfd4)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t res = 5;
	int64_t fd = -1;
	uint32_t mask = 0;
	uint16_t flags = 47;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD4_E, 2, fd, mask);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD4_X, 2, res, flags);

	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(res));
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "signalfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "s");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "15");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_FD_FILTER_CHECK_NOT_FILE()

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "signalfd");
	ASSERT_EQ(fdinfo->get_typechar(), 's');
	ASSERT_EQ(fdinfo->m_openflags, flags);
	ASSERT_EQ(fdinfo->get_ino(), 0);
	ASSERT_FD_GETTERS_NOT_FILE(fdinfo)
}

TEST_F(sinsp_with_test_input, fchmod)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	const char *path = "/tmp/test";
	int64_t fd = 3;
	int32_t flags = PPM_O_RDWR;
	uint32_t mode = 0;
	uint32_t dev = 0;
	uint64_t ino = 0;

	int64_t res = 0;

	// We need to open a fd first so fchmod can act on it
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, path, flags, mode, dev, ino);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "3");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCHMOD_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCHMOD_X, 3, res, fd, mode);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "3");
}

TEST_F(sinsp_with_test_input, fchown)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	const char *path = "/tmp/test";
	int64_t fd = 3;
	int32_t flags = PPM_O_RDWR;
	uint32_t mode = 0;
	uint32_t dev = 0;
	uint64_t ino = 0;

	int64_t res = 0;
	uint32_t uid = 0;
	uint32_t gid = 0;

	// We need to open a fd first so fchmod can act on it
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, path, flags, mode, dev, ino);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "3");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCHOWN_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_FCHOWN_X, 4, res, fd, uid, gid);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/test");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "3");
}

TEST_F(sinsp_with_test_input, memfd_create)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	const char *name = "test_name";
	int64_t fd = 4;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_MEMFD_CREATE_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_MEMFD_CREATE_X, 3, fd, name, 0);
	
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_MEMFD_CREATE_X);
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), std::to_string(fd));
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), name);
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "m"); 
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "memfd");

}

TEST_F(sinsp_with_test_input, test_fdtypes)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	// since adding and reading events happens on a single thread they can be interleaved.
	// tests may need to change if that will not be the case anymore
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", (uint32_t) PPM_O_RDWR, (uint32_t) 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t) 1, "/tmp/the_file", (uint32_t) PPM_O_RDWR, (uint32_t) 0, (uint32_t) 5, (uint64_t) 123);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_X);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "1");
	ASSERT_EQ(get_field_as_string(evt, "fd.types[1]"), "(file)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(file)");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, (int64_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_X, 1, (int64_t)2);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_BPF_2_X);
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "2");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "bpf");
	ASSERT_EQ(get_field_as_string(evt, "fd.types[1]"), "(file)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types[2]"), "(bpf)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(bpf,file)");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, (int64_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_X, 1, (int64_t)3);

	ASSERT_EQ(get_field_as_string(evt, "fd.types[3]"), "(bpf)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(bpf,file)");
}

TEST_F(sinsp_with_test_input, test_pidfd)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t pidfd = 1;
	int64_t pid = 2;
	int64_t target_fd = 3;
	int64_t fd = 4;

	/* Open a file descriptor */
	add_event_advance_ts(increasing_ts(), pid, PPME_SYSCALL_OPEN_X, 6, (uint64_t)target_fd, "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t)123);


	/* Create a pidfd using the same pid */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIDFD_OPEN_X, 3, pidfd, pid, 0);
	
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_PIDFD_OPEN_X);
	ASSERT_EQ(get_field_as_string(evt,"fd.num"), std::to_string(pidfd));
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"),"P");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"),"pidfd");

	/* Duplicate the created fd created that is refrenced in pidfd */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIDFD_GETFD_X, 4, fd, pidfd, target_fd, 0);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_PIDFD_GETFD_X);
	ASSERT_EQ(get_field_as_string(evt,"fd.num"), std::to_string(fd));
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"), "/tmp");
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"), "the_file");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"),"f");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"),"file");
}
