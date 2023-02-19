/*
Copyright (C) 2022 The Falco Authors.

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
#include <arpa/inet.h>
#include <netinet/in.h>

TEST_F(sinsp_with_test_input, file_open)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	// since adding and reading events happens on a single thread they can be interleaved.
	// tests may need to change if that will not be the case anymore
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_RDWR, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t) 3, "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t) 123);

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

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/test", PPM_O_TRUNC | PPM_O_CREAT | PPM_O_WRONLY, 0666);
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, "/tmp/test", PPM_O_TRUNC | PPM_O_CREAT | PPM_O_WRONLY, 0666, 0xCA02, (uint64_t) 123);

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

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, long_path.c_str(), PPM_O_RDWR, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, long_path.c_str(), PPM_O_RDWR, 0, 5, (uint64_t) 123);
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

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_E, 3, (uint64_t) -1, NULL, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SIGNALFD_X, 1, fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "signalfd");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "s");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "5");

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
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, (int64_t) 0);
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
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_X, 4, 0, fd1, fd2, (uint64_t) 81976492);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "4");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_X, 5, 0, 6, 7, 81976492, 17);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "7");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, 12, 32);
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "12");
}

TEST_F(sinsp_with_test_input, umount)
{
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t res = 0;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT_1_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT_1_X, 2, res, "/target_name");
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "umount");
	ASSERT_EQ(get_field_as_string(evt, "evt.category"), "file");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.res"), "0");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), "/target_name");
}

TEST_F(sinsp_with_test_input, umount2)
{
    add_default_init_thread();

    open_inspector();
    sinsp_evt* evt = NULL;

    add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT2_E, 1, 10);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_UMOUNT2_X, 2, 0, "/target_name");
    ASSERT_EQ(get_field_as_string(evt, "evt.type"), "umount2");
    ASSERT_EQ(get_field_as_string(evt, "evt.category"), "file");
    ASSERT_EQ(get_field_as_string(evt, "evt.arg.res"), "0");
    ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), "/target_name");
}

TEST_F(sinsp_with_test_input, pipe)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE_X, 4, 0, 3, 4, 899);

	/* `pipe` is particular because it generates 2 file descriptors but a single event can have at most one `fdinfo` associated.
	 * So in this case the associated file descriptor is the second one (`4`). Please note that both file descriptors are added to
	 * thread info, but in the `m_fdinfo` field we find only the second file descriptor.
	 */

	/* Here we assert some info regarding the second file descriptor `4` through filter-checks */
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "4");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");
	EXPECT_THROW(get_field_as_string(evt, "fd.directory"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.filename"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.ip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.port"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rport"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "<NA>");
	EXPECT_THROW(get_field_as_string(evt, "fd.sockfamily"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "false");
	/* `14` where `1` is the thread-id and `4` is the fd */
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "14");
	ASSERT_EQ(get_field_as_string(evt, "fd.containername"), ":");
	EXPECT_THROW(get_field_as_string(evt, "fd.containerdirectory"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.proto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.net"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cnet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.snet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lnet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rnet"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.name_changed"), "false");
	EXPECT_THROW(get_field_as_string(evt, "fd.cip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rip.name"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.dev"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.major"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.minor"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "899");
	ASSERT_EQ(get_field_as_string(evt, "fd.nameraw"), "");

	sinsp_fdinfo_t* fdinfo2 = evt->get_fd_info();
	ASSERT_NE(fdinfo2, nullptr);

	/* Here we check the `openflags` field of the fdinfo2, it should be 0 since pipe has no flags */
	ASSERT_EQ(fdinfo2->m_openflags, 0);

	/* Now we get the first file descriptor (`3`) and we assert some fields directly through the `fdinfo` pointer. */
	/// TODO: @Andreagit97 it would be great to have a method to overwrite the `fdinfo` of an event.

	ASSERT_NE(evt->get_thread_info(), nullptr);
	sinsp_fdinfo_t* fdinfo1 = evt->get_thread_info()->get_fd(3);
	ASSERT_NE(fdinfo1, nullptr);
	ASSERT_STREQ(fdinfo1->get_typestring(), "pipe");
	ASSERT_EQ(fdinfo1->get_typechar(), 'p');
	ASSERT_EQ(fdinfo1->tostring_clean(), "");
	ASSERT_EQ(fdinfo1->m_name, "");
	ASSERT_EQ(fdinfo1->m_name_raw, "");
	ASSERT_EQ(fdinfo1->m_oldname, "");
	ASSERT_EQ(fdinfo1->m_openflags, 0);
	ASSERT_TRUE(fdinfo1->is_pipe());
	ASSERT_EQ(fdinfo1->get_device(), 0);
	ASSERT_EQ(fdinfo1->get_device_major(), 0);
	ASSERT_EQ(fdinfo1->get_device_minor(), 0);
	ASSERT_EQ(fdinfo1->get_ino(), 899);
}

TEST_F(sinsp_with_test_input, pipe2)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_PIPE2_X, 5, 0, 5, 6, 7479253124, 17);

	/* `pipe2` is particular because it generates 2 file descriptors but a single event can have at most one `fdinfo` associated.
	 * So in this case the associated file descriptor is the second one (`4`). Please note that both file descriptors are added to
	 * thread info, but in the `m_fdinfo` field we find only the second file descriptor.
	 */

	/* Here we assert some info regarding the second file descriptor `6` through filter-checks */
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "6");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "pipe");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "p");
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");
	EXPECT_THROW(get_field_as_string(evt, "fd.directory"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.filename"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.ip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.port"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rport"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "<NA>");
	EXPECT_THROW(get_field_as_string(evt, "fd.sockfamily"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "false");
	/* `14` where `1` is the thread-id and `6` is the fd */
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "16");
	ASSERT_EQ(get_field_as_string(evt, "fd.containername"), ":");
	EXPECT_THROW(get_field_as_string(evt, "fd.containerdirectory"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.proto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.net"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cnet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.snet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lnet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rnet"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.name_changed"), "false");
	EXPECT_THROW(get_field_as_string(evt, "fd.cip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rip.name"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.dev"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.major"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.minor"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "7479253124");
	ASSERT_EQ(get_field_as_string(evt, "fd.nameraw"), "");

	sinsp_fdinfo_t* fdinfo2 = evt->get_fd_info();
	ASSERT_NE(fdinfo2, nullptr);

	/* Here we check the `openflags` field of the fdinfo2, it should be 17 since pipe2 has flags field */
	ASSERT_EQ(fdinfo2->m_openflags, 17);

	/* Now we get the first file descriptor (`3`) and we assert some fields directly through the `fdinfo` pointer. */
	ASSERT_NE(evt->get_thread_info(), nullptr);
	sinsp_fdinfo_t* fdinfo1 = evt->get_thread_info()->get_fd(5);
	ASSERT_NE(fdinfo1, nullptr);
	ASSERT_STREQ(fdinfo1->get_typestring(), "pipe");
	ASSERT_EQ(fdinfo1->get_typechar(), 'p');
	ASSERT_EQ(fdinfo1->tostring_clean(), "");
	ASSERT_EQ(fdinfo1->m_name, "");
	ASSERT_EQ(fdinfo1->m_name_raw, "");
	ASSERT_EQ(fdinfo1->m_oldname, "");
	ASSERT_EQ(fdinfo1->m_openflags, 17);
	ASSERT_TRUE(fdinfo1->is_pipe());
	ASSERT_EQ(fdinfo1->get_device(), 0);
	ASSERT_EQ(fdinfo1->get_device_major(), 0);
	ASSERT_EQ(fdinfo1->get_device_minor(), 0);
	ASSERT_EQ(fdinfo1->get_ino(), 7479253124);
}

TEST_F(sinsp_with_test_input, inotify_init1)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_E, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_INOTIFY_INIT1_X, 2, 14, 89);

	/* Here we assert some info regarding the second file descriptor `6` through filter-checks */
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "14");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "inotify");
	ASSERT_EQ(get_field_as_string(evt, "fd.typechar"), "i");
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");
	EXPECT_THROW(get_field_as_string(evt, "fd.directory"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.filename"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.ip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rip"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.port"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lport"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rport"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "<NA>");
	EXPECT_THROW(get_field_as_string(evt, "fd.sockfamily"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.uid"), "114");
	ASSERT_EQ(get_field_as_string(evt, "fd.containername"), ":");
	EXPECT_THROW(get_field_as_string(evt, "fd.containerdirectory"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.proto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rproto"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.net"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.cnet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.snet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lnet"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rnet"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.name_changed"), "false");
	EXPECT_THROW(get_field_as_string(evt, "fd.cip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.sip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.lip.name"), sinsp_exception);
	EXPECT_THROW(get_field_as_string(evt, "fd.rip.name"), sinsp_exception);
	ASSERT_EQ(get_field_as_string(evt, "fd.dev"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.major"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.dev.minor"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.ino"), "0");
	ASSERT_EQ(get_field_as_string(evt, "fd.nameraw"), "");

	/* Here we check fields of the fdinfo directly with getter methods */
	sinsp_fdinfo_t* fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->get_typestring(), "inotify");
	ASSERT_EQ(fdinfo->get_typechar(), 'i');
	ASSERT_EQ(fdinfo->tostring_clean(), "");
	ASSERT_EQ(fdinfo->m_name, "");
	ASSERT_EQ(fdinfo->m_name_raw, "");
	ASSERT_EQ(fdinfo->m_oldname, "");
	ASSERT_EQ(fdinfo->m_openflags, 89);
	ASSERT_FALSE(fdinfo->is_pipe());
	ASSERT_EQ(fdinfo->get_device(), 0);
	ASSERT_EQ(fdinfo->get_device_major(), 0);
	ASSERT_EQ(fdinfo->get_device_minor(), 0);
	ASSERT_EQ(fdinfo->get_ino(), 0);
}
