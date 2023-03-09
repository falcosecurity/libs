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
#include <sinsp.h>
#include "../test_utils.h"

/*
 * Please note this set must be kept in sync if we update the sinsp internal state set
 * otherwise some of the following checks will fail.
 */
libsinsp::events::set<ppm_sc_code> state_sc_set_truth = {
	PPM_SC_ACCEPT,
	PPM_SC_ACCEPT4,
	PPM_SC_BIND,
	PPM_SC_CAPSET,
	PPM_SC_CHDIR,
	PPM_SC_CHROOT,
	PPM_SC_CLONE,
	PPM_SC_CLONE3,
	PPM_SC_CLOSE,
	PPM_SC_CONNECT,
	PPM_SC_CREAT,
	PPM_SC_DUP,
	PPM_SC_DUP2,
	PPM_SC_DUP3,
	PPM_SC_EVENTFD,
	PPM_SC_EVENTFD2,
	PPM_SC_EXECVE,
	PPM_SC_EXECVEAT,
	PPM_SC_FCHDIR,
	PPM_SC_FCNTL,
	PPM_SC_FCNTL64,
	PPM_SC_FORK,
	PPM_SC_INOTIFY_INIT,
	PPM_SC_INOTIFY_INIT1,
	PPM_SC_IO_URING_SETUP,
	PPM_SC_MOUNT,
	PPM_SC_OPEN,
	PPM_SC_OPEN_BY_HANDLE_AT,
	PPM_SC_OPENAT,
	PPM_SC_OPENAT2,
	PPM_SC_PIPE,
	PPM_SC_PIPE2,
	PPM_SC_PRLIMIT64,
	PPM_SC_RECVFROM,
	PPM_SC_RECVMSG,
	PPM_SC_GETSOCKOPT,
	PPM_SC_SENDMSG,
	PPM_SC_SENDTO,
	PPM_SC_SETGID,
	PPM_SC_SETGID32,
	PPM_SC_SETPGID,
	PPM_SC_SETRESGID,
	PPM_SC_SETRESGID32,
	PPM_SC_SETRESUID,
	PPM_SC_SETRESUID32,
	PPM_SC_SETRLIMIT,
	PPM_SC_SETSID,
	PPM_SC_SETUID,
	PPM_SC_SETUID32,
	PPM_SC_SHUTDOWN,
	PPM_SC_SIGNALFD,
	PPM_SC_SIGNALFD4,
	PPM_SC_SOCKET,
	PPM_SC_SOCKETPAIR,
	PPM_SC_TIMERFD_CREATE,
	PPM_SC_UMOUNT,
	PPM_SC_UMOUNT2,
	PPM_SC_USERFAULTFD,
	PPM_SC_VFORK,
	PPM_SC_EPOLL_CREATE,
	PPM_SC_EPOLL_CREATE1,
	// TODO PPM_SC_SCHED_PROCESS_EXIT,
};

TEST(interesting_syscalls, sinsp_state_sc_set)
{
	auto state_sc_set = libsinsp::events::sinsp_state_sc_set();
	ASSERT_PPM_SC_CODES_EQ(state_sc_set_truth, state_sc_set);
}

TEST(interesting_syscalls, sinsp_state_sc_set_additional_syscalls)
{
	libsinsp::events::set<ppm_sc_code> additional_syscalls_truth;
	auto sc_set_truth = state_sc_set_truth;

	additional_syscalls_truth.insert(PPM_SC_KILL);
	sc_set_truth.insert(PPM_SC_KILL);

	additional_syscalls_truth.insert(PPM_SC_READ);
	sc_set_truth.insert(PPM_SC_READ);

	auto sinsp_state_set = libsinsp::events::sinsp_state_sc_set();
	auto sc_set = additional_syscalls_truth.merge(sinsp_state_set);
	auto additional_syscalls = additional_syscalls_truth.diff(sinsp_state_set);

	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);
	ASSERT_PPM_SC_CODES_EQ(additional_syscalls_truth, additional_syscalls);
}

TEST(interesting_syscalls, io_sc_set)
{
	libsinsp::events::set<ppm_sc_code> io_sc_set_truth;

	io_sc_set_truth.insert(PPM_SC_READ);
	io_sc_set_truth.insert(PPM_SC_RECVFROM);
	io_sc_set_truth.insert(PPM_SC_RECVMSG);
	io_sc_set_truth.insert(PPM_SC_RECVMMSG);
	io_sc_set_truth.insert(PPM_SC_READV);
	io_sc_set_truth.insert(PPM_SC_PREADV);
	io_sc_set_truth.insert(PPM_SC_WRITE);
	io_sc_set_truth.insert(PPM_SC_WRITEV);
	io_sc_set_truth.insert(PPM_SC_PWRITEV);
	io_sc_set_truth.insert(PPM_SC_SENDFILE);
	io_sc_set_truth.insert(PPM_SC_SENDTO);
	io_sc_set_truth.insert(PPM_SC_SENDMSG);
	io_sc_set_truth.insert(PPM_SC_SENDMMSG);
	io_sc_set_truth.insert(PPM_SC_PREAD64);
	io_sc_set_truth.insert(PPM_SC_PWRITE64);

	auto io_sc_set = libsinsp::events::io_sc_set();
	ASSERT_PPM_SC_CODES_EQ(io_sc_set_truth, io_sc_set);
}

TEST(interesting_syscalls, all_sc_set)
{
	auto sc_set = libsinsp::events::all_sc_set();

	/*
	 * Assert that all the syscalls are taken
	 * -> note: since some PPM_SC might be skipped because unused,
	 * max size might be lower than PPM_SC_MAX.
	 */
	ASSERT_TRUE(sc_set.size() <= PPM_SC_MAX);
}

TEST(interesting_syscalls, sc_set_to_names)
{
	// "syncfs" is a generic event / syscall
	static std::set<std::string> names_truth = {"kill", "read", "syncfs"};
	static libsinsp::events::set<ppm_sc_code> sc_set = {PPM_SC_KILL, PPM_SC_READ, PPM_SC_SYNCFS};
	auto names = test_utils::unordered_set_to_ordered(libsinsp::events::sc_set_to_names(sc_set));
	ASSERT_NAMES_EQ(names_truth, names);
}

TEST(interesting_syscalls, names_to_sc_set)
{
	static libsinsp::events::set<ppm_sc_code> sc_set_truth = {
	PPM_SC_KILL,
	PPM_SC_READ,
	PPM_SC_SYNCFS,
	PPM_SC_ACCEPT,
 	PPM_SC_ACCEPT4,
	PPM_SC_EXECVE,
	PPM_SC_SETRESUID,
 	PPM_SC_SETRESUID32,
 	PPM_SC_EVENTFD,
	PPM_SC_EVENTFD2,
 	PPM_SC_UMOUNT,
	PPM_SC_UMOUNT2,
 	PPM_SC_PIPE,
	PPM_SC_PIPE2,
 	PPM_SC_SIGNALFD,
	PPM_SC_SIGNALFD4
	};

	auto sc_set = libsinsp::events::names_to_sc_set(std::unordered_set<std::string>{
	"kill",
	"read",
	"syncfs",
 	"accept",
 	"accept4",
	"execve",
	"setresuid",
	"eventfd",
	"eventfd2",
	"umount",
	"umount2",
	"pipe",
	"pipe2",
	"signalfd",
	"signalfd4",
	});
	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);

	static std::unordered_set<std::string> sc_set_names_truth = {"accept",
	"accept4", "execve", "syncfs", "eventfd", "eventfd2", "umount", "umount2",
	"pipe", "pipe2", "signalfd", "signalfd4"};
	auto tmp_sc_set = libsinsp::events::names_to_sc_set(std::unordered_set<std::string>{"accept",
	"execve", "syncfs", "eventfd", "umount", "pipe", "signalfd"});
	auto sc_set_names = libsinsp::events::sc_set_to_names(tmp_sc_set);
	ASSERT_NAMES_EQ(sc_set_names_truth, sc_set_names);
}

TEST(interesting_syscalls, event_set_to_sc_set)
{
	libsinsp::events::set<ppm_sc_code> sc_set_truth = {
	PPM_SC_KILL,
	PPM_SC_SENDTO,
	};

	libsinsp::events::set<ppm_event_code> event_set = {
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
	};

	auto sc_set = libsinsp::events::event_set_to_sc_set(event_set);
	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);
}

TEST(interesting_syscalls, event_set_to_sc_set_generic_events)
{

	libsinsp::events::set<ppm_event_code> event_set = {
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
	PPME_GENERIC_E,
	PPME_GENERIC_X,
	};

	auto sc_set = libsinsp::events::event_set_to_sc_set(event_set);
	ASSERT_GT(sc_set.size(), 180);
	ASSERT_TRUE(sc_set.contains(PPM_SC_SYNCFS));
	ASSERT_TRUE(sc_set.contains(PPM_SC_KILL));
	ASSERT_TRUE(sc_set.contains(PPM_SC_SENDTO));
	/* Random checks for some generic sc events. */
	ASSERT_TRUE(sc_set.contains(PPM_SC_PERF_EVENT_OPEN));
	ASSERT_TRUE(sc_set.contains(PPM_SC_GETSID));
	ASSERT_TRUE(sc_set.contains(PPM_SC_INIT_MODULE));
	ASSERT_TRUE(sc_set.contains(PPM_SC_READLINKAT));
}
