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
#include <sys/syscall.h>
#include "../test_utils.h"
// We need to include syscall compat tables
#ifdef __x86_64__
#include "syscall_compat_x86_64.h"
#elif __aarch64__
#include "syscall_compat_aarch64.h"
#elif __s390x__
#include "syscall_compat_s390x.h"
#endif /* __x86_64__ */

/* Please note this set must be kept in sync if we update the sinsp internal state set
 * otherwise some of the following checks will fail.
 */
libsinsp::events::set<ppm_sc_code> state_sc_set_truth = {
#ifdef __NR_accept
	PPM_SC_ACCEPT,
#endif

#ifdef __NR_accept4
	PPM_SC_ACCEPT4,
#endif

#ifdef __NR_bind
	PPM_SC_BIND,
#endif

#ifdef __NR_capset
	PPM_SC_CAPSET,
#endif

#ifdef __NR_chdir
	PPM_SC_CHDIR,
#endif

#ifdef __NR_chroot
	PPM_SC_CHROOT,
#endif

#ifdef __NR_clone
	PPM_SC_CLONE,
#endif

#ifdef __NR_clone3
	PPM_SC_CLONE3,
#endif

#ifdef __NR_close
	PPM_SC_CLOSE,
#endif

#ifdef __NR_connect
	PPM_SC_CONNECT,
#endif

#ifdef __NR_creat
	PPM_SC_CREAT,
#endif

#ifdef __NR_dup
	PPM_SC_DUP,
#endif

#ifdef __NR_dup2
	PPM_SC_DUP2,
#endif

#ifdef __NR_dup3
	PPM_SC_DUP3,
#endif

#ifdef __NR_eventfd
	PPM_SC_EVENTFD,
#endif

#ifdef __NR_eventfd2
	PPM_SC_EVENTFD2,
#endif

#ifdef __NR_execve
	PPM_SC_EXECVE,
#endif

#ifdef __NR_execveat
	PPM_SC_EXECVEAT,
#endif

#ifdef __NR_fchdir
	PPM_SC_FCHDIR,
#endif

#ifdef __NR_fcntl
	PPM_SC_FCNTL,
#endif

#ifdef __NR_fcntl64
	PPM_SC_FCNTL64,
#endif

#ifdef __NR_fork
	PPM_SC_FORK,
#endif

#ifdef __NR_inotify_init
	PPM_SC_INOTIFY_INIT,
#endif

#ifdef __NR_inotify_init1
	PPM_SC_INOTIFY_INIT1,
#endif

#ifdef __NR_io_uring_setup
	PPM_SC_IO_URING_SETUP,
#endif

#ifdef __NR_mount
	PPM_SC_MOUNT,
#endif

#ifdef __NR_open
	PPM_SC_OPEN,
#endif

#ifdef __NR_open_by_handle_at
	PPM_SC_OPEN_BY_HANDLE_AT,
#endif

#ifdef __NR_openat
	PPM_SC_OPENAT,
#endif

#ifdef __NR_openat2
	PPM_SC_OPENAT2,
#endif

#ifdef __NR_pipe
	PPM_SC_PIPE,
#endif

#ifdef __NR_pipe2
	PPM_SC_PIPE2,
#endif

#ifdef __NR_prlimit64
	PPM_SC_PRLIMIT64,
#endif

#ifdef __NR_recvfrom
	PPM_SC_RECVFROM,
#endif

#ifdef __NR_recvmsg
	PPM_SC_RECVMSG,
#endif

#ifdef __NR_getsockopt
	PPM_SC_GETSOCKOPT, /// TODO: In the next future probably we could remove this from the state
#endif

#ifdef __NR_sendmsg
	PPM_SC_SENDMSG,
#endif

#ifdef __NR_sendto
	PPM_SC_SENDTO,
#endif

#ifdef __NR_setgid
	PPM_SC_SETGID,
#endif

#ifdef __NR_setgid32
	PPM_SC_SETGID32,
#endif

#ifdef __NR_setpgid
	PPM_SC_SETPGID,
#endif

#ifdef __NR_setresgid
	PPM_SC_SETRESGID,
#endif

#ifdef __NR_setresgid32
	PPM_SC_SETRESGID32,
#endif

#ifdef __NR_setresuid
	PPM_SC_SETRESUID,
#endif

#ifdef __NR_setresuid32
	PPM_SC_SETRESUID32,
#endif

#ifdef __NR_setrlimit
	PPM_SC_SETRLIMIT,
#endif

#ifdef __NR_setsid
	PPM_SC_SETSID,
#endif

#ifdef __NR_setuid
	PPM_SC_SETUID,
#endif

#ifdef __NR_setuid32
	PPM_SC_SETUID32,
#endif

#ifdef __NR_shutdown
	PPM_SC_SHUTDOWN,
#endif

#ifdef __NR_signalfd
	PPM_SC_SIGNALFD,
#endif

#ifdef __NR_signalfd4
	PPM_SC_SIGNALFD4,
#endif

#ifdef __NR_socket
	PPM_SC_SOCKET,
#endif

#ifdef __NR_socketpair
	PPM_SC_SOCKETPAIR,
#endif

#ifdef __NR_timerfd_create
	PPM_SC_TIMERFD_CREATE,
#endif

#ifdef __NR_umount
	PPM_SC_UMOUNT,
#endif

#ifdef __NR_umount2
	PPM_SC_UMOUNT2,
#endif

#ifdef __NR_userfaultfd
	PPM_SC_USERFAULTFD,
#endif

#ifdef __NR_vfork
	PPM_SC_VFORK,
#endif

#ifdef __NR_epoll_create
	PPM_SC_EPOLL_CREATE,
#endif

#ifdef __NR_epoll_create1
	PPM_SC_EPOLL_CREATE1,
#endif
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

#ifdef __NR_kill
	additional_syscalls_truth.insert(PPM_SC_KILL);
	sc_set_truth.insert(PPM_SC_KILL);
#endif

#ifdef __NR_read
	additional_syscalls_truth.insert(PPM_SC_READ);
	sc_set_truth.insert(PPM_SC_READ);
#endif

	auto sinsp_state_set = libsinsp::events::sinsp_state_sc_set();
	auto sc_set = additional_syscalls_truth.merge(sinsp_state_set);
	auto additional_syscalls = additional_syscalls_truth.diff(sinsp_state_set);

	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);
	ASSERT_PPM_SC_CODES_EQ(additional_syscalls_truth, additional_syscalls);
}

TEST(interesting_syscalls, io_sc_set)
{
	libsinsp::events::set<ppm_sc_code> io_sc_set_truth;

#ifdef __NR_read
	io_sc_set_truth.insert(PPM_SC_READ);
#endif

#ifdef __NR_recv
	io_sc_set_truth.insert(PPM_SC_RECV);
#endif

#ifdef __NR_recvfrom
	io_sc_set_truth.insert(PPM_SC_RECVFROM);
#endif

#ifdef __NR_recvmsg
	io_sc_set_truth.insert(PPM_SC_RECVMSG);
#endif

#ifdef __NR_recvmmsg
	io_sc_set_truth.insert(PPM_SC_RECVMMSG);
#endif

#ifdef __NR_readv
	io_sc_set_truth.insert(PPM_SC_READV);
#endif

#ifdef __NR_preadv
	io_sc_set_truth.insert(PPM_SC_PREADV);
#endif

#ifdef __NR_write
	io_sc_set_truth.insert(PPM_SC_WRITE);
#endif

#ifdef __NR_pwrite
	io_sc_set_truth.insert(PPM_SC_PWRITE);
#endif

#ifdef __NR_writev
	io_sc_set_truth.insert(PPM_SC_WRITEV);
#endif

#ifdef __NR_pwritev
	io_sc_set_truth.insert(PPM_SC_PWRITEV);
#endif

#ifdef __NR_sendfile
	io_sc_set_truth.insert(PPM_SC_SENDFILE);
#endif

#ifdef __NR_send
	io_sc_set_truth.insert(PPM_SC_SEND);
#endif

#ifdef __NR_sendto
	io_sc_set_truth.insert(PPM_SC_SENDTO);
#endif

#ifdef __NR_sendmsg
	io_sc_set_truth.insert(PPM_SC_SENDMSG);
#endif

#ifdef __NR_sendmmsg
	io_sc_set_truth.insert(PPM_SC_SENDMMSG);
#endif

#ifdef __NR_pread64
	io_sc_set_truth.insert(PPM_SC_PREAD64);
#endif

#ifdef __NR_pwrite64
	io_sc_set_truth.insert(PPM_SC_PWRITE64);
#endif

	auto io_sc_set = libsinsp::events::io_sc_set();
	ASSERT_PPM_SC_CODES_EQ(io_sc_set_truth, io_sc_set);
}

TEST(interesting_syscalls, all_sc_set)
{
	auto sc_set = libsinsp::events::all_sc_set();

	/* Assert that all the syscalls are taken */
	ASSERT_EQ(sc_set.size(), PPM_SC_MAX);
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
#ifdef __NR_kill
	PPM_SC_KILL,
#endif

#ifdef __NR_read
	PPM_SC_READ,
#endif

#ifdef __NR_syncfs
	PPM_SC_SYNCFS,
#endif

// s390x test issues
// #ifdef __NR_accept
// 	PPM_SC_ACCEPT,
// #endif

// #ifdef __NR_accept4
// 	PPM_SC_ACCEPT4,
// #endif

#ifdef __NR_execve
	PPM_SC_EXECVE,
#endif

#ifdef __NR_setresuid
	PPM_SC_SETRESUID,
#endif

// #ifdef __NR_setresuid32 // TOOD later after ifdef cleanup
// 	PPM_SC_SETRESUID32,
// #endif

// #ifdef __NR_eventfd
// 	PPM_SC_EVENTFD,
// #endif

#ifdef __NR_eventfd2
	PPM_SC_EVENTFD2,
#endif

// #ifdef __NR_umount
// 	PPM_SC_UMOUNT,
// #endif

#ifdef __NR_umount2
	PPM_SC_UMOUNT2,
#endif

// #ifdef __NR_pipe
// 	PPM_SC_PIPE,
// #endif

#ifdef __NR_pipe2
	PPM_SC_PIPE2,
#endif

// #ifdef __NR_signalfd
// 	PPM_SC_SIGNALFD,
// #endif

#ifdef __NR_signalfd4
	PPM_SC_SIGNALFD4
#endif
	};

	auto sc_set = libsinsp::events::names_to_sc_set(std::unordered_set<std::string>{
#ifdef __NR_kill
	"kill",
#endif

#ifdef __NR_read
	"read",
#endif

#ifdef __NR_syncfs
	"syncfs",
#endif

// #ifdef __NR_accept
// 	"accept",
// #endif

// #ifdef __NR_accept4
// 	"accept",
// #endif

#ifdef __NR_execve
	"execve",
#endif

#ifdef __NR_setresuid
	"setresuid",
#endif

#ifdef __NR_eventfd2
	"eventfd2",
#endif

#ifdef __NR_umount2
	"umount2",
#endif

#ifdef __NR_pipe2
	"pipe2",
#endif

#ifdef __NR_signalfd4
	"signalfd4",
#endif
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
#ifdef __NR_kill
	PPM_SC_KILL,
#endif

#ifdef __NR_sendto
	PPM_SC_SENDTO,
#endif
	};

	libsinsp::events::set<ppm_event_code> event_set = {
#ifdef __NR_kill
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
#endif

#ifdef __NR_sendto
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
#endif
	};

	auto sc_set = libsinsp::events::event_set_to_sc_set(event_set);
	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);
}

TEST(interesting_syscalls, event_set_to_sc_set_generic_events)
{

	libsinsp::events::set<ppm_event_code> event_set = {
#ifdef __NR_kill
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
#endif

#ifdef __NR_sendto
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
#endif

#ifdef __NR_syncfs
	PPME_GENERIC_E,
	PPME_GENERIC_X,
#endif
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
