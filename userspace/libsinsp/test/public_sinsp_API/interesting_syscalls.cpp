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
libsinsp::events::set<ppm_sc_code> expected_sinsp_state_ppm_sc_set = {
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
	PPM_SC_SYS_ENTER,
	PPM_SC_SYS_EXIT,
	PPM_SC_SCHED_PROCESS_EXIT,
	PPM_SC_SCHED_SWITCH,
	PPM_SC_SCHED_PROCESS_FORK,
	PPM_SC_SCHED_PROCESS_EXEC
};

/* This test asserts that `enforce_sinsp_state_ppm_sc` correctly retrieves
 * the `libsinsp` state ppm_sc set.
 */
TEST(interesting_syscalls, enforce_sinsp_state_basic)
{
	auto state_ppm_sc_set = libsinsp::events::sinsp_state_sc_set();

	ASSERT_TRUE(expected_sinsp_state_ppm_sc_set.equals(state_ppm_sc_set));
}

/* This test asserts that `enforce_sinsp_state_ppm_sc` correctly merges
 * the provided set with the `libsinsp` state set.
 */
TEST(interesting_syscalls, enforce_sinsp_state_with_additions)
{
	libsinsp::events::set<ppm_sc_code> additional_sc;
	auto ppm_sc_matching_set = expected_sinsp_state_ppm_sc_set;

#ifdef __NR_kill
	additional_sc.insert(PPM_SC_KILL);
	ppm_sc_matching_set.insert(PPM_SC_KILL);
#endif

#ifdef __NR_read
	additional_sc.insert(PPM_SC_READ);
	ppm_sc_matching_set.insert(PPM_SC_READ);
#endif

	additional_sc.insert(PPM_SC_PAGE_FAULT_USER);
	ppm_sc_matching_set.insert(PPM_SC_PAGE_FAULT_USER);

	auto sinsp_state_set = libsinsp::events::sinsp_state_sc_set();
	auto ppm_sc_final_set = additional_sc.merge(sinsp_state_set);

	ASSERT_TRUE(ppm_sc_matching_set.equals(ppm_sc_final_set));
}

/// TODO: we can add also some tests for `enforce_io_ppm_sc_set`, `enforce_net_ppm_sc_set`, ... here.

/* This test asserts that `get_event_set_from_ppm_sc_set` correctly returns the events
 * associated with the provided `ppm_sc_set`.
 */
TEST(interesting_syscalls, get_event_set_from_ppm_sc_set)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set = {
#ifdef __NR_kill
	PPM_SC_KILL,
#endif

#ifdef __NR_sendto
	PPM_SC_SENDTO,
#endif

#ifdef __NR_alarm
	PPM_SC_ALARM,
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

#ifdef __NR_alarm
	PPME_GENERIC_E,
	PPME_GENERIC_X,
#endif
	};

	auto final_evt_set = libsinsp::events::sc_set_to_event_set(ppm_sc_set);

	ASSERT_TRUE(final_evt_set.equals(event_set));
}

/* This test asserts that `get_all_ppm_sc` correctly retrieves all the available syscalls
 */
TEST(interesting_syscalls, get_all_ppm_sc)
{
	auto ppm_sc_set = libsinsp::events::all_sc_set();

	/* Assert that all the syscalls are taken */
	ASSERT_EQ(ppm_sc_set.size(), PPM_SC_MAX);
}

/* This test asserts that `get_syscalls_names` correctly retrieves all the syscalls names
 */
TEST(interesting_syscalls, get_sc_names)
{
	std::set<std::string> orderd_sc_names_matching_set;
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;

	/* Here we don't need ifdefs, our ppm_sc codes are always defined. */
	ppm_sc_set.insert(PPM_SC_KILL);
	orderd_sc_names_matching_set.insert("kill");

	ppm_sc_set.insert(PPM_SC_READ);
	orderd_sc_names_matching_set.insert("read");

	ppm_sc_set.insert(PPM_SC_SYS_ENTER);
	orderd_sc_names_matching_set.insert("sys_enter");

	ppm_sc_set.insert(PPM_SC_SCHED_PROCESS_FORK);
	orderd_sc_names_matching_set.insert("sched_process_fork");

	auto syscall_names_final_set = libsinsp::events::sc_set_to_names(ppm_sc_set);

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(orderd_sc_names_matching_set.size(), syscall_names_final_set.size());

	auto ordered_syscall_names_final_set = test_utils::unordered_set_to_ordered(syscall_names_final_set);

	auto final = ordered_syscall_names_final_set.begin();
	auto matching = orderd_sc_names_matching_set.begin();

	for(; final != ordered_syscall_names_final_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}

/* This test asserts that `get_events_names` correctly retrieves all the events names
 */
TEST(interesting_syscalls, get_events_names)
{
	std::set<std::string> orderd_events_names_matching_set;
	libsinsp::events::set<ppm_event_code> events_set;

	/* Here we don't need ifdefs, our events are always defined. */
	events_set.insert(PPME_SYSCALL_KILL_E);
	events_set.insert(PPME_SYSCALL_KILL_X);
	/* Please note the name of the 2 events should be the same: "kill" */
	orderd_events_names_matching_set.insert("kill");

	events_set.insert(PPME_SYSCALL_DUP_1_E);
	events_set.insert(PPME_SYSCALL_DUP_1_X);
	orderd_events_names_matching_set.insert("dup");

	auto events_names_final_set = libsinsp::events::event_set_to_names(events_set);

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(events_names_final_set.size(), orderd_events_names_matching_set.size());

	auto ordered_events_names_final_set = test_utils::unordered_set_to_ordered(events_names_final_set);

	auto final = ordered_events_names_final_set.begin();
	auto matching = orderd_events_names_matching_set.begin();

	for(; final != ordered_events_names_final_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}
