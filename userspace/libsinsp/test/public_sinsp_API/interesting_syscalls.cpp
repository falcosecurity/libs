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

/*
 * Please note this set must be kept in sync if we update the sinsp internal state set
 * otherwise some of the following checks will fail.
 */
libsinsp::events::set<ppm_sc_code> expected_sinsp_state_ppm_sc_set = {
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
	PPM_SC_UMOUNT2,
	PPM_SC_USERFAULTFD,
	PPM_SC_VFORK,
	PPM_SC_EPOLL_CREATE,
	PPM_SC_EPOLL_CREATE1,
	PPM_SC_SYS_ENTER,
	PPM_SC_SYS_EXIT,
	PPM_SC_SCHED_PROCESS_EXIT,
	PPM_SC_SCHED_PROCESS_FORK,
	PPM_SC_SCHED_PROCESS_EXEC
};

/* This test asserts that `enforce_sinsp_state_ppm_sc` correctly retrieves
 * the `libsinsp` state ppm_sc set.
 */
TEST(interesting_syscalls, enforce_sinsp_state_basic)
{
	auto state_ppm_sc_set = libsinsp::events::sinsp_state_sc_set();
	ASSERT_EQ(expected_sinsp_state_ppm_sc_set.size(), state_ppm_sc_set.size());
	ASSERT_EQ(expected_sinsp_state_ppm_sc_set, state_ppm_sc_set);
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

	ASSERT_EQ(ppm_sc_matching_set, ppm_sc_final_set);
}

/// TODO: we can add also some tests for `enforce_io_ppm_sc_set`, `enforce_net_ppm_sc_set`, ... here.

/* This test asserts that `get_event_set_from_ppm_sc_set` correctly returns the events
 * associated with the provided `ppm_sc_set`.
 */
TEST(interesting_syscalls, get_event_set_from_ppm_sc_set)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set = {
		PPM_SC_KILL,
		PPM_SC_SENDTO,
		PPM_SC_UMOUNT, // this is generic!
		PPM_SC_UMOUNT2,
	};

	libsinsp::events::set<ppm_event_code> event_set = {
		PPME_GENERIC_E,
		PPME_GENERIC_X,
		PPME_SYSCALL_KILL_E,
		PPME_SYSCALL_KILL_X,
		PPME_SOCKET_SENDTO_E,
		PPME_SOCKET_SENDTO_X,
		PPME_SYSCALL_UMOUNT_E,
		PPME_SYSCALL_UMOUNT_X,
	};

	auto final_evt_set = libsinsp::events::sc_set_to_event_set(ppm_sc_set);

	ASSERT_EQ(final_evt_set, event_set);
}

/* This test asserts that `get_all_ppm_sc` correctly retrieves all the available syscalls
 */
TEST(interesting_syscalls, get_all_ppm_sc)
{
	auto ppm_sc_set = libsinsp::events::all_sc_set();

	/* Assert that all the syscalls are taken */
	ASSERT_EQ(ppm_sc_set.size(), PPM_SC_SYSCALL_END + PPM_SC_TP_LEN);
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
