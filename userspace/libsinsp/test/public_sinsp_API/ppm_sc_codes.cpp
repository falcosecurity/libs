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
#include <libsinsp/sinsp.h>
#include "../test_utils.h"

// This is loaded in the first test
static libsinsp::events::set<ppm_sc_code> sinsp_generic_syscalls_set;

#define GENERIC_SYSCALLS_NUM (sinsp_generic_syscalls_set.size())

/*
 * Please note these sets must be kept in sync if we update the sinsp internal state set
 * otherwise some of the following checks will fail.
 */
const libsinsp::events::set<ppm_event_code> expected_sinsp_state_event_set = {
	PPME_SOCKET_ACCEPT_E,
	PPME_SOCKET_ACCEPT_X,
	PPME_SOCKET_ACCEPT_5_E,
	PPME_SOCKET_ACCEPT_5_X,
	PPME_SOCKET_ACCEPT4_E,
	PPME_SOCKET_ACCEPT4_X,
	PPME_SOCKET_ACCEPT4_5_E,
	PPME_SOCKET_ACCEPT4_5_X,
	PPME_SOCKET_BIND_E,
	PPME_SOCKET_BIND_X,
	PPME_SYSCALL_CAPSET_E,
	PPME_SYSCALL_CAPSET_X,
	PPME_SYSCALL_CHDIR_E,
	PPME_SYSCALL_CHDIR_X,
	PPME_SYSCALL_CHROOT_E,
	PPME_SYSCALL_CHROOT_X,
	PPME_SYSCALL_CLONE3_E,
	PPME_SYSCALL_CLONE3_X,
	PPME_SYSCALL_CLONE_11_E,
	PPME_SYSCALL_CLONE_11_X,
	PPME_SYSCALL_CLONE_16_E,
	PPME_SYSCALL_CLONE_16_X,
	PPME_SYSCALL_CLONE_17_E,
	PPME_SYSCALL_CLONE_17_X,
	PPME_SYSCALL_CLONE_20_E,
	PPME_SYSCALL_CLONE_20_X,
	PPME_SYSCALL_CLOSE_E,
	PPME_SYSCALL_CLOSE_X,
	PPME_SOCKET_CONNECT_E,
	PPME_SOCKET_CONNECT_X,
	PPME_SYSCALL_CREAT_E,
	PPME_SYSCALL_CREAT_X,
	PPME_SYSCALL_DUP_E,
	PPME_SYSCALL_DUP_X,
	PPME_SYSCALL_DUP_1_E,
	PPME_SYSCALL_DUP_1_X,
	PPME_SYSCALL_DUP2_E,
	PPME_SYSCALL_DUP2_X,
	PPME_SYSCALL_DUP3_E,
	PPME_SYSCALL_DUP3_X,
	PPME_SYSCALL_EVENTFD_E,
	PPME_SYSCALL_EVENTFD_X,
	PPME_SYSCALL_EXECVE_8_E,
	PPME_SYSCALL_EXECVE_8_X,
	PPME_SYSCALL_EXECVE_13_E,
	PPME_SYSCALL_EXECVE_13_X,
	PPME_SYSCALL_EXECVE_14_E,
	PPME_SYSCALL_EXECVE_14_X,
	PPME_SYSCALL_EXECVE_15_E,
	PPME_SYSCALL_EXECVE_15_X,
	PPME_SYSCALL_EXECVE_16_E,
	PPME_SYSCALL_EXECVE_16_X,
	PPME_SYSCALL_EXECVE_17_E,
	PPME_SYSCALL_EXECVE_17_X,
	PPME_SYSCALL_EXECVE_18_E,
	PPME_SYSCALL_EXECVE_18_X,
	PPME_SYSCALL_EXECVE_19_E,
	PPME_SYSCALL_EXECVE_19_X,
	PPME_SYSCALL_EXECVEAT_E,
	PPME_SYSCALL_EXECVEAT_X,
	PPME_SYSCALL_FCHDIR_E,
	PPME_SYSCALL_FCHDIR_X,
	PPME_SYSCALL_FCNTL_E,
	PPME_SYSCALL_FCNTL_X,
	PPME_SYSCALL_FORK_E,
	PPME_SYSCALL_FORK_X,
	PPME_SYSCALL_FORK_17_E,
	PPME_SYSCALL_FORK_17_X,
	PPME_SYSCALL_FORK_20_E,
	PPME_SYSCALL_FORK_20_X,
	PPME_SYSCALL_INOTIFY_INIT_E,
	PPME_SYSCALL_INOTIFY_INIT_X,
	PPME_SYSCALL_IO_URING_SETUP_E,
	PPME_SYSCALL_IO_URING_SETUP_X,
	PPME_SYSCALL_MOUNT_E,
	PPME_SYSCALL_MOUNT_X,
	PPME_SYSCALL_OPEN_E,
	PPME_SYSCALL_OPEN_X,
	PPME_SYSCALL_OPEN_BY_HANDLE_AT_E,
	PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	PPME_SYSCALL_OPENAT_E,
	PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E,
	PPME_SYSCALL_OPENAT_2_X,
	PPME_SYSCALL_OPENAT2_E,
	PPME_SYSCALL_OPENAT2_X,
	PPME_SYSCALL_PIPE_E,
	PPME_SYSCALL_PIPE_X,
	PPME_SYSCALL_PRLIMIT_E,
	PPME_SYSCALL_PRLIMIT_X,
	PPME_SOCKET_RECVFROM_E,
	PPME_SOCKET_RECVFROM_X,
	PPME_SOCKET_RECVMSG_E,
	PPME_SOCKET_RECVMSG_X,
	PPME_SOCKET_GETSOCKOPT_E,
	PPME_SOCKET_GETSOCKOPT_X,
	PPME_SOCKET_SENDMSG_E,
	PPME_SOCKET_SENDMSG_X,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
	PPME_SYSCALL_SETGID_E,
	PPME_SYSCALL_SETGID_X,
	PPME_SYSCALL_SETPGID_E,
	PPME_SYSCALL_SETPGID_X,
	PPME_SYSCALL_SETRESGID_E,
	PPME_SYSCALL_SETRESGID_X,
	PPME_SYSCALL_SETRESUID_E,
	PPME_SYSCALL_SETRESUID_X,
	PPME_SYSCALL_SETRLIMIT_E,
	PPME_SYSCALL_SETRLIMIT_X,
	PPME_SYSCALL_SETSID_E,
	PPME_SYSCALL_SETSID_X,
	PPME_SYSCALL_SETUID_E,
	PPME_SYSCALL_SETUID_X,
	PPME_SOCKET_SHUTDOWN_E,
	PPME_SOCKET_SHUTDOWN_X,
	PPME_SYSCALL_SIGNALFD_E,
	PPME_SYSCALL_SIGNALFD_X,
	PPME_SOCKET_SOCKET_E,
	PPME_SOCKET_SOCKET_X,
	PPME_SOCKET_SOCKETPAIR_E,
	PPME_SOCKET_SOCKETPAIR_X,
	PPME_SYSCALL_TIMERFD_CREATE_E,
	PPME_SYSCALL_TIMERFD_CREATE_X,
	PPME_SYSCALL_UMOUNT_E,
	PPME_SYSCALL_UMOUNT_X,
	PPME_SYSCALL_USERFAULTFD_E,
	PPME_SYSCALL_USERFAULTFD_X,
	PPME_SYSCALL_VFORK_E,
	PPME_SYSCALL_VFORK_X,
	PPME_SYSCALL_VFORK_17_E,
	PPME_SYSCALL_VFORK_17_X,
	PPME_SYSCALL_VFORK_20_E,
	PPME_SYSCALL_VFORK_20_X,
	PPME_SYSCALL_EPOLL_CREATE_E,
	PPME_SYSCALL_EPOLL_CREATE_X,
	PPME_SYSCALL_EPOLL_CREATE1_E,
	PPME_SYSCALL_EPOLL_CREATE1_X,
	PPME_PROCEXIT_E,
	PPME_PROCEXIT_1_E,
	PPME_DROP_E,
	PPME_DROP_X,
	PPME_SCAPEVENT_E,
	PPME_CONTAINER_E,
	PPME_PROCINFO_E,
	PPME_CPU_HOTPLUG_E,
	PPME_K8S_E,
	PPME_TRACER_E,
	PPME_TRACER_X,
	PPME_MESOS_E,
	PPME_CONTAINER_JSON_E,
	PPME_NOTIFICATION_E,
	PPME_INFRASTRUCTURE_EVENT_E,
	PPME_CONTAINER_JSON_2_E,
	PPME_USER_ADDED_E,
	PPME_USER_DELETED_E,
	PPME_GROUP_ADDED_E,
	PPME_GROUP_DELETED_E,
	PPME_GROUP_DELETED_E,
	PPME_SYSCALL_UMOUNT_1_E,
	PPME_SYSCALL_UMOUNT_1_X,
	PPME_SOCKET_ACCEPT4_6_E,
	PPME_SOCKET_ACCEPT4_6_X,
	PPME_SYSCALL_UMOUNT2_E,
	PPME_SYSCALL_UMOUNT2_X,
	PPME_SYSCALL_PIPE2_E,
	PPME_SYSCALL_PIPE2_X,
	PPME_SYSCALL_INOTIFY_INIT1_E,
	PPME_SYSCALL_INOTIFY_INIT1_X,
	PPME_SYSCALL_EVENTFD2_E,
	PPME_SYSCALL_EVENTFD2_X,
	PPME_SYSCALL_SIGNALFD4_E,
	PPME_SYSCALL_SIGNALFD4_X,
	PPME_SYSCALL_PRCTL_E,
	PPME_SYSCALL_PRCTL_X,
	PPME_ASYNCEVENT_E,
	PPME_SYSCALL_MEMFD_CREATE_E,
	PPME_SYSCALL_MEMFD_CREATE_X,
	PPME_SYSCALL_PIDFD_GETFD_E,
	PPME_SYSCALL_PIDFD_GETFD_X,
	PPME_SYSCALL_PIDFD_OPEN_E,
	PPME_SYSCALL_PIDFD_OPEN_X
};

const libsinsp::events::set<ppm_sc_code> expected_sinsp_state_sc_set = {
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
	PPM_SC_SCHED_PROCESS_EXIT,
	PPM_SC_PRCTL,
	PPM_SC_MEMFD_CREATE,
	PPM_SC_PIDFD_OPEN,
	PPM_SC_PIDFD_GETFD,
};

const libsinsp::events::set<ppm_event_code> expected_unknown_event_set = {
	PPME_PROCEXIT_X,
	PPME_SCHEDSWITCH_1_X,
	PPME_SCHEDSWITCH_6_X,
	PPME_PROCEXIT_1_X,
	PPME_PLUGINEVENT_X,
	PPME_USER_ADDED_X,
	PPME_USER_DELETED_X,
	PPME_GROUP_ADDED_X,
	PPME_GROUP_DELETED_X,
	PPME_CONTAINER_JSON_2_X,
	PPME_PAGE_FAULT_X,
	PPME_INFRASTRUCTURE_EVENT_X,
	PPME_NOTIFICATION_X,
	PPME_CONTAINER_JSON_X,
	PPME_MESOS_X,
	PPME_K8S_X,
	PPME_CPU_HOTPLUG_X,
	PPME_PROCINFO_X,
	PPME_SIGNALDELIVER_X,
	PPME_CONTAINER_X,
	PPME_ASYNCEVENT_X,
};

/// todo(@Andreagit97): here we miss static sets for io, proc, net groups

/*=============================== Events related ===============================*/

/* Check the `info` API works correctly */
TEST(ppm_sc_API, check_event_info)
{
	{
		auto event_info_pointer = libsinsp::events::info(PPME_GENERIC_E);
		ASSERT_STREQ(event_info_pointer->name, "syscall");
		ASSERT_EQ(event_info_pointer->category, ppm_event_category(EC_OTHER | EC_SYSCALL));
		ASSERT_EQ(event_info_pointer->flags, EF_NONE);
		ASSERT_EQ(event_info_pointer->nparams, 2);
		ASSERT_STREQ(event_info_pointer->params[0].name, "ID");
	}

	{
		auto event_info_pointer = libsinsp::events::info(PPME_SYSCALL_CLONE3_X);
		ASSERT_STREQ(event_info_pointer->name, "clone3");
		ASSERT_EQ(event_info_pointer->category, ppm_event_category(EC_PROCESS | EC_SYSCALL));
		ASSERT_EQ(event_info_pointer->flags, EF_MODIFIES_STATE);
		ASSERT_EQ(event_info_pointer->nparams, 21);
		ASSERT_STREQ(event_info_pointer->params[0].name, "res");
	}
}

/* Check the `is_generic` API works correctly */
TEST(ppm_sc_API, check_generic_events)
{
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_GENERIC_E), true);
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_GENERIC_X), true);
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_SYSCALL_CLONE3_X), false);
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_PLUGINEVENT_E), false);
}

/* Check the `is_skip_parse_reset_event` API works correctly */
TEST(ppm_sc_API, check_skip_parse_reset_events)
{
	ASSERT_EQ(libsinsp::events::is_skip_parse_reset_event(ppm_event_code::PPME_PROCINFO_E), true);
	ASSERT_EQ(libsinsp::events::is_skip_parse_reset_event(ppm_event_code::PPME_SYSCALL_GETDENTS_E), false);
	ASSERT_EQ(libsinsp::events::is_skip_parse_reset_event(ppm_event_code::PPME_PLUGINEVENT_E), false);
}

/*=============================== Events related ===============================*/

/*=============================== PPME set related (sinsp_events.cpp) ===============================*/

/* The schema here is:
 * - All event set
 * - All event names
 * - sinsp state event set
 * - all generic events names
 * - all generic sc
 * - generic_e generic_x comparison
 * - unknown events
 * - event empty sets
 * - (AES) -> names -> (AES)         AES = all event set
 * - (AES) -> sc set -> (AES)
 * - (SES) -> names -> (SES)         SES = shared event set (some generic + some not generic events)
 * - (SES) -> sc set -> (SES)
 * - (NGES) -> names -> (NGES)       NGES = not generic event set (not generic events)
 * - (NGES) -> sc set -> (NGES)
 * - (AEN) -> event set -> (AEN)     AEN = all event names
 * - (SEN) -> event set -> (SEN)     SEN = shared event names
 * - (NGEN) -> event set -> (NGEN)   NGEN = not generic event names
 */

TEST(ppm_sc_API, generic_syscalls_set)
{
	libsinsp::events::set<ppm_event_code> generic_enter_event{PPME_GENERIC_E};
	libsinsp::events::set<ppm_event_code> generic_exit_event{PPME_GENERIC_X};
	std::vector<uint8_t> generic_syscalls_enter(PPM_SC_MAX, 0);
	std::vector<uint8_t> generic_syscalls_exit(PPM_SC_MAX, 0);
	ASSERT_EQ(scap_get_ppm_sc_from_events(generic_enter_event.data(), generic_syscalls_enter.data()), SCAP_SUCCESS);
	ASSERT_EQ(scap_get_ppm_sc_from_events(generic_exit_event.data(), generic_syscalls_exit.data()), SCAP_SUCCESS);
	ASSERT_EQ(generic_syscalls_enter, generic_syscalls_exit);

	// Load generic syscalls in the sinsp_generic_syscalls_set
	for(uint32_t ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if (generic_syscalls_enter[ppm_sc])
		{
			sinsp_generic_syscalls_set.insert((ppm_sc_code)ppm_sc);
		}
	}
}

TEST(ppm_sc_API, all_event_set)
{
	/* Here we want to return also unused events like `PPME_SCHEDSWITCH_6_X` */
	const auto all_events = libsinsp::events::all_event_set();
	ASSERT_EQ(all_events.size(), PPM_EVENT_MAX);
	for(int i = 0; i < PPM_EVENT_MAX; i++)
	{
		ASSERT_TRUE(all_events.contains((ppm_event_code)i)) << "\n- The event '" << scap_get_event_info_table()[i].name << "' is not present inside the all event set" << std::endl;
	}
}

TEST(ppm_sc_API, all_event_names)
{
	/* Here we want all events' names also the ones associated with generic events, so the syscalls
	 * names, but we don't want the "syscall" event name associated with `GENERIC_E`/`GENERIC_X` events extracted from the event table.
	 */
	auto events_names = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names(libsinsp::events::all_event_set()));
	/* `NA*` events were now removed so we don't want them again, all other syscall names have no events associated so they shouldn't be in this set */
	std::set<std::string> some_not_desired_names{"syscall", "ugetrlimit", "fcntl64", "sendfile64", "setresuid32", "setresgid32", "setuid32", "setgid32", "getuid32", "geteuid32", "getgid32", "getegid32", "getresuid32", "getresgid32", "NA1", "NA2", "NA3", "NA4", "NA5", "NA6"};
	ASSERT_NOT_CONTAINS(events_names, some_not_desired_names);

	/* We count old version events to be sure about the final number of names we should expect */
	int old_versions_events = 0;
	std::set<std::string> all_expected_events_names = {};

	/* We skip `syscall` name associated with `GENERIC_E`/`GENERIC_X` */
	for(int evt = 2; evt < PPM_EVENT_MAX; evt++)
	{
		if(libsinsp::events::is_old_version_event((ppm_event_code)evt))
		{
			old_versions_events++;
		}
		all_expected_events_names.insert(scap_get_event_info_table()[evt].name);
	}

	libsinsp::events::set<ppm_event_code> generic_events{PPME_GENERIC_E, PPME_GENERIC_X};
	std::vector<uint8_t> generic_syscalls(PPM_SC_MAX, 0);
	ASSERT_EQ(scap_get_ppm_sc_from_events(generic_events.data(), generic_syscalls.data()), SCAP_SUCCESS);
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(generic_syscalls[ppm_sc])
		{
			all_expected_events_names.insert(scap_get_ppm_sc_name((ppm_sc_code)ppm_sc));
		}
	}
	ASSERT_NAMES_EQ(events_names, all_expected_events_names);
	/* To obtain the right size of the event names we need to divide by 2 the total number of events.
	 * Events are almost all paired, and when they are not paired dividing by 2 we remove the `NA` entries.
	 * Since we consider the `NA` a valid name we need to add it to the set, so `+1`
	 * We don't want the name "syscall" associated with  `PPME_GENERIC_E` and `PPME_GENERIC_E`, so `-1`. `-1` and not `-2` because we have already divided by 2.
	 * We need to remove all the old version events because their names are just a replica of current events ones. `/2` because we have already divided by 2.
	 * Finally we need to add the GENERIC names.
	 */
	ASSERT_EQ(events_names.size(), (PPM_EVENT_MAX / 2) + 1 - 1 - old_versions_events / 2 + GENERIC_SYSCALLS_NUM);
}

TEST(ppm_sc_API, sinsp_state_event_set)
{
	ASSERT_PPM_EVENT_CODES_EQ(libsinsp::events::sinsp_state_event_set(), expected_sinsp_state_event_set);
}

TEST(ppm_sc_API, all_generic_events_names)
{
	libsinsp::events::set<ppm_event_code> generic_events{PPME_GENERIC_E, PPME_GENERIC_X};
	std::set<std::string> generic_events_names = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names(generic_events));

	std::vector<uint8_t> generic_syscalls(PPM_SC_MAX, 0);
	ASSERT_EQ(scap_get_ppm_sc_from_events(generic_events.data(), generic_syscalls.data()), SCAP_SUCCESS);

	std::set<std::string> expected_generic_event_names;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(generic_syscalls[ppm_sc])
		{
			expected_generic_event_names.insert(scap_get_ppm_sc_name((ppm_sc_code)ppm_sc));
		}
	}

	ASSERT_NAMES_EQ(generic_events_names, expected_generic_event_names);
	ASSERT_EQ(generic_events_names.size(), GENERIC_SYSCALLS_NUM);
}

TEST(ppm_sc_API, all_generic_ppm_sc)
{
	libsinsp::events::set<ppm_event_code> generic_events{PPME_GENERIC_E, PPME_GENERIC_X};
	auto generic_ppm_sc = libsinsp::events::event_set_to_sc_set(generic_events);

	std::vector<uint8_t> generic_syscalls(PPM_SC_MAX, 0);
	ASSERT_EQ(scap_get_ppm_sc_from_events(generic_events.data(), generic_syscalls.data()), SCAP_SUCCESS);

	libsinsp::events::set<ppm_sc_code> expected_generic_ppm_sc;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(generic_syscalls[ppm_sc])
		{
			expected_generic_ppm_sc.insert((ppm_sc_code)ppm_sc);
		}
	}

	ASSERT_PPM_SC_CODES_EQ(generic_ppm_sc, expected_generic_ppm_sc);
	ASSERT_EQ(generic_ppm_sc.size(), GENERIC_SYSCALLS_NUM);
}

TEST(ppm_sc_API, generic_e_generic_x_comparison)
{
	/* These 2 sets should be equal */
	const auto generic_e_event_names = libsinsp::events::event_set_to_names({PPME_GENERIC_E});
	const auto generic_x_event_names = libsinsp::events::event_set_to_names({PPME_GENERIC_X});
	ASSERT_EQ(generic_e_event_names, generic_x_event_names);
	ASSERT_EQ(generic_e_event_names.size(), GENERIC_SYSCALLS_NUM);

	/* Coming back to generic events */
	libsinsp::events::set<ppm_event_code> generic_events{PPME_GENERIC_E, PPME_GENERIC_X};
	const auto generic_e_set = libsinsp::events::names_to_event_set(generic_e_event_names);
	const auto generic_x_set = libsinsp::events::names_to_event_set(generic_x_event_names);
	ASSERT_PPM_EVENT_CODES_EQ(generic_e_set, generic_events);
	ASSERT_PPM_EVENT_CODES_EQ(generic_e_set, generic_x_set);
}

TEST(ppm_sc_API, unknown_events)
{
	std::unordered_set<std::string> unknown_event_names{"NA"};
	const auto unknown_event_set = libsinsp::events::names_to_event_set(unknown_event_names);
	ASSERT_PPM_EVENT_CODES_EQ(unknown_event_set, expected_unknown_event_set);

	/* We should obtain only "NA" here */
	const auto unknown_event_names_again = libsinsp::events::event_set_to_names(unknown_event_set);
	ASSERT_NAMES_EQ(unknown_event_names_again, unknown_event_names);

	/* We should obtain an empty sc set from here */
	const auto empty_sc_set = libsinsp::events::event_set_to_sc_set(unknown_event_set);
	ASSERT_TRUE(empty_sc_set.empty());

	/* We should obtain also an empty set of events */
	ASSERT_TRUE(libsinsp::events::sc_set_to_event_set(empty_sc_set).empty());
}

TEST(ppm_sc_API, event_empty_sets)
{
	std::unordered_set<std::string> empty_string_set;
	const auto empty_event_set = libsinsp::events::names_to_event_set(empty_string_set);
	const auto empty_sc_set = libsinsp::events::event_set_to_sc_set(empty_event_set);
	const auto empty_event_names = libsinsp::events::event_set_to_names(empty_event_set);
	ASSERT_TRUE(empty_event_set.empty());
	ASSERT_TRUE(empty_sc_set.empty());
	ASSERT_TRUE(empty_event_names.empty());

	libsinsp::events::set<ppm_event_code> meta_event{PPME_CONTAINER_E};
	ASSERT_TRUE(libsinsp::events::event_set_to_sc_set(meta_event).empty());
}

TEST(ppm_sc_API, AES_names_AES)
{
	const auto all_events = libsinsp::events::all_event_set();
	const auto all_events_names = libsinsp::events::event_set_to_names(all_events);
	/* Convert again to codes */
	ASSERT_PPM_EVENT_CODES_EQ(all_events, libsinsp::events::names_to_event_set(all_events_names));
}

/* Information Loss */
TEST(ppm_sc_API, AES_sc_set_AES)
{
	const auto all_events = libsinsp::events::all_event_set();

	auto all_ppm_sc = libsinsp::events::event_set_to_sc_set(all_events);
	ASSERT_PPM_SC_CODES_EQ(all_ppm_sc, libsinsp::events::all_sc_set());

	/* We cannot recover events not related to tracepoints or syscalls like meta events or unused ones */
	const auto partial_events = libsinsp::events::sc_set_to_event_set(all_ppm_sc);
	for(int i = 0; i < PPM_EVENT_MAX; i++)
	{
		if(libsinsp::events::is_unused_event((ppm_event_code)i) ||
		   libsinsp::events::is_plugin_event((ppm_event_code)i) ||
		   libsinsp::events::is_unknown_event((ppm_event_code)i) ||
		   libsinsp::events::is_metaevent((ppm_event_code)i))
		{
			continue;
		}

		ASSERT_TRUE(partial_events.contains((ppm_event_code)i)) << "\n- The event '" << scap_get_event_info_table()[i].name << "' is not present inside the event set" << std::endl;
	}
	ASSERT_EQ(partial_events.size(), SYSCALL_EVENTS_NUM + TRACEPOINT_EVENTS_NUM);
}

/* Information Enrichment */
TEST(ppm_sc_API, SES_names_SES)
{
	const libsinsp::events::set<ppm_event_code> shared_events{PPME_GENERIC_E, PPME_SYSCALL_CLONE_11_E, PPME_CONTAINER_JSON_2_E, PPME_PLUGINEVENT_E, PPME_SYSCALL_CLOSE_X, PPME_SCAPEVENT_E, PPME_PROCEXIT_1_X};
	const auto shared_events_names = libsinsp::events::event_set_to_names(shared_events);
	std::set<std::string> some_desired_event_names{"alarm", "clone", "container", "pluginevent", "close", "scapevent", "NA"}; // PPME_PROCEXIT_1_X is UNKNOWN
	ASSERT_CONTAINS(shared_events_names, some_desired_event_names);
	/* size = all generic names + 6 names written above (alarm is generic one so already included in the generic names) */
	ASSERT_EQ(shared_events_names.size(), GENERIC_SYSCALLS_NUM + 6);
	/* Convert again to codes, here we recover also enter/exit and old version */
	libsinsp::events::set<ppm_event_code> expected_shared_events{
		PPME_GENERIC_E,
		PPME_GENERIC_X,
		PPME_SYSCALL_CLONE_11_E,
		PPME_SYSCALL_CLONE_11_X,
		PPME_SYSCALL_CLONE_16_E,
		PPME_SYSCALL_CLONE_16_X,
		PPME_SYSCALL_CLONE_17_E,
		PPME_SYSCALL_CLONE_17_X,
		PPME_SYSCALL_CLONE_20_E,
		PPME_SYSCALL_CLONE_20_X,
		PPME_CONTAINER_E, // CONTAINER_X is unknown
		PPME_CONTAINER_JSON_E,
		PPME_CONTAINER_JSON_2_E,
		PPME_PLUGINEVENT_E,
		PPME_SYSCALL_CLOSE_E,
		PPME_SYSCALL_CLOSE_X,
		PPME_SCAPEVENT_E,
		PPME_SCAPEVENT_X};

	/* We need to add all events associated with `NA` */
	expected_shared_events = expected_shared_events.merge(expected_unknown_event_set);
	ASSERT_PPM_EVENT_CODES_EQ(expected_shared_events, libsinsp::events::names_to_event_set(shared_events_names));
}

/* Information Loss */
TEST(ppm_sc_API, SES_sc_set_SES)
{
	const libsinsp::events::set<ppm_event_code> shared_events{PPME_GENERIC_E, PPME_SYSCALL_CLONE_11_E, PPME_CONTAINER_JSON_2_X, PPME_PLUGINEVENT_E, PPME_SYSCALL_CLOSE_X, PPME_SCAPEVENT_E, PPME_PAGE_FAULT_E};

	auto shared_ppm_sc = libsinsp::events::event_set_to_sc_set(shared_events);

	/* We can recover only syscall/tracepoints codes */
	ASSERT_TRUE(shared_ppm_sc.contains(PPM_SC_CLONE));
	ASSERT_TRUE(shared_ppm_sc.contains(PPM_SC_CLOSE));
	ASSERT_TRUE(shared_ppm_sc.contains(PPM_SC_PAGE_FAULT_KERNEL));
	ASSERT_TRUE(shared_ppm_sc.contains(PPM_SC_PAGE_FAULT_USER));
	ASSERT_EQ(shared_ppm_sc.size(), GENERIC_SYSCALLS_NUM + 4);

	auto shared_events_again = libsinsp::events::sc_set_to_event_set(shared_ppm_sc);

	/* Convert again to codes, here we recover enter/exit and old versions but we cannot recover not syscall/tracepoints events */
	libsinsp::events::set<ppm_event_code> expected_shared_events{
		PPME_GENERIC_E,
		PPME_GENERIC_X,
		PPME_PAGE_FAULT_E, // not PAGE_FAULT_X because it is UNKNOWN
		PPME_SYSCALL_CLONE_11_E,
		PPME_SYSCALL_CLONE_11_X,
		PPME_SYSCALL_CLONE_16_E,
		PPME_SYSCALL_CLONE_16_X,
		PPME_SYSCALL_CLONE_17_E,
		PPME_SYSCALL_CLONE_17_X,
		PPME_SYSCALL_CLONE_20_E,
		PPME_SYSCALL_CLONE_20_X,
		PPME_SYSCALL_CLOSE_E,
		PPME_SYSCALL_CLOSE_X,
	};
	ASSERT_PPM_EVENT_CODES_EQ(expected_shared_events, shared_events_again);
}

/* Information Enrichment */
TEST(ppm_sc_API, NGES_names_NGES)
{
	/* This test is useful to assert that conversion without generics works well */
	const libsinsp::events::set<ppm_event_code> not_generic_events{PPME_SYSCALL_CLONE_11_E, PPME_CONTAINER_JSON_2_E, PPME_PLUGINEVENT_E, PPME_SYSCALL_CLOSE_X};
	const auto not_generic_events_names = libsinsp::events::event_set_to_names(not_generic_events);
	std::set<std::string> some_desired_event_names{"clone", "container", "pluginevent", "close"};
	ASSERT_NAMES_EQ(test_utils::unordered_set_to_ordered(not_generic_events_names), some_desired_event_names);
	/* Convert again to codes, here we recover also enter/exit and old version */
	libsinsp::events::set<ppm_event_code> expected_not_generic_events{
		PPME_SYSCALL_CLONE_11_E,
		PPME_SYSCALL_CLONE_11_X,
		PPME_SYSCALL_CLONE_16_E,
		PPME_SYSCALL_CLONE_16_X,
		PPME_SYSCALL_CLONE_17_E,
		PPME_SYSCALL_CLONE_17_X,
		PPME_SYSCALL_CLONE_20_E,
		PPME_SYSCALL_CLONE_20_X,
		PPME_CONTAINER_E,
		PPME_CONTAINER_JSON_E,
		PPME_CONTAINER_JSON_2_E,
		PPME_PLUGINEVENT_E,
		PPME_SYSCALL_CLOSE_E,
		PPME_SYSCALL_CLOSE_X};

	ASSERT_PPM_EVENT_CODES_EQ(expected_not_generic_events, libsinsp::events::names_to_event_set(not_generic_events_names));
}

/* Information Loss */
TEST(ppm_sc_API, NGES_sc_set_NGES)
{
	const libsinsp::events::set<ppm_event_code> not_generic_events{PPME_SYSCALL_CLONE_11_E, PPME_CONTAINER_JSON_2_X, PPME_PLUGINEVENT_E, PPME_SYSCALL_CLOSE_X};

	auto not_generic_ppm_sc = libsinsp::events::event_set_to_sc_set(not_generic_events);

	/* We can recover only syscall/tracepoints codes */
	libsinsp::events::set<ppm_sc_code> expected_not_generic_ppm_sc{PPM_SC_CLONE, PPM_SC_CLOSE};
	ASSERT_PPM_SC_CODES_EQ(not_generic_ppm_sc, expected_not_generic_ppm_sc);

	auto not_generic_events_again = libsinsp::events::sc_set_to_event_set(not_generic_ppm_sc);

	/* Convert again to codes, here we recover enter/exit and old versions but we cannot recover not syscall/tracepoints events */
	libsinsp::events::set<ppm_event_code> expected_not_generic_events{
		PPME_SYSCALL_CLONE_11_E,
		PPME_SYSCALL_CLONE_11_X,
		PPME_SYSCALL_CLONE_16_E,
		PPME_SYSCALL_CLONE_16_X,
		PPME_SYSCALL_CLONE_17_E,
		PPME_SYSCALL_CLONE_17_X,
		PPME_SYSCALL_CLONE_20_E,
		PPME_SYSCALL_CLONE_20_X,
		PPME_SYSCALL_CLOSE_E,
		PPME_SYSCALL_CLOSE_X,
	};
	ASSERT_PPM_EVENT_CODES_EQ(expected_not_generic_events, not_generic_events_again);
}

TEST(ppm_sc_API, AEN_event_set_AEN)
{
	const auto all_events_names = libsinsp::events::event_set_to_names(libsinsp::events::all_event_set());
	const auto all_events = libsinsp::events::names_to_event_set(all_events_names);
	ASSERT_EQ(all_events.size(), PPM_EVENT_MAX);
	const auto all_events_names_again = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names(all_events));
	ASSERT_NAMES_EQ(test_utils::unordered_set_to_ordered(all_events_names), all_events_names_again);
}

/* Information Enrichment */
TEST(ppm_sc_API, SEN_event_set_SEN)
{
	/* `not-exists` and `Read` should not be considered */
	std::unordered_set<std::string> shared_events_names{"syncfs", "clone", "switch", "not-exists", "Read"}; // Note the capital letter in 'Read'
	const auto shared_events = libsinsp::events::names_to_event_set(shared_events_names);
	libsinsp::events::set<ppm_event_code> expected_shared_events{
		PPME_GENERIC_E,
		PPME_GENERIC_X,
		PPME_SYSCALL_CLONE_11_E,
		PPME_SYSCALL_CLONE_11_X,
		PPME_SYSCALL_CLONE_16_E,
		PPME_SYSCALL_CLONE_16_X,
		PPME_SYSCALL_CLONE_17_E,
		PPME_SYSCALL_CLONE_17_X,
		PPME_SYSCALL_CLONE_20_E,
		PPME_SYSCALL_CLONE_20_X,
		PPME_SCHEDSWITCH_1_E,
		PPME_SCHEDSWITCH_6_E};
	ASSERT_PPM_EVENT_CODES_EQ(expected_shared_events, shared_events);

	std::set<std::string> some_desired_names{"syncfs", "clone", "switch"};
	auto shared_events_names_again = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names(shared_events));

	/* Here we cannot recover just "syncfs" but we recover all generic syscalls names */
	ASSERT_CONTAINS(shared_events_names_again, some_desired_names);
	ASSERT_EQ(shared_events_names_again.size(), GENERIC_SYSCALLS_NUM + 2);
}

TEST(ppm_sc_API, NGEN_event_set_NGEN)
{
	std::unordered_set<std::string> not_generic_events_names{"brk", "fcntl"};
	const auto not_generic_events = libsinsp::events::names_to_event_set(not_generic_events_names);
	libsinsp::events::set<ppm_event_code> expected_not_generic_events{
		PPME_SYSCALL_FCNTL_E,
		PPME_SYSCALL_FCNTL_X,
		PPME_SYSCALL_BRK_4_E,
		PPME_SYSCALL_BRK_4_X,
		PPME_SYSCALL_BRK_1_E,
		PPME_SYSCALL_BRK_1_X};
	ASSERT_PPM_EVENT_CODES_EQ(expected_not_generic_events, not_generic_events);
	const auto not_generic_events_names_again = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names(not_generic_events));
	ASSERT_NAMES_EQ(test_utils::unordered_set_to_ordered(not_generic_events_names), not_generic_events_names_again);
}

/// todo(@Andreagit97) remove duplicated
TEST(ppm_sc_API, from_event_names_to_event_names_with_information_loss)
{
	std::unordered_set<std::string> event_names{"openat", "execveat", "syncfs"};

	/* Converting event names associated with generic events causes information loss!
	 * From the event set we are not able to recover the specific event we want to enable
	 * since we have generic `PPME_GENERIC_E`, `PPME_GENERIC_X`.
	 */
	auto event_codes = libsinsp::events::names_to_event_set(event_names);
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_OPENAT_E));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_OPENAT_X));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_OPENAT_2_E));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_OPENAT_2_X));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_EXECVEAT_E));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_EXECVEAT_X));
	ASSERT_TRUE(event_codes.contains(PPME_GENERIC_E));
	ASSERT_TRUE(event_codes.contains(PPME_GENERIC_X));
	ASSERT_EQ(event_codes.size(), 8);

	/* Converting again event set to names */
	auto event_names_with_all_generics = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names(event_codes));

	/* Expected set */
	auto expected_events_names = test_utils::unordered_set_to_ordered(libsinsp::events::event_set_to_names({PPME_GENERIC_E, PPME_GENERIC_X}));
	expected_events_names.insert("openat");
	expected_events_names.insert("execveat");
	ASSERT_NAMES_EQ(event_names_with_all_generics, expected_events_names);
}

/// todo(@Andreagit97) remove duplicated
TEST(ppm_sc_API, event_set_to_names_misc)
{
	auto event_codes = libsinsp::events::set<ppm_event_code>{PPME_GENERIC_E, PPME_GENERIC_X, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPENAT_X, PPME_SYSCALL_OPENAT_2_E};
	const auto event_names = libsinsp::events::event_set_to_names(event_codes);
	std::set<std::string> some_desired_event_names = {"open", "openat"};
	ASSERT_CONTAINS(event_names, some_desired_event_names);
	const auto event_codes_again = libsinsp::events::names_to_event_set(event_names);
	/* we need to insert the missing part of the pairs */
	event_codes.insert((ppm_event_code)PPME_SYSCALL_OPEN_X);
	event_codes.insert((ppm_event_code)PPME_SYSCALL_OPENAT_E);
	event_codes.insert((ppm_event_code)PPME_SYSCALL_OPENAT_2_X);
	ASSERT_PPM_EVENT_CODES_EQ(event_codes, event_codes_again);
}

/*=============================== PPME set related (sinsp_events.cpp) ===============================*/

/*=============================== PPM_SC set related (sinsp_events_ppm_sc.cpp) ===============================*/

/* The schema here is:
 * - All sc set
 * - All sc names
 * - sinsp state sc set
 * - enforce sinsp state sc set
 * - sc empty sets
 * - sc unknown
 * - IO sc set         todo(@Andreagit97)
 * - IO_OTHER sc set   todo(@Andreagit97)
 * - NET sc set        todo(@Andreagit97)
 * - PROC sc set       todo(@Andreagit97)
 * - SYS sc set        todo(@Andreagit97)
 * - (ASS) -> names -> (ASS)         ASS = all sc set (this test is not so meaningful the mapping is 1:1)
 * - (ASS) -> event set -> (ASS)
 * - (SSS) -> event set -> (SSS)     SSS = shared sc set (some syscall associated with generic events + not generic syscalls)
 * - (NGSS) -> event set -> (NGSS)   NGSS = not generic sc set
 * - (SSN) -> sc set -> (SSN)        SSN = shared sc names
 */

TEST(ppm_sc_API, all_sc_set)
{
	auto all_sc = libsinsp::events::all_sc_set();
	/* In all_sc we don't have `PPM_SC_UNKNOWN` and the code `382` that corresponds to old/wrong code */
	ASSERT_EQ(all_sc.size(), PPM_SC_MAX - 2);
}

TEST(ppm_sc_API, all_sc_names)
{
	auto sc_names = test_utils::unordered_set_to_ordered(libsinsp::events::sc_set_to_sc_names(libsinsp::events::all_sc_set()));
	std::set<std::string> expected_sc_names;
	/* In all_sc we don't have `PPM_SC_UNKNOWN` so we don't have to retrieve the "unknown" name, we start the for loop from 1 */
	for(int ppm_sc = 1; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(std::string("").compare(scap_get_ppm_sc_name((ppm_sc_code)ppm_sc)) == 0)
		{
			continue;
		}
		expected_sc_names.insert(scap_get_ppm_sc_name((ppm_sc_code)ppm_sc));
	}
	ASSERT_NAMES_EQ(sc_names, expected_sc_names);
}

TEST(ppm_sc_API, sinsp_state_sc_set)
{
	ASSERT_PPM_SC_CODES_EQ(expected_sinsp_state_sc_set, libsinsp::events::sinsp_state_sc_set());
}

TEST(ppm_sc_API, enforce_sinsp_state_sc_set)
{
	auto expected_final_state_set = libsinsp::events::enforce_simple_sc_set();
	expected_final_state_set.insert(PPM_SC_UNKNOWN);
	expected_final_state_set.insert(PPM_SC__NEWSELECT);
	expected_final_state_set.insert(PPM_SC_PAGE_FAULT_KERNEL);
	expected_final_state_set.insert(PPM_SC_SCHED_SWITCH);

	ASSERT_PPM_SC_CODES_EQ(expected_final_state_set, libsinsp::events::enforce_simple_sc_set({PPM_SC_UNKNOWN, PPM_SC__NEWSELECT, PPM_SC_PAGE_FAULT_KERNEL, PPM_SC_SCHED_SWITCH}));
	ASSERT_CONTAINS(expected_final_state_set, libsinsp::events::sinsp_state_sc_set());
}

TEST(ppm_sc_API, sc_empty_sets)
{
	std::unordered_set<std::string> empty_string_set;
	const auto empty_sc_set = libsinsp::events::sc_names_to_sc_set(empty_string_set);
	const auto empty_event_set = libsinsp::events::sc_set_to_event_set(empty_sc_set);
	const auto empty_sc_names = libsinsp::events::sc_set_to_sc_names(empty_sc_set);
	ASSERT_TRUE(empty_sc_set.empty());
	ASSERT_TRUE(empty_event_set.empty());
	ASSERT_TRUE(empty_sc_names.empty());
}

TEST(ppm_sc_API, sc_unknown)
{
	libsinsp::events::set<ppm_sc_code> unknown_sc{PPM_SC_UNKNOWN};
	ASSERT_TRUE(libsinsp::events::sc_set_to_event_set(unknown_sc).empty());
	ASSERT_NAMES_EQ(libsinsp::events::sc_set_to_sc_names(unknown_sc), std::unordered_set<std::string>{"unknown"});
}

TEST(ppm_sc_API, ASS_sc_names_ASS)
{
	const auto all_sc = libsinsp::events::all_sc_set();
	const auto all_sc_names = libsinsp::events::sc_set_to_sc_names(all_sc);
	const auto all_sc_again = libsinsp::events::sc_names_to_sc_set(all_sc_names);
	ASSERT_PPM_SC_CODES_EQ(all_sc, all_sc_again);
}

TEST(ppm_sc_API, ASS_event_names_ASS)
{
	const auto all_sc = libsinsp::events::all_sc_set();
	const auto all_event_names = libsinsp::events::sc_set_to_event_names(all_sc);
	const auto all_sc_again = libsinsp::events::event_names_to_sc_set(all_event_names);
	ASSERT_PPM_SC_CODES_EQ(all_sc, all_sc_again);
}

TEST(ppm_sc_API, ASS_event_set_ASS)
{
	const auto all_sc = libsinsp::events::all_sc_set();

	const auto all_events = libsinsp::events::sc_set_to_event_set(all_sc);
	for(int i = 0; i < PPM_EVENT_MAX; i++)
	{
		if(libsinsp::events::is_unused_event((ppm_event_code)i) ||
		   libsinsp::events::is_plugin_event((ppm_event_code)i) ||
		   libsinsp::events::is_unknown_event((ppm_event_code)i) ||
		   libsinsp::events::is_metaevent((ppm_event_code)i))
		{
			continue;
		}

		ASSERT_TRUE(all_events.contains((ppm_event_code)i)) << "\n- The event '" << scap_get_event_info_table()[i].name << "' is not present inside the event set" << std::endl;
	}
	ASSERT_EQ(all_events.size(), SYSCALL_EVENTS_NUM + TRACEPOINT_EVENTS_NUM);

	auto all_sc_again = libsinsp::events::event_set_to_sc_set(all_events);
	ASSERT_PPM_SC_CODES_EQ(all_sc_again, all_sc);
}

/* Information Loss */
TEST(ppm_sc_API, SSS_event_set_SSS)
{
	const libsinsp::events::set<ppm_sc_code> shared_sc_set{PPM_SC_UNKNOWN, PPM_SC_SYSLOG, PPM_SC_ACCEPT4, PPM_SC_PAGE_FAULT_KERNEL};
	const auto shared_event_set = libsinsp::events::sc_set_to_event_set(shared_sc_set);
	const libsinsp::events::set<ppm_event_code> expected_shared_event_set{
		PPME_GENERIC_E,
		PPME_GENERIC_X,
        PPME_SOCKET_ACCEPT4_6_E,
        PPME_SOCKET_ACCEPT4_6_X,
		PPME_SOCKET_ACCEPT4_5_E,
		PPME_SOCKET_ACCEPT4_5_X,
		PPME_SOCKET_ACCEPT4_E,
		PPME_SOCKET_ACCEPT4_X,
		PPME_PAGE_FAULT_E};
	ASSERT_PPM_EVENT_CODES_EQ(shared_event_set, expected_shared_event_set);

	/* Converting again we are not able to understand that the initial syscall was `PPM_SC_SYSLOG`.
	 * Moreover some `PPME_PAGE_FAULT_E` corresponds to two PPM_SCs.
	 * We lose also the `PPM_SC_UNKNOWN`
	 */
	const auto shared_sc_set_again = libsinsp::events::event_set_to_sc_set(shared_event_set);
	ASSERT_TRUE(shared_sc_set_again.contains(PPM_SC_SYSLOG));
	ASSERT_TRUE(shared_sc_set_again.contains(PPM_SC_ACCEPT4));
	ASSERT_TRUE(shared_sc_set_again.contains(PPM_SC_PAGE_FAULT_KERNEL));
	ASSERT_TRUE(shared_sc_set_again.contains(PPM_SC_PAGE_FAULT_USER));
	ASSERT_FALSE(shared_sc_set_again.contains(PPM_SC_UNKNOWN));
	/* +3 because we have to add `PPM_SC_ACCEPT4` `PPM_SC_PAGE_FAULT_KERNEL` `PPM_SC_PAGE_FAULT_USER` */
	ASSERT_EQ(shared_sc_set_again.size(), GENERIC_SYSCALLS_NUM + 3);
}

/* Information Loss */
TEST(ppm_sc_API, NGSS_event_set_NGSS)
{
	const libsinsp::events::set<ppm_sc_code> not_generic_sc_set{PPM_SC_UNKNOWN, PPM_SC_PIPE2, PPM_SC_EVENTFD2, PPM_SC_BRK};
	const auto not_generic_event_set = libsinsp::events::sc_set_to_event_set(not_generic_sc_set);
	const libsinsp::events::set<ppm_event_code> expected_not_generic_event_set{
		PPME_SYSCALL_PIPE2_E,
		PPME_SYSCALL_PIPE2_X,
		PPME_SYSCALL_EVENTFD2_E,
		PPME_SYSCALL_EVENTFD2_X,
		PPME_SYSCALL_BRK_1_E,
		PPME_SYSCALL_BRK_1_X,
		PPME_SYSCALL_BRK_4_E,
		PPME_SYSCALL_BRK_4_X};
	ASSERT_PPM_EVENT_CODES_EQ(expected_not_generic_event_set, not_generic_event_set);

	/* We lose also the `PPM_SC_UNKNOWN` */
	const auto not_generic_sc_set_again = libsinsp::events::event_set_to_sc_set(not_generic_event_set);
	ASSERT_CONTAINS(not_generic_sc_set, not_generic_sc_set_again);
	ASSERT_EQ(not_generic_sc_set_again.size(), 3);
}

TEST(ppm_sc_API, SSN_sc_set_SSN)
{
	auto sc_set = libsinsp::events::sc_names_to_sc_set(std::unordered_set<std::string>{"open", "openat", "alarm", "****!!!!!", "NOT-SC", "", "unknown", "sched_process_exit"});
	ASSERT_TRUE(sc_set.contains(PPM_SC_OPEN));
	ASSERT_TRUE(sc_set.contains(PPM_SC_OPENAT));
	ASSERT_TRUE(sc_set.contains(PPM_SC_ALARM));
	ASSERT_TRUE(sc_set.contains(PPM_SC_UNKNOWN));
	ASSERT_TRUE(sc_set.contains(PPM_SC_SCHED_PROCESS_EXIT));
	ASSERT_EQ(sc_set.size(), 5);

	std::unordered_set<std::string> expected_sc_names{"open", "openat", "alarm", "unknown", "sched_process_exit"};
	auto sc_names_again = libsinsp::events::sc_set_to_sc_names(sc_set);
	ASSERT_NAMES_EQ(expected_sc_names, sc_names_again);
}

/// todo(@Andreagit97) Here we miss all tests on `io_sc_set` and others... Not sure we want all those helpers, if yes we need to create
/// sets here in tests so we can assert against them

/*=============================== PPM_SC set related (sinsp_events_ppm_sc.cpp) ===============================*/
