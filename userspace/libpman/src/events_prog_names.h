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

#pragma once

#include <ppm_events_public.h>

/* For every event here we have the name of the corresponding bpf program. */
static const char* event_prog_names[PPM_EVENT_MAX] = {
	[PPME_SYSCALL_MKDIR_2_E] = "mkdir_e",
	[PPME_SYSCALL_MKDIR_2_X] = "mkdir_x",
	[PPME_SYSCALL_OPEN_E] = "open_e",
	[PPME_SYSCALL_OPEN_X] = "open_x",
	[PPME_SYSCALL_OPENAT_2_E] = "openat_e",
	[PPME_SYSCALL_OPENAT_2_X] = "openat_x",
	[PPME_SYSCALL_OPENAT2_E] = "openat2_e",
	[PPME_SYSCALL_OPENAT2_X] = "openat2_x",
	[PPME_SYSCALL_OPEN_BY_HANDLE_AT_E] = "open_by_handle_at_e",
	[PPME_SYSCALL_OPEN_BY_HANDLE_AT_X] = "open_by_handle_at_x",
	[PPME_SYSCALL_CLOSE_E] = "close_e",
	[PPME_SYSCALL_CLOSE_X] = "close_x",
	[PPME_SYSCALL_COPY_FILE_RANGE_E] = "copy_file_range_e",
	[PPME_SYSCALL_COPY_FILE_RANGE_X] = "copy_file_range_x",
	[PPME_SYSCALL_CREAT_E] = "creat_e",
	[PPME_SYSCALL_CREAT_X] = "creat_x",
	[PPME_SYSCALL_DUP_1_E] = "dup_e",
	[PPME_SYSCALL_DUP_1_X] = "dup_x",
	[PPME_SYSCALL_DUP2_E] = "dup2_e",
	[PPME_SYSCALL_DUP2_X] = "dup2_x",
	[PPME_SYSCALL_DUP3_E] = "dup3_e",
	[PPME_SYSCALL_DUP3_X] = "dup3_x",
	[PPME_SYSCALL_CHDIR_E] = "chdir_e",
	[PPME_SYSCALL_CHDIR_X] = "chdir_x",
	[PPME_SYSCALL_CHMOD_E] = "chmod_e",
	[PPME_SYSCALL_CHMOD_X] = "chmod_x",
	[PPME_SYSCALL_CHROOT_E] = "chroot_e",
	[PPME_SYSCALL_CHROOT_X] = "chroot_x",
	[PPME_SYSCALL_FCHDIR_E] = "fchdir_e",
	[PPME_SYSCALL_FCHDIR_X] = "fchdir_x",
	[PPME_SYSCALL_FCHMOD_E] = "fchmod_e",
	[PPME_SYSCALL_FCHMOD_X] = "fchmod_x",
	[PPME_SYSCALL_FCHMODAT_E] = "fchmodat_e",
	[PPME_SYSCALL_FCHMODAT_X] = "fchmodat_x",
	[PPME_SYSCALL_MKDIRAT_E] = "mkdirat_e",
	[PPME_SYSCALL_MKDIRAT_X] = "mkdirat_x",
	[PPME_SYSCALL_RMDIR_2_E] = "rmdir_e",
	[PPME_SYSCALL_RMDIR_2_X] = "rmdir_x",
	[PPME_SYSCALL_EVENTFD_E] = "eventfd_e",
	[PPME_SYSCALL_EVENTFD_X] = "eventfd_x",
	[PPME_SYSCALL_INOTIFY_INIT_E] = "inotify_init_e",
	[PPME_SYSCALL_INOTIFY_INIT_X] = "inotify_init_x",
	[PPME_SYSCALL_TIMERFD_CREATE_E] = "timerfd_create_e",
	[PPME_SYSCALL_TIMERFD_CREATE_X] = "timerfd_create_x",
	[PPME_SYSCALL_USERFAULTFD_E] = "userfaultfd_e",
	[PPME_SYSCALL_USERFAULTFD_X] = "userfaultfd_x",
	[PPME_SYSCALL_SIGNALFD_E] = "signalfd_e",
	[PPME_SYSCALL_SIGNALFD_X] = "signalfd_x",
	[PPME_SYSCALL_KILL_E] = "kill_e",
	[PPME_SYSCALL_KILL_X] = "kill_x",
	[PPME_SYSCALL_TGKILL_E] = "tgkill_e",
	[PPME_SYSCALL_TGKILL_X] = "tgkill_x",
	[PPME_SYSCALL_TKILL_E] = "tkill_e",
	[PPME_SYSCALL_TKILL_X] = "tkill_x",
	[PPME_SYSCALL_SECCOMP_E] = "seccomp_e",
	[PPME_SYSCALL_SECCOMP_X] = "seccomp_x",
	[PPME_SYSCALL_PTRACE_E] = "ptrace_e",
	[PPME_SYSCALL_PTRACE_X] = "ptrace_x",
	[PPME_SYSCALL_CAPSET_E] = "capset_e",
	[PPME_SYSCALL_CAPSET_X] = "capset_x",
	[PPME_SOCKET_SOCKET_E] = "socket_e",
	[PPME_SOCKET_SOCKET_X] = "socket_x",
	[PPME_SOCKET_CONNECT_E] = "connect_e",
	[PPME_SOCKET_CONNECT_X] = "connect_x",
	[PPME_SOCKET_SOCKETPAIR_E] = "socketpair_e",
	[PPME_SOCKET_SOCKETPAIR_X] = "socketpair_x",
};

/* Some events can require more than one bpf program to collect all the data. */
static const char* extra_event_prog_names[TAIL_EXTRA_EVENT_PROG_MAX] = {};
