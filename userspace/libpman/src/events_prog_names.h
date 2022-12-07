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
#include <feature_gates.h>

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
	[PPME_SOCKET_ACCEPT_5_E] = "accept_e",
	[PPME_SOCKET_ACCEPT_5_X] = "accept_x",
	[PPME_SOCKET_ACCEPT4_5_E] = "accept4_e",
	[PPME_SOCKET_ACCEPT4_5_X] = "accept4_x",
	[PPME_SOCKET_BIND_E] = "bind_e",
	[PPME_SOCKET_BIND_X] = "bind_x",
	[PPME_SOCKET_LISTEN_E] = "listen_e",
	[PPME_SOCKET_LISTEN_X] = "listen_x",
	[PPME_SYSCALL_EXECVE_19_E] = "execve_e",
	[PPME_SYSCALL_EXECVE_19_X] = "execve_x",
	[PPME_SYSCALL_EXECVEAT_E] = "execveat_e",
	[PPME_SYSCALL_EXECVEAT_X] = "execveat_x",
	[PPME_SYSCALL_CLONE_20_E] = "clone_e",
	[PPME_SYSCALL_CLONE_20_X] = "clone_x",
	[PPME_SYSCALL_CLONE3_E] = "clone3_e",
	[PPME_SYSCALL_CLONE3_X] = "clone3_x",
	[PPME_SYSCALL_FORK_20_E] = "fork_e",
	[PPME_SYSCALL_FORK_20_X] = "fork_x",
	[PPME_SYSCALL_VFORK_20_E] = "vfork_e",
	[PPME_SYSCALL_VFORK_20_X] = "vfork_x",
	[PPME_SYSCALL_RENAME_E] = "rename_e",
	[PPME_SYSCALL_RENAME_X] = "rename_x",
	[PPME_SYSCALL_RENAMEAT_E] = "renameat_e",
	[PPME_SYSCALL_RENAMEAT_X] = "renameat_x",
	[PPME_SYSCALL_RENAMEAT2_E] = "renameat2_e",
	[PPME_SYSCALL_RENAMEAT2_X] = "renameat2_x",
	[PPME_SYSCALL_PIPE_E] = "pipe_e",
	[PPME_SYSCALL_PIPE_X] = "pipe_x",
	[PPME_SYSCALL_BPF_2_E] = "bpf_e",
	[PPME_SYSCALL_BPF_2_X] = "bpf_x",
	[PPME_SYSCALL_FLOCK_E] = "flock_e",
	[PPME_SYSCALL_FLOCK_X] = "flock_x",
	[PPME_SYSCALL_IOCTL_3_E] = "ioctl_e",
	[PPME_SYSCALL_IOCTL_3_X] = "ioctl_x",
	[PPME_SYSCALL_QUOTACTL_E] = "quotactl_e",
	[PPME_SYSCALL_QUOTACTL_X] = "quotactl_x",
	[PPME_SYSCALL_UNSHARE_E] = "unshare_e",
	[PPME_SYSCALL_UNSHARE_X] = "unshare_x",
	[PPME_SYSCALL_MOUNT_E] = "mount_e",
	[PPME_SYSCALL_MOUNT_X] = "mount_x",
	/* These events should be called `PPME_SYSCALL_UMOUNT2_...` */
	[PPME_SYSCALL_UMOUNT_E] = "umount2_e",
	[PPME_SYSCALL_UMOUNT_X] = "umount2_x",
	[PPME_SYSCALL_LINK_2_E] = "link_e",
	[PPME_SYSCALL_LINK_2_X] = "link_x",
	[PPME_SYSCALL_LINKAT_2_E] = "linkat_e",
	[PPME_SYSCALL_LINKAT_2_X] = "linkat_x",
	[PPME_SYSCALL_SYMLINK_E] = "symlink_e",
	[PPME_SYSCALL_SYMLINK_X] = "symlink_x",
	[PPME_SYSCALL_SYMLINKAT_E] = "symlinkat_e",
	[PPME_SYSCALL_SYMLINKAT_X] = "symlinkat_x",
	[PPME_SYSCALL_UNLINK_2_E] = "unlink_e",
	[PPME_SYSCALL_UNLINK_2_X] = "unlink_x",
	[PPME_SYSCALL_UNLINKAT_2_E] = "unlinkat_e",
	[PPME_SYSCALL_UNLINKAT_2_X] = "unlinkat_x",
	[PPME_SYSCALL_SETGID_E] = "setgid_e",
	[PPME_SYSCALL_SETGID_X] = "setgid_x",
	[PPME_SYSCALL_SETUID_E] = "setuid_e",
	[PPME_SYSCALL_SETUID_X] = "setuid_x",
	[PPME_SYSCALL_SETNS_E] = "setns_e",
	[PPME_SYSCALL_SETNS_X] = "setns_x",
	[PPME_SYSCALL_SETPGID_E] = "setpgid_e",
	[PPME_SYSCALL_SETPGID_X] = "setpgid_x",
	[PPME_SYSCALL_SETRESGID_E] = "setresgid_e",
	[PPME_SYSCALL_SETRESGID_X] = "setresgid_x",
	[PPME_SYSCALL_SETRESUID_E] = "setresuid_e",
	[PPME_SYSCALL_SETRESUID_X] = "setresuid_x",
	[PPME_SYSCALL_SETSID_E] = "setsid_e",
	[PPME_SYSCALL_SETSID_X] = "setsid_x",
	[PPME_SYSCALL_SETRLIMIT_E] = "setrlimit_e",
	[PPME_SYSCALL_SETRLIMIT_X] = "setrlimit_x",
	[PPME_SYSCALL_PRLIMIT_E] = "prlimit64_e",
	[PPME_SYSCALL_PRLIMIT_X] = "prlimit64_x",
	[PPME_SOCKET_SETSOCKOPT_E] = "setsockopt_e",
	[PPME_SOCKET_SETSOCKOPT_X] = "setsockopt_x",
	[PPME_SOCKET_SENDMSG_E] = "sendmsg_e",
	[PPME_SOCKET_SENDMSG_X] = "sendmsg_x",
	[PPME_SOCKET_SENDTO_E] = "sendto_e",
	[PPME_SOCKET_SENDTO_X] = "sendto_x",
	[PPME_SOCKET_RECVMSG_E] = "recvmsg_e",
	[PPME_SOCKET_RECVMSG_X] = "recvmsg_x",
	[PPME_SOCKET_RECVFROM_E] = "recvfrom_e",
	[PPME_SOCKET_RECVFROM_X] = "recvfrom_x",
	[PPME_SYSCALL_FCNTL_E] = "fcntl_e",
	[PPME_SYSCALL_FCNTL_X] = "fcntl_x",
	[PPME_SOCKET_SHUTDOWN_E] = "shutdown_e",
	[PPME_SOCKET_SHUTDOWN_X] = "shutdown_x",
	[PPME_SYSCALL_FSCONFIG_E] = "fsconfig_e",
	[PPME_SYSCALL_FSCONFIG_X] = "fsconfig_x",
	[PPME_SYSCALL_EPOLL_CREATE_E] = "epoll_create_e",
	[PPME_SYSCALL_EPOLL_CREATE_X] = "epoll_create_x",
	[PPME_SYSCALL_EPOLL_CREATE1_E] = "epoll_create1_e",
	[PPME_SYSCALL_EPOLL_CREATE1_X] = "epoll_create1_x",
	[PPME_SYSCALL_ACCESS_E] = "access_e",
	[PPME_SYSCALL_ACCESS_X] = "access_x",
};

/* Some events can require more than one bpf program to collect all the data. */
static const char* extra_event_prog_names[TAIL_EXTRA_EVENT_PROG_MAX] = {
	[T1_EXECVE_X] = "t1_execve_x",
	[T1_EXECVEAT_X] = "t1_execveat_x",
	[T1_CLONE_X] = "t1_clone_x",
	[T1_CLONE3_X] = "t1_clone3_x",
	[T1_FORK_X] = "t1_fork_x",
	[T1_VFORK_X] = "t1_vfork_x",
#ifdef CAPTURE_SCHED_PROC_EXEC
	[T1_SCHED_PROC_EXEC] = "t1_sched_p_exec",
#endif
#ifdef CAPTURE_SCHED_PROC_FORK
	[T1_SCHED_PROC_FORK] = "t1_sched_p_fork",
	[T2_SCHED_PROC_FORK] = "t2_sched_p_fork",
#endif
	[T2_CLONE_X] = "t2_clone_x",
	[T2_CLONE3_X] = "t2_clone3_x",
	[T2_FORK_X] = "t2_fork_x",
	[T2_VFORK_X] = "t2_vfork_x",
};
