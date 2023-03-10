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
	[PPME_GENERIC_E] = "generic_e",
	[PPME_GENERIC_X] = "generic_x",
	[PPME_SYSCALL_MKDIR_2_E] = "mkdir_e",
	[PPME_SYSCALL_MKDIR_2_X] = "mkdir_x",
	[PPME_SYSCALL_MMAP_E] = "mmap_e",
	[PPME_SYSCALL_MMAP_X] = "mmap_x",
	[PPME_SYSCALL_MUNMAP_E] = "munmap_e",
	[PPME_SYSCALL_MUNMAP_X] = "munmap_x",
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
	[PPME_SOCKET_GETSOCKOPT_E] = "getsockopt_e",
	[PPME_SOCKET_GETSOCKOPT_X] = "getsockopt_x",
	[PPME_SYSCALL_MPROTECT_E] = "mprotect_e",
	[PPME_SYSCALL_MPROTECT_X] = "mprotect_x",
	[PPME_SYSCALL_GETUID_E] = "getuid_e",
	[PPME_SYSCALL_GETUID_X] = "getuid_x",
	[PPME_SYSCALL_GETGID_E] = "getgid_e",
	[PPME_SYSCALL_GETGID_X] = "getgid_x",
	[PPME_SYSCALL_GETEUID_E] = "geteuid_e",
	[PPME_SYSCALL_GETEUID_X] = "geteuid_x",
	[PPME_SYSCALL_GETEGID_E] = "getegid_e",
	[PPME_SYSCALL_GETEGID_X] = "getegid_x",
	[PPME_SYSCALL_MLOCK_E] = "mlock_e",
	[PPME_SYSCALL_MLOCK_X] = "mlock_x",
	[PPME_SYSCALL_MLOCK2_E] = "mlock2_e",
	[PPME_SYSCALL_MLOCK2_X] = "mlock2_x",
	[PPME_SYSCALL_MUNLOCK_E] = "munlock_e",
	[PPME_SYSCALL_MUNLOCK_X] = "munlock_x",
	[PPME_SYSCALL_MLOCKALL_E] = "mlockall_e",
	[PPME_SYSCALL_MLOCKALL_X] = "mlockall_x",
	[PPME_SYSCALL_MUNLOCKALL_E] = "munlockall_e",
	[PPME_SYSCALL_MUNLOCKALL_X] = "munlockall_x",
	[PPME_SYSCALL_READ_E] = "read_e",
	[PPME_SYSCALL_READ_X] = "read_x",
	[PPME_SYSCALL_IO_URING_ENTER_E] = "io_uring_enter_e",
	[PPME_SYSCALL_IO_URING_ENTER_X] = "io_uring_enter_x",
	[PPME_SYSCALL_IO_URING_REGISTER_E] = "io_uring_register_e",
	[PPME_SYSCALL_IO_URING_REGISTER_X] = "io_uring_register_x",
	[PPME_SYSCALL_IO_URING_SETUP_E] = "io_uring_setup_e",
	[PPME_SYSCALL_IO_URING_SETUP_X] = "io_uring_setup_x",
	[PPME_SYSCALL_POLL_E] = "poll_e",
	[PPME_SYSCALL_POLL_X] = "poll_x",
	[PPME_SYSCALL_PPOLL_E] = "ppoll_e",
	[PPME_SYSCALL_PPOLL_X] = "ppoll_x",
	[PPME_SYSCALL_MMAP2_E] = "mmap2_e",
	[PPME_SYSCALL_MMAP2_X] = "mmap2_x",
	[PPME_SYSCALL_SEMGET_E] = "semget_e",
	[PPME_SYSCALL_SEMGET_X] = "semget_x",
	[PPME_SYSCALL_SEMCTL_E] = "semctl_e",
	[PPME_SYSCALL_SEMCTL_X] = "semctl_x",
	[PPME_SYSCALL_SELECT_E] = "select_e",
	[PPME_SYSCALL_SELECT_X] = "select_x",
	[PPME_SYSCALL_SPLICE_E] = "splice_e",
	[PPME_SYSCALL_SPLICE_X] = "splice_x",
	[PPME_SOCKET_RECVMMSG_E] = "recvmmsg_e",
	[PPME_SOCKET_RECVMMSG_X] = "recvmmsg_x",
	[PPME_SOCKET_SENDMMSG_E] = "sendmmsg_e",
	[PPME_SOCKET_SENDMMSG_X] = "sendmmsg_x",
	[PPME_SYSCALL_SEMOP_E] = "semop_e",
	[PPME_SYSCALL_SEMOP_X] = "semop_x",
	[PPME_SYSCALL_GETRESUID_E] = "getresuid_e",
	[PPME_SYSCALL_GETRESUID_X] = "getresuid_x",
	[PPME_SYSCALL_SENDFILE_E] = "sendfile_e",
	[PPME_SYSCALL_SENDFILE_X] = "sendfile_x",
	[PPME_SYSCALL_FUTEX_E] = "futex_e",
	[PPME_SYSCALL_FUTEX_X] = "futex_x",
	[PPME_SYSCALL_STAT_E] = "stat_e",
	[PPME_SYSCALL_STAT_X] = "stat_x",
	[PPME_SYSCALL_LSEEK_E] = "lseek_e",
	[PPME_SYSCALL_LSEEK_X] = "lseek_x",
	[PPME_SYSCALL_LLSEEK_E] = "llseek_e",
	[PPME_SYSCALL_LLSEEK_X] = "llseek_x",
	[PPME_SYSCALL_WRITE_E] = "write_e",
	[PPME_SYSCALL_WRITE_X] = "write_x",
	[PPME_SYSCALL_GETRESGID_E] = "getresgid_e",
	[PPME_SYSCALL_GETRESGID_X] = "getresgid_x",
	[PPME_SYSCALL_CHOWN_E] = "chown_e",
	[PPME_SYSCALL_CHOWN_X] = "chown_x",
	[PPME_SYSCALL_LCHOWN_E] = "lchown_e",
	[PPME_SYSCALL_LCHOWN_X] = "lchown_x",
	[PPME_SYSCALL_FCHOWN_E] = "fchown_e",
	[PPME_SYSCALL_FCHOWN_X] = "fchown_x",
	[PPME_SYSCALL_FCHOWNAT_E] = "fchownat_e",
	[PPME_SYSCALL_FCHOWNAT_X] = "fchownat_x",
	[PPME_SYSCALL_BRK_4_E] = "brk_e",
	[PPME_SYSCALL_BRK_4_X] = "brk_x",
	[PPME_SYSCALL_NANOSLEEP_E] = "nanosleep_e",
	[PPME_SYSCALL_NANOSLEEP_X] = "nanosleep_x",
	[PPME_SYSCALL_UMOUNT_1_E] = "umount_e",
	[PPME_SYSCALL_UMOUNT_1_X] = "umount_x",
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
