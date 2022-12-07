/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef __EVENT_DIMENSIONS_H__
#define __EVENT_DIMENSIONS_H__

#include "vmlinux.h"

/* Here we have all the dimensions for fixed-size events.
 */

#define PARAM_LEN 2
#define HEADER_LEN sizeof(struct ppm_evt_hdr)

/// TODO: We have to move these in the event_table.c. Right now we don't
/// want to touch scap tables.

/* Syscall events */
#define MKDIR_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define OPEN_BY_HANDLE_AT_E_SIZE HEADER_LEN
#define CLOSE_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define CLOSE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define COPY_FILE_RANGE_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define COPY_FILE_RANGE_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) + PARAM_LEN * 3
#define DUP_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define DUP_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define DUP2_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define DUP2_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define DUP3_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define DUP3_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) + PARAM_LEN * 4
#define CHDIR_E_SIZE HEADER_LEN
#define CHMOD_E_SIZE HEADER_LEN
#define CHROOT_E_SIZE HEADER_LEN
#define FCHDIR_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FCHDIR_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FCHMOD_E_SIZE HEADER_LEN
#define FCHMOD_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define FCHMODAT_E_SIZE HEADER_LEN
#define MKDIRAT_E_SIZE HEADER_LEN
#define RMDIR_E_SIZE HEADER_LEN
#define EVENTFD_E_SIZE HEADER_LEN + sizeof(uint64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define EVENTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define INOTIFY_INIT_E_SIZE HEADER_LEN + sizeof(uint8_t) + PARAM_LEN
#define INOTIFY_INIT_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TIMERFD_CREATE_E_SIZE HEADER_LEN + sizeof(uint8_t) * 2 + PARAM_LEN * 2
#define TIMERFD_CREATE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define USERFAULTFD_E_SIZE HEADER_LEN
#define USERFAULTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define SIGNALFD_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint8_t) + PARAM_LEN * 3
#define SIGNALFD_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define KILL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define KILL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TGKILL_E_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define TGKILL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TKILL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define TKILL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SECCOMP_E_SIZE HEADER_LEN + sizeof(uint64_t) + PARAM_LEN
#define SECCOMP_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define PTRACE_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint16_t) + PARAM_LEN * 2
#define CAPSET_E_SIZE HEADER_LEN
#define CAPSET_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 3 + PARAM_LEN * 4
#define SOCKET_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SOCKET_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SOCKETPAIR_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SOCKETPAIR_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 5
#define ACCEPT_E_SIZE HEADER_LEN
#define ACCEPT4_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define BIND_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define LISTEN_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define LISTEN_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define CLONE_E_SIZE HEADER_LEN
#define CLONE3_E_SIZE HEADER_LEN
#define FORK_E_SIZE HEADER_LEN
#define VFORK_E_SIZE HEADER_LEN
#define RENAME_E_SIZE HEADER_LEN
#define RENAMEAT_E_SIZE HEADER_LEN
#define RENAMEAT2_E_SIZE HEADER_LEN
#define PIPE_E_SIZE HEADER_LEN
#define PIPE_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) + PARAM_LEN * 4
#define BPF_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define BPF_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FLOCK_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define FLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define IOCTL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define IOCTL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define QUOTACTL_E_SIZE HEADER_LEN + sizeof(uint16_t) + sizeof(uint8_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 4
#define UNSHARE_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define UNSHARE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define MOUNT_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define UMOUNT2_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define LINK_E_SIZE HEADER_LEN
#define LINKAT_E_SIZE HEADER_LEN
#define SYMLINK_E_SIZE HEADER_LEN
#define SYMLINKAT_E_SIZE HEADER_LEN
#define UNLINK_E_SIZE HEADER_LEN
#define UNLINKAT_E_SIZE HEADER_LEN
#define SETGID_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define SETGID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETUID_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define SETUID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETNS_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define SETNS_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETPGID_E_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define SETPGID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETRESGID_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SETRESGID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETRESUID_E_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + PARAM_LEN * 3
#define SETRESUID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETSID_E_SIZE HEADER_LEN
#define SETSID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SETRLIMIT_E_SIZE HEADER_LEN + sizeof(uint8_t) + PARAM_LEN
#define SETRLIMIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define PRLIMIT64_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define PRLIMIT64_X_SIZE HEADER_LEN + sizeof(int64_t) * 5 + PARAM_LEN * 5
#define SETSOCKOPT_E_SIZE HEADER_LEN
#define RECVMSG_E_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define RECVFROM_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define FCNTL_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define FCNTL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define SHUTDOWN_E_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define SHUTDOWN_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define FSCONFIG_E_SIZE HEADER_LEN
#define EPOLL_CREATE_E_SIZE HEADER_LEN + sizeof(int32_t) + PARAM_LEN
#define EPOLL_CREATE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define EPOLL_CREATE1_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define EPOLL_CREATE1_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define ACCESS_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN

/* Generic tracepoints events. */
#define PROC_EXIT_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) * 2 + PARAM_LEN * 4
#define SCHED_SWITCH_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + sizeof(uint32_t) * 3 + PARAM_LEN * 6

#endif /* __EVENT_DIMENSIONS_H__ */
