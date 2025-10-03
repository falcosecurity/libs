// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
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
#define SYSCALL_X_SIZE HEADER_LEN + sizeof(uint16_t) * 2 + PARAM_LEN * 2
#define CLOSE_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define SOCKET_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define LISTEN_X_SIZE HEADER_LEN + sizeof(int32_t) + sizeof(int64_t) * 2 + PARAM_LEN * 3
#define SHUTDOWN_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define GETSOCKNAME_X_SIZE HEADER_LEN
#define GETPEERNAME_X_SIZE HEADER_LEN
#define SOCKETPAIR_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 8
#define PIPE_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) + PARAM_LEN * 4
#define EVENTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint64_t) + PARAM_LEN * 3
#define FUTEX_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint16_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 4
#define FSTAT_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define FSTAT64_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define EPOLL_WAIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define SELECT_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define LSEEK_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) + sizeof(uint8_t) + PARAM_LEN * 4
#define LLSEEK_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) + sizeof(uint8_t) + PARAM_LEN * 4
#define FCHDIR_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define SIGNALFD_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + sizeof(uint8_t) + PARAM_LEN * 4
#define KILL_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define TKILL_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define TGKILL_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint8_t) + PARAM_LEN * 4
#define NANOSLEEP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) + PARAM_LEN * 2
#define TIMERFD_CREATE_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) * 2 + PARAM_LEN * 3
#define INOTIFY_INIT_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint8_t) + PARAM_LEN * 2
#define GETRLIMIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint8_t) + PARAM_LEN * 4
#define SETRLIMIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint8_t) + PARAM_LEN * 4
#define PRLIMIT_X_SIZE HEADER_LEN + sizeof(int64_t) * 6 + sizeof(uint8_t) + PARAM_LEN * 7
#define DROP_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define DROP_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define FCNTL_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define SWITCH_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 6
#define BRK_X_SIZE HEADER_LEN + sizeof(uint32_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 5
#define MMAP_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) * 5 + sizeof(uint64_t) * 3 + PARAM_LEN * 10
#define MMAP2_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) * 5 + sizeof(uint64_t) * 3 + PARAM_LEN * 10
#define MUNMAP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 6
#define SPLICE_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) + sizeof(uint64_t) + PARAM_LEN * 5
#define IOCTL_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint64_t) * 2 + PARAM_LEN * 4
#define PROCEXIT_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint8_t) * 2 + PARAM_LEN * 5
#define SENDFILE_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) * 2 + PARAM_LEN * 5
#define SETRESUID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define SETRESGID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define SCAPEVENT_E_SIZE HEADER_LEN + sizeof(uint32_t) + sizeof(uint64_t) + PARAM_LEN * 2
#define SETUID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define SETGID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define GETUID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETEUID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETGID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETEGID_X_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define GETRESUID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define GETRESGID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 3 + PARAM_LEN * 4
#define SIGNALDELIVER_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint8_t) + PARAM_LEN * 3
#define PROCINFO_E_SIZE HEADER_LEN + sizeof(uint64_t) * 2 + PARAM_LEN * 2
#define GETDENTS_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define GETDENTS64_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define SETNS_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define FLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define CPU_HOTPLUG_E_SIZE HEADER_LEN + sizeof(uint32_t) * 2 + PARAM_LEN * 2
#define SEMOP_X_SIZE HEADER_LEN + sizeof(int16_t) * 2 + sizeof(int32_t) + sizeof(int64_t) + sizeof(uint16_t) * 4 + sizeof(uint32_t) + PARAM_LEN * 9
#define SEMCTL_X_SIZE HEADER_LEN + sizeof(int32_t) * 3 + sizeof(int64_t) + sizeof(uint16_t) + PARAM_LEN * 5
#define SEMGET_X_SIZE HEADER_LEN + sizeof(int32_t) * 2 + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 4
#define SETSID_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define UNSHARE_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define PAGE_FAULT_SIZE HEADER_LEN + sizeof(uint32_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define SETPGID_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define SECCOMP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define FCHMOD_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define USERFAULTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define MPROTECT_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 4
#define COPY_FILE_RANGE_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint64_t) * 3 + PARAM_LEN * 6
#define IO_URING_SETUP_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 7 + PARAM_LEN * 8
#define IO_URING_ENTER_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) * 4 + PARAM_LEN * 6
#define IO_URING_REGISTER_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint64_t) + PARAM_LEN * 5
#define MLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define MUNLOCK_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 3
#define MLOCKALL_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define MUNLOCKALL_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define CAPSET_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint64_t) * 3 + PARAM_LEN * 4
#define DUP2_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + PARAM_LEN * 3
#define DUP3_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) + PARAM_LEN * 4
#define DUP_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + PARAM_LEN * 2
#define BPF_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define MLOCK2_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint64_t) * 2 + PARAM_LEN * 4
#define EPOLL_CREATE_X_SIZE HEADER_LEN + sizeof(int32_t) + sizeof(int64_t) + PARAM_LEN * 2
#define EPOLL_CREATE1_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define FCHOWN_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) * 2 + PARAM_LEN * 4
#define PIPE2_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) + sizeof(uint64_t) + PARAM_LEN * 5
#define INOTIFY_INIT1_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint16_t) + PARAM_LEN * 2
#define EVENTFD2_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint16_t) + sizeof(uint64_t) + PARAM_LEN * 3
#define SIGNALFD4_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint16_t) + sizeof(uint32_t) + PARAM_LEN * 4
#define PIDFD_GETFD_X_SIZE HEADER_LEN + sizeof(int64_t) * 3 + sizeof(uint32_t) + PARAM_LEN * 4
#define PIDFD_OPEN_X_SIZE HEADER_LEN + sizeof(int64_t) * 2 + sizeof(uint32_t) + PARAM_LEN * 3
#define SETREUID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 2 + PARAM_LEN * 3
#define SETREGID_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) * 2 + PARAM_LEN * 3

#endif /* __EVENT_DIMENSIONS_H__ */
