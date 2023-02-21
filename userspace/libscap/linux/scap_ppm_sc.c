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

#include "scap.h"
#include "scap-int.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

/*
 * When adding a new event, a new line should be added with the list of ppm_sc codes mapping that event.
 * Events that are not mapped to any ppm_sc (ie: "container", "useradded"..., have NULL entries.
 * Events that are mapped to an unknown syscall (eg: `send` that is not available on any of the supported architectures),
 * will have PPM_SC_UNKNOWN value.
 *
 * If adding a specific event mapping an existing generic event, remember to
 * remove the generic events from the first 2 lines.
 *
 * NOTE: first 2 lines are automatically bumped by syscalls-bumper.
 */
static const ppm_sc_code *g_events_to_sc_map[PPM_EVENT_MAX] = {
	(ppm_sc_code[]){ PPM_SC_RESTART_SYSCALL, PPM_SC_EXIT, PPM_SC_TIME,  PPM_SC_MKNOD, PPM_SC_GETPID, PPM_SC_SYNC, PPM_SC_TIMES, PPM_SC_ACCT, PPM_SC_UMASK, PPM_SC_USTAT, PPM_SC_GETPPID, PPM_SC_GETPGRP, PPM_SC_SETHOSTNAME, PPM_SC_GETRUSAGE, PPM_SC_GETTIMEOFDAY, PPM_SC_SETTIMEOFDAY, PPM_SC_READLINK, PPM_SC_SWAPON, PPM_SC_REBOOT, PPM_SC_TRUNCATE, PPM_SC_FTRUNCATE, PPM_SC_GETPRIORITY, PPM_SC_SETPRIORITY, PPM_SC_STATFS, PPM_SC_FSTATFS, PPM_SC_SETITIMER, PPM_SC_GETITIMER, PPM_SC_UNAME, PPM_SC_VHANGUP, PPM_SC_WAIT4, PPM_SC_SWAPOFF, PPM_SC_SYSINFO, PPM_SC_FSYNC, PPM_SC_SETDOMAINNAME, PPM_SC_ADJTIMEX, PPM_SC_INIT_MODULE, PPM_SC_DELETE_MODULE, PPM_SC_GETPGID, PPM_SC_SYSFS, PPM_SC_PERSONALITY, PPM_SC_MSYNC, PPM_SC_GETSID, PPM_SC_FDATASYNC, PPM_SC_SCHED_SETSCHEDULER, PPM_SC_SCHED_GETSCHEDULER, PPM_SC_SCHED_YIELD, PPM_SC_SCHED_GET_PRIORITY_MAX, PPM_SC_SCHED_GET_PRIORITY_MIN, PPM_SC_SCHED_RR_GET_INTERVAL, PPM_SC_MREMAP, PPM_SC_PRCTL, PPM_SC_ARCH_PRCTL, PPM_SC_RT_SIGACTION, PPM_SC_RT_SIGPROCMASK, PPM_SC_RT_SIGPENDING, PPM_SC_RT_SIGTIMEDWAIT, PPM_SC_RT_SIGQUEUEINFO, PPM_SC_RT_SIGSUSPEND, PPM_SC_CAPGET, PPM_SC_SETREUID, PPM_SC_SETREGID, PPM_SC_GETGROUPS, PPM_SC_SETGROUPS, PPM_SC_SETFSUID, PPM_SC_SETFSGID, PPM_SC_PIVOT_ROOT, PPM_SC_MINCORE, PPM_SC_MADVISE, PPM_SC_GETTID, PPM_SC_SETXATTR, PPM_SC_LSETXATTR, PPM_SC_FSETXATTR, PPM_SC_GETXATTR, PPM_SC_LGETXATTR, PPM_SC_FGETXATTR, PPM_SC_LISTXATTR, PPM_SC_LLISTXATTR, PPM_SC_FLISTXATTR, PPM_SC_REMOVEXATTR, PPM_SC_LREMOVEXATTR, PPM_SC_FREMOVEXATTR,PPM_SC_SCHED_SETAFFINITY, PPM_SC_SCHED_GETAFFINITY, PPM_SC_SET_THREAD_AREA, PPM_SC_GET_THREAD_AREA, PPM_SC_IO_SETUP, PPM_SC_IO_DESTROY, PPM_SC_IO_GETEVENTS, PPM_SC_IO_SUBMIT, PPM_SC_IO_CANCEL, PPM_SC_EXIT_GROUP, PPM_SC_REMAP_FILE_PAGES, PPM_SC_SET_TID_ADDRESS, PPM_SC_TIMER_CREATE, PPM_SC_TIMER_SETTIME, PPM_SC_TIMER_GETTIME, PPM_SC_TIMER_GETOVERRUN, PPM_SC_TIMER_DELETE, PPM_SC_CLOCK_SETTIME, PPM_SC_CLOCK_GETTIME, PPM_SC_CLOCK_GETRES, PPM_SC_CLOCK_NANOSLEEP,PPM_SC_UTIMES, PPM_SC_MQ_OPEN, PPM_SC_MQ_UNLINK, PPM_SC_MQ_TIMEDSEND, PPM_SC_MQ_TIMEDRECEIVE, PPM_SC_MQ_NOTIFY, PPM_SC_MQ_GETSETATTR, PPM_SC_KEXEC_LOAD, PPM_SC_WAITID, PPM_SC_ADD_KEY, PPM_SC_REQUEST_KEY, PPM_SC_KEYCTL, PPM_SC_IOPRIO_SET, PPM_SC_IOPRIO_GET, PPM_SC_INOTIFY_ADD_WATCH, PPM_SC_INOTIFY_RM_WATCH, PPM_SC_MKNODAT, PPM_SC_FUTIMESAT, PPM_SC_READLINKAT, PPM_SC_FACCESSAT, PPM_SC_SET_ROBUST_LIST, PPM_SC_GET_ROBUST_LIST, PPM_SC_TEE, PPM_SC_VMSPLICE, PPM_SC_GETCPU, PPM_SC_EPOLL_PWAIT, PPM_SC_UTIMENSAT, PPM_SC_TIMERFD_SETTIME, PPM_SC_TIMERFD_GETTIME, PPM_SC_RT_TGSIGQUEUEINFO, PPM_SC_PERF_EVENT_OPEN, PPM_SC_FANOTIFY_INIT, PPM_SC_CLOCK_ADJTIME, PPM_SC_SYNCFS, PPM_SC_MSGSND, PPM_SC_MSGRCV, PPM_SC_MSGGET, PPM_SC_MSGCTL, PPM_SC_SHMDT, PPM_SC_SHMGET, PPM_SC_SHMCTL, PPM_SC_STATFS64, PPM_SC_FSTATFS64, PPM_SC_FSTATAT64, PPM_SC_BDFLUSH, PPM_SC_SIGPROCMASK, PPM_SC_IPC, PPM_SC_LSTAT64, PPM_SC__NEWSELECT, PPM_SC_SGETMASK, PPM_SC_SSETMASK, PPM_SC_SIGPENDING, PPM_SC_OLDUNAME, PPM_SC_UMOUNT, PPM_SC_SIGNAL, PPM_SC_NICE, PPM_SC_STIME, PPM_SC_WAITPID, PPM_SC_SHMAT, PPM_SC_RT_SIGRETURN, PPM_SC_FALLOCATE, PPM_SC_NEWFSTATAT, PPM_SC_FINIT_MODULE, PPM_SC_SIGALTSTACK, PPM_SC_GETRANDOM, PPM_SC_FADVISE64, PPM_SC_SOCKETCALL, PPM_SC_FSPICK, PPM_SC_FSMOUNT, PPM_SC_FSOPEN, PPM_SC_OPEN_TREE, PPM_SC_MOVE_MOUNT, PPM_SC_MOUNT_SETATTR, PPM_SC_MEMFD_CREATE, PPM_SC_MEMFD_SECRET, PPM_SC_IOPERM, PPM_SC_KEXEC_FILE_LOAD, PPM_SC_PIDFD_GETFD, PPM_SC_PIDFD_OPEN, PPM_SC_PIDFD_SEND_SIGNAL, PPM_SC_PKEY_ALLOC, PPM_SC_PKEY_MPROTECT, PPM_SC_PKEY_FREE, PPM_SC_LANDLOCK_CREATE_RULESET, PPM_SC_QUOTACTL_FD, PPM_SC_LANDLOCK_RESTRICT_SELF, PPM_SC_LANDLOCK_ADD_RULE, PPM_SC_EPOLL_PWAIT2, PPM_SC_MIGRATE_PAGES, PPM_SC_MOVE_PAGES, PPM_SC_PREADV2, PPM_SC_PWRITEV2, PPM_SC_QUERY_MODULE, PPM_SC_STATX, PPM_SC_SET_MEMPOLICY, PPM_SC_FANOTIFY_MARK, PPM_SC_SYNC_FILE_RANGE, PPM_SC_READAHEAD, PPM_SC_PROCESS_MRELEASE, PPM_SC_MBIND, PPM_SC_PROCESS_MADVISE, PPM_SC_MEMBARRIER, PPM_SC_MODIFY_LDT, PPM_SC_SEMTIMEDOP, PPM_SC_NAME_TO_HANDLE_AT, PPM_SC_KCMP, PPM_SC_EPOLL_CTL_OLD, PPM_SC_EPOLL_WAIT_OLD, PPM_SC_FUTEX_WAITV, PPM_SC_CREATE_MODULE, PPM_SC__SYSCTL, PPM_SC_LOOKUP_DCOOKIE, PPM_SC_IOPL, PPM_SC_IO_PGETEVENTS, PPM_SC_GETPMSG, PPM_SC_SCHED_SETATTR, PPM_SC_GET_KERNEL_SYMS, PPM_SC_RSEQ, PPM_SC_CLOSE_RANGE, PPM_SC_GET_MEMPOLICY, PPM_SC_SCHED_GETATTR, PPM_SC_NFSSERVCTL, PPM_SC_SET_MEMPOLICY_HOME_NODE, PPM_SC_FACCESSAT2, PPM_SC_EPOLL_CTL, PPM_SC_PROCESS_VM_WRITEV, PPM_SC_SCHED_GETPARAM, PPM_SC_PSELECT6, PPM_SC_SCHED_SETPARAM, PPM_SC_PROCESS_VM_READV, PPM_SC_PAUSE, PPM_SC_UTIME, PPM_SC_SYSLOG, PPM_SC_USELIB, PPM_SC_ALARM, -1},
	(ppm_sc_code[]){ PPM_SC_RESTART_SYSCALL, PPM_SC_EXIT, PPM_SC_TIME,  PPM_SC_MKNOD, PPM_SC_GETPID, PPM_SC_SYNC, PPM_SC_TIMES, PPM_SC_ACCT, PPM_SC_UMASK, PPM_SC_USTAT, PPM_SC_GETPPID, PPM_SC_GETPGRP, PPM_SC_SETHOSTNAME, PPM_SC_GETRUSAGE, PPM_SC_GETTIMEOFDAY, PPM_SC_SETTIMEOFDAY, PPM_SC_READLINK, PPM_SC_SWAPON, PPM_SC_REBOOT, PPM_SC_TRUNCATE, PPM_SC_FTRUNCATE, PPM_SC_GETPRIORITY, PPM_SC_SETPRIORITY, PPM_SC_STATFS, PPM_SC_FSTATFS, PPM_SC_SETITIMER, PPM_SC_GETITIMER, PPM_SC_UNAME, PPM_SC_VHANGUP, PPM_SC_WAIT4, PPM_SC_SWAPOFF, PPM_SC_SYSINFO, PPM_SC_FSYNC, PPM_SC_SETDOMAINNAME, PPM_SC_ADJTIMEX, PPM_SC_INIT_MODULE, PPM_SC_DELETE_MODULE, PPM_SC_GETPGID, PPM_SC_SYSFS, PPM_SC_PERSONALITY, PPM_SC_MSYNC, PPM_SC_GETSID, PPM_SC_FDATASYNC, PPM_SC_SCHED_SETSCHEDULER, PPM_SC_SCHED_GETSCHEDULER, PPM_SC_SCHED_YIELD, PPM_SC_SCHED_GET_PRIORITY_MAX, PPM_SC_SCHED_GET_PRIORITY_MIN, PPM_SC_SCHED_RR_GET_INTERVAL, PPM_SC_MREMAP, PPM_SC_PRCTL, PPM_SC_ARCH_PRCTL, PPM_SC_RT_SIGACTION, PPM_SC_RT_SIGPROCMASK, PPM_SC_RT_SIGPENDING, PPM_SC_RT_SIGTIMEDWAIT, PPM_SC_RT_SIGQUEUEINFO, PPM_SC_RT_SIGSUSPEND, PPM_SC_CAPGET, PPM_SC_SETREUID, PPM_SC_SETREGID, PPM_SC_GETGROUPS, PPM_SC_SETGROUPS, PPM_SC_SETFSUID, PPM_SC_SETFSGID, PPM_SC_PIVOT_ROOT, PPM_SC_MINCORE, PPM_SC_MADVISE, PPM_SC_GETTID, PPM_SC_SETXATTR, PPM_SC_LSETXATTR, PPM_SC_FSETXATTR, PPM_SC_GETXATTR, PPM_SC_LGETXATTR, PPM_SC_FGETXATTR, PPM_SC_LISTXATTR, PPM_SC_LLISTXATTR, PPM_SC_FLISTXATTR, PPM_SC_REMOVEXATTR, PPM_SC_LREMOVEXATTR, PPM_SC_FREMOVEXATTR,PPM_SC_SCHED_SETAFFINITY, PPM_SC_SCHED_GETAFFINITY, PPM_SC_SET_THREAD_AREA, PPM_SC_GET_THREAD_AREA, PPM_SC_IO_SETUP, PPM_SC_IO_DESTROY, PPM_SC_IO_GETEVENTS, PPM_SC_IO_SUBMIT, PPM_SC_IO_CANCEL, PPM_SC_EXIT_GROUP, PPM_SC_REMAP_FILE_PAGES, PPM_SC_SET_TID_ADDRESS, PPM_SC_TIMER_CREATE, PPM_SC_TIMER_SETTIME, PPM_SC_TIMER_GETTIME, PPM_SC_TIMER_GETOVERRUN, PPM_SC_TIMER_DELETE, PPM_SC_CLOCK_SETTIME, PPM_SC_CLOCK_GETTIME, PPM_SC_CLOCK_GETRES, PPM_SC_CLOCK_NANOSLEEP,PPM_SC_UTIMES, PPM_SC_MQ_OPEN, PPM_SC_MQ_UNLINK, PPM_SC_MQ_TIMEDSEND, PPM_SC_MQ_TIMEDRECEIVE, PPM_SC_MQ_NOTIFY, PPM_SC_MQ_GETSETATTR, PPM_SC_KEXEC_LOAD, PPM_SC_WAITID, PPM_SC_ADD_KEY, PPM_SC_REQUEST_KEY, PPM_SC_KEYCTL, PPM_SC_IOPRIO_SET, PPM_SC_IOPRIO_GET, PPM_SC_INOTIFY_ADD_WATCH, PPM_SC_INOTIFY_RM_WATCH, PPM_SC_MKNODAT, PPM_SC_FUTIMESAT, PPM_SC_READLINKAT, PPM_SC_FACCESSAT, PPM_SC_SET_ROBUST_LIST, PPM_SC_GET_ROBUST_LIST, PPM_SC_TEE, PPM_SC_VMSPLICE, PPM_SC_GETCPU, PPM_SC_EPOLL_PWAIT, PPM_SC_UTIMENSAT, PPM_SC_TIMERFD_SETTIME, PPM_SC_TIMERFD_GETTIME, PPM_SC_RT_TGSIGQUEUEINFO, PPM_SC_PERF_EVENT_OPEN, PPM_SC_FANOTIFY_INIT, PPM_SC_CLOCK_ADJTIME, PPM_SC_SYNCFS, PPM_SC_MSGSND, PPM_SC_MSGRCV, PPM_SC_MSGGET, PPM_SC_MSGCTL, PPM_SC_SHMDT, PPM_SC_SHMGET, PPM_SC_SHMCTL, PPM_SC_STATFS64, PPM_SC_FSTATFS64, PPM_SC_FSTATAT64, PPM_SC_BDFLUSH, PPM_SC_SIGPROCMASK, PPM_SC_IPC, PPM_SC_LSTAT64, PPM_SC__NEWSELECT, PPM_SC_SGETMASK, PPM_SC_SSETMASK, PPM_SC_SIGPENDING, PPM_SC_OLDUNAME, PPM_SC_UMOUNT, PPM_SC_SIGNAL, PPM_SC_NICE, PPM_SC_STIME, PPM_SC_WAITPID, PPM_SC_SHMAT, PPM_SC_RT_SIGRETURN, PPM_SC_FALLOCATE, PPM_SC_NEWFSTATAT, PPM_SC_FINIT_MODULE, PPM_SC_SIGALTSTACK, PPM_SC_GETRANDOM, PPM_SC_FADVISE64, PPM_SC_SOCKETCALL, PPM_SC_FSPICK, PPM_SC_FSMOUNT, PPM_SC_FSOPEN, PPM_SC_OPEN_TREE, PPM_SC_MOVE_MOUNT, PPM_SC_MOUNT_SETATTR, PPM_SC_MEMFD_CREATE, PPM_SC_MEMFD_SECRET, PPM_SC_IOPERM, PPM_SC_KEXEC_FILE_LOAD, PPM_SC_PIDFD_GETFD, PPM_SC_PIDFD_OPEN, PPM_SC_PIDFD_SEND_SIGNAL, PPM_SC_PKEY_ALLOC, PPM_SC_PKEY_MPROTECT, PPM_SC_PKEY_FREE, PPM_SC_LANDLOCK_CREATE_RULESET, PPM_SC_QUOTACTL_FD, PPM_SC_LANDLOCK_RESTRICT_SELF, PPM_SC_LANDLOCK_ADD_RULE, PPM_SC_EPOLL_PWAIT2, PPM_SC_MIGRATE_PAGES, PPM_SC_MOVE_PAGES, PPM_SC_PREADV2, PPM_SC_PWRITEV2, PPM_SC_QUERY_MODULE, PPM_SC_STATX, PPM_SC_SET_MEMPOLICY, PPM_SC_FANOTIFY_MARK, PPM_SC_SYNC_FILE_RANGE, PPM_SC_READAHEAD, PPM_SC_PROCESS_MRELEASE, PPM_SC_MBIND, PPM_SC_PROCESS_MADVISE, PPM_SC_MEMBARRIER, PPM_SC_MODIFY_LDT, PPM_SC_SEMTIMEDOP, PPM_SC_NAME_TO_HANDLE_AT, PPM_SC_KCMP, PPM_SC_EPOLL_CTL_OLD, PPM_SC_EPOLL_WAIT_OLD, PPM_SC_FUTEX_WAITV, PPM_SC_CREATE_MODULE, PPM_SC__SYSCTL, PPM_SC_LOOKUP_DCOOKIE, PPM_SC_IOPL, PPM_SC_IO_PGETEVENTS, PPM_SC_GETPMSG, PPM_SC_SCHED_SETATTR, PPM_SC_GET_KERNEL_SYMS, PPM_SC_RSEQ, PPM_SC_CLOSE_RANGE, PPM_SC_GET_MEMPOLICY, PPM_SC_SCHED_GETATTR, PPM_SC_NFSSERVCTL, PPM_SC_SET_MEMPOLICY_HOME_NODE, PPM_SC_FACCESSAT2, PPM_SC_EPOLL_CTL, PPM_SC_PROCESS_VM_WRITEV, PPM_SC_SCHED_GETPARAM, PPM_SC_PSELECT6, PPM_SC_SCHED_SETPARAM, PPM_SC_PROCESS_VM_READV, PPM_SC_PAUSE, PPM_SC_UTIME, PPM_SC_SYSLOG, PPM_SC_USELIB, PPM_SC_ALARM, -1},
	(ppm_sc_code[]){PPM_SC_OPEN, -1},
	(ppm_sc_code[]){PPM_SC_OPEN, -1},
	(ppm_sc_code[]){PPM_SC_CLOSE, -1},
	(ppm_sc_code[]){PPM_SC_CLOSE, -1},
	(ppm_sc_code[]){PPM_SC_READ, -1},
	(ppm_sc_code[]){PPM_SC_READ, -1},
	(ppm_sc_code[]){PPM_SC_WRITE, -1},
	(ppm_sc_code[]){PPM_SC_WRITE, -1},
	(ppm_sc_code[]){PPM_SC_BRK, -1},
	(ppm_sc_code[]){PPM_SC_BRK, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_SCHED_PROCESS_EXIT, -1},
	NULL,
	(ppm_sc_code[]){PPM_SC_SOCKET, -1},
	(ppm_sc_code[]){PPM_SC_SOCKET, -1},
	(ppm_sc_code[]){PPM_SC_BIND, -1},
	(ppm_sc_code[]){PPM_SC_BIND, -1},
	(ppm_sc_code[]){PPM_SC_CONNECT, -1},
	(ppm_sc_code[]){PPM_SC_CONNECT, -1},
	(ppm_sc_code[]){PPM_SC_LISTEN, -1},
	(ppm_sc_code[]){PPM_SC_LISTEN, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT, -1},
	(ppm_sc_code[]){PPM_SC_UNKNOWN, -1}, // send -> is not impl by supported archs
	(ppm_sc_code[]){PPM_SC_UNKNOWN, -1}, // send -> is not impl by supported archs
	(ppm_sc_code[]){PPM_SC_SENDTO, -1},
	(ppm_sc_code[]){PPM_SC_SENDTO, -1},
	(ppm_sc_code[]){PPM_SC_UNKNOWN, -1}, // recv -> is not impl by supported archs
	(ppm_sc_code[]){PPM_SC_UNKNOWN, -1}, // recv -> is not impl by supported archs
	(ppm_sc_code[]){PPM_SC_RECVFROM, -1},
	(ppm_sc_code[]){PPM_SC_RECVFROM, -1},
	(ppm_sc_code[]){PPM_SC_SHUTDOWN, -1},
	(ppm_sc_code[]){PPM_SC_SHUTDOWN, -1},
	(ppm_sc_code[]){PPM_SC_GETSOCKNAME, -1},
	(ppm_sc_code[]){PPM_SC_GETSOCKNAME, -1},
	(ppm_sc_code[]){PPM_SC_GETPEERNAME, -1},
	(ppm_sc_code[]){PPM_SC_GETPEERNAME, -1},
	(ppm_sc_code[]){PPM_SC_SOCKETPAIR, -1},
	(ppm_sc_code[]){PPM_SC_SOCKETPAIR, -1},
	(ppm_sc_code[]){PPM_SC_SETSOCKOPT, -1},
	(ppm_sc_code[]){PPM_SC_SETSOCKOPT, -1},
	(ppm_sc_code[]){PPM_SC_GETSOCKOPT, -1},
	(ppm_sc_code[]){PPM_SC_GETSOCKOPT, -1},
	(ppm_sc_code[]){PPM_SC_SENDMSG, -1},
	(ppm_sc_code[]){PPM_SC_SENDMSG, -1},
	(ppm_sc_code[]){PPM_SC_SENDMMSG, -1},
	(ppm_sc_code[]){PPM_SC_SENDMMSG, -1},
	(ppm_sc_code[]){PPM_SC_RECVMSG, -1},
	(ppm_sc_code[]){PPM_SC_RECVMSG, -1},
	(ppm_sc_code[]){PPM_SC_RECVMMSG, -1},
	(ppm_sc_code[]){PPM_SC_RECVMMSG, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT, -1},
	(ppm_sc_code[]){PPM_SC_CREAT, -1},
	(ppm_sc_code[]){PPM_SC_CREAT, -1},
	(ppm_sc_code[]){PPM_SC_PIPE, PPM_SC_PIPE2, -1},
	(ppm_sc_code[]){PPM_SC_PIPE, PPM_SC_PIPE2, -1},
	(ppm_sc_code[]){PPM_SC_EVENTFD, PPM_SC_EVENTFD2, -1},
	(ppm_sc_code[]){PPM_SC_EVENTFD, PPM_SC_EVENTFD2, -1},
	(ppm_sc_code[]){PPM_SC_FUTEX, -1},
	(ppm_sc_code[]){PPM_SC_FUTEX, -1},
	(ppm_sc_code[]){PPM_SC_STAT, -1},
	(ppm_sc_code[]){PPM_SC_STAT, -1},
	(ppm_sc_code[]){PPM_SC_LSTAT, -1},
	(ppm_sc_code[]){PPM_SC_LSTAT, -1},
	(ppm_sc_code[]){PPM_SC_FSTAT, -1},
	(ppm_sc_code[]){PPM_SC_FSTAT, -1},
	(ppm_sc_code[]){PPM_SC_STAT64, -1},
	(ppm_sc_code[]){PPM_SC_STAT64, -1},
	(ppm_sc_code[]){PPM_SC_UNKNOWN, -1}, // lstat64 -> is not impl by supported archs
	(ppm_sc_code[]){PPM_SC_UNKNOWN, -1}, // lstat64 -> is not impl by supported archs
	(ppm_sc_code[]){PPM_SC_FSTAT64, -1},
	(ppm_sc_code[]){PPM_SC_FSTAT64, -1},
	(ppm_sc_code[]){PPM_SC_EPOLL_WAIT, -1},
	(ppm_sc_code[]){PPM_SC_EPOLL_WAIT, -1},
	(ppm_sc_code[]){PPM_SC_POLL, -1},
	(ppm_sc_code[]){PPM_SC_POLL, -1},
	(ppm_sc_code[]){PPM_SC_SELECT, -1},
	(ppm_sc_code[]){PPM_SC_SELECT, -1},
	(ppm_sc_code[]){PPM_SC_SELECT, -1},
	(ppm_sc_code[]){PPM_SC_SELECT, -1},
	(ppm_sc_code[]){PPM_SC_LSEEK, -1},
	(ppm_sc_code[]){PPM_SC_LSEEK, -1},
	(ppm_sc_code[]){PPM_SC__LLSEEK, -1},
	(ppm_sc_code[]){PPM_SC__LLSEEK, -1},
	(ppm_sc_code[]){PPM_SC_IOCTL, -1},
	(ppm_sc_code[]){PPM_SC_IOCTL, -1},
	(ppm_sc_code[]){PPM_SC_GETCWD, -1},
	(ppm_sc_code[]){PPM_SC_GETCWD, -1},
	(ppm_sc_code[]){PPM_SC_CHDIR, -1},
	(ppm_sc_code[]){PPM_SC_CHDIR, -1},
	(ppm_sc_code[]){PPM_SC_FCHDIR, -1},
	(ppm_sc_code[]){PPM_SC_FCHDIR, -1},
	(ppm_sc_code[]){PPM_SC_MKDIR, -1},
	(ppm_sc_code[]){PPM_SC_MKDIR, -1},
	(ppm_sc_code[]){PPM_SC_RMDIR, -1},
	(ppm_sc_code[]){PPM_SC_RMDIR, -1},
	(ppm_sc_code[]){PPM_SC_OPENAT, -1},
	(ppm_sc_code[]){PPM_SC_OPENAT, -1},
	(ppm_sc_code[]){PPM_SC_LINK, -1},
	(ppm_sc_code[]){PPM_SC_LINK, -1},
	(ppm_sc_code[]){PPM_SC_LINKAT, -1},
	(ppm_sc_code[]){PPM_SC_LINKAT, -1},
	(ppm_sc_code[]){PPM_SC_UNLINK, -1},
	(ppm_sc_code[]){PPM_SC_UNLINK, -1},
	(ppm_sc_code[]){PPM_SC_UNLINKAT, -1},
	(ppm_sc_code[]){PPM_SC_UNLINKAT, -1},
	(ppm_sc_code[]){PPM_SC_PREAD64, -1},
	(ppm_sc_code[]){PPM_SC_PREAD64, -1},
	(ppm_sc_code[]){PPM_SC_PWRITE64, -1},
	(ppm_sc_code[]){PPM_SC_PWRITE64, -1},
	(ppm_sc_code[]){PPM_SC_READV, -1},
	(ppm_sc_code[]){PPM_SC_READV, -1},
	(ppm_sc_code[]){PPM_SC_WRITEV, -1},
	(ppm_sc_code[]){PPM_SC_WRITEV, -1},
	(ppm_sc_code[]){PPM_SC_PREADV, -1},
	(ppm_sc_code[]){PPM_SC_PREADV, -1},
	(ppm_sc_code[]){PPM_SC_PWRITEV, -1},
	(ppm_sc_code[]){PPM_SC_PWRITEV, -1},
	(ppm_sc_code[]){PPM_SC_DUP, -1},
	(ppm_sc_code[]){PPM_SC_DUP, -1},
	(ppm_sc_code[]){PPM_SC_SIGNALFD, PPM_SC_SIGNALFD4, -1},
	(ppm_sc_code[]){PPM_SC_SIGNALFD, PPM_SC_SIGNALFD4, -1},
	(ppm_sc_code[]){PPM_SC_KILL, -1},
	(ppm_sc_code[]){PPM_SC_KILL, -1},
	(ppm_sc_code[]){PPM_SC_TKILL, -1},
	(ppm_sc_code[]){PPM_SC_TKILL, -1},
	(ppm_sc_code[]){PPM_SC_TGKILL, -1},
	(ppm_sc_code[]){PPM_SC_TGKILL, -1},
	(ppm_sc_code[]){PPM_SC_NANOSLEEP, -1},
	(ppm_sc_code[]){PPM_SC_NANOSLEEP, -1},
	(ppm_sc_code[]){PPM_SC_TIMERFD_CREATE, -1},
	(ppm_sc_code[]){PPM_SC_TIMERFD_CREATE, -1},
	(ppm_sc_code[]){PPM_SC_INOTIFY_INIT, PPM_SC_INOTIFY_INIT1, -1},
	(ppm_sc_code[]){PPM_SC_INOTIFY_INIT, PPM_SC_INOTIFY_INIT1, -1},
	(ppm_sc_code[]){PPM_SC_GETRLIMIT, PPM_SC_UGETRLIMIT, -1},
	(ppm_sc_code[]){PPM_SC_GETRLIMIT, PPM_SC_UGETRLIMIT, -1},
	(ppm_sc_code[]){PPM_SC_SETRLIMIT, -1},
	(ppm_sc_code[]){PPM_SC_SETRLIMIT, -1},
	(ppm_sc_code[]){PPM_SC_PRLIMIT64, -1},
	(ppm_sc_code[]){PPM_SC_PRLIMIT64, -1},
	(ppm_sc_code[]){PPM_SC_SCHED_SWITCH, -1},
	NULL,
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_FCNTL, PPM_SC_FCNTL64, -1},
	(ppm_sc_code[]){PPM_SC_FCNTL, PPM_SC_FCNTL64, -1},
	(ppm_sc_code[]){PPM_SC_SCHED_SWITCH, -1},
	NULL,
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_BRK, -1},
	(ppm_sc_code[]){PPM_SC_BRK, -1},
	(ppm_sc_code[]){PPM_SC_MMAP, -1},
	(ppm_sc_code[]){PPM_SC_MMAP, -1},
	(ppm_sc_code[]){PPM_SC_MMAP2, -1},
	(ppm_sc_code[]){PPM_SC_MMAP2, -1},
	(ppm_sc_code[]){PPM_SC_MUNMAP, -1},
	(ppm_sc_code[]){PPM_SC_MUNMAP, -1},
	(ppm_sc_code[]){PPM_SC_SPLICE, -1},
	(ppm_sc_code[]){PPM_SC_SPLICE, -1},
	(ppm_sc_code[]){PPM_SC_PTRACE, -1},
	(ppm_sc_code[]){PPM_SC_PTRACE, -1},
	(ppm_sc_code[]){PPM_SC_IOCTL, -1},
	(ppm_sc_code[]){PPM_SC_IOCTL, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_RENAME, -1},
	(ppm_sc_code[]){PPM_SC_RENAME, -1},
	(ppm_sc_code[]){PPM_SC_RENAMEAT, -1},
	(ppm_sc_code[]){PPM_SC_RENAMEAT, -1},
	(ppm_sc_code[]){PPM_SC_SYMLINK, -1},
	(ppm_sc_code[]){PPM_SC_SYMLINK, -1},
	(ppm_sc_code[]){PPM_SC_SYMLINKAT, -1},
	(ppm_sc_code[]){PPM_SC_SYMLINKAT, -1},
	(ppm_sc_code[]){PPM_SC_FORK, -1},
	(ppm_sc_code[]){PPM_SC_FORK, -1},
	(ppm_sc_code[]){PPM_SC_VFORK, -1},
	(ppm_sc_code[]){PPM_SC_VFORK, -1},
	(ppm_sc_code[]){PPM_SC_SCHED_PROCESS_EXIT, -1},
	NULL,
	(ppm_sc_code[]){PPM_SC_SENDFILE, PPM_SC_SENDFILE64, -1},
	(ppm_sc_code[]){PPM_SC_SENDFILE, PPM_SC_SENDFILE64, -1},
	(ppm_sc_code[]){PPM_SC_QUOTACTL, -1},
	(ppm_sc_code[]){PPM_SC_QUOTACTL, -1},
	(ppm_sc_code[]){PPM_SC_SETRESUID, PPM_SC_SETRESUID32,  -1},
	(ppm_sc_code[]){PPM_SC_SETRESUID, PPM_SC_SETRESUID32,  -1},
	(ppm_sc_code[]){PPM_SC_SETRESGID,  PPM_SC_SETRESGID32, -1},
	(ppm_sc_code[]){PPM_SC_SETRESGID, PPM_SC_SETRESGID32, -1},
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_SETUID, PPM_SC_SETUID32, -1},
	(ppm_sc_code[]){PPM_SC_SETUID, PPM_SC_SETUID32, -1},
	(ppm_sc_code[]){PPM_SC_SETGID, PPM_SC_SETGID32, -1},
	(ppm_sc_code[]){PPM_SC_SETGID, PPM_SC_SETGID32, -1},
	(ppm_sc_code[]){PPM_SC_GETUID, PPM_SC_GETUID32, -1},
	(ppm_sc_code[]){PPM_SC_GETUID, PPM_SC_GETUID32, -1},
	(ppm_sc_code[]){PPM_SC_GETEUID, PPM_SC_GETEUID32,  -1},
	(ppm_sc_code[]){PPM_SC_GETEUID, PPM_SC_GETEUID32, -1},
	(ppm_sc_code[]){PPM_SC_GETGID, PPM_SC_GETGID32, -1},
	(ppm_sc_code[]){PPM_SC_GETGID, PPM_SC_GETGID32, -1},
	(ppm_sc_code[]){PPM_SC_GETEGID, PPM_SC_GETEGID32, -1},
	(ppm_sc_code[]){PPM_SC_GETEGID, PPM_SC_GETEGID32, -1},
	(ppm_sc_code[]){PPM_SC_GETRESUID,  PPM_SC_GETRESUID32, -1},
	(ppm_sc_code[]){PPM_SC_GETRESUID, PPM_SC_GETRESUID32, -1},
	(ppm_sc_code[]){PPM_SC_GETRESGID, PPM_SC_GETRESGID32, -1},
	(ppm_sc_code[]){PPM_SC_GETRESGID, PPM_SC_GETRESGID32, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_FORK, -1},
	(ppm_sc_code[]){PPM_SC_FORK, -1},
	(ppm_sc_code[]){PPM_SC_VFORK, -1},
	(ppm_sc_code[]){PPM_SC_VFORK, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE, -1},
	(ppm_sc_code[]){PPM_SC_FORK, -1},
	(ppm_sc_code[]){PPM_SC_FORK, -1},
	(ppm_sc_code[]){PPM_SC_VFORK, -1},
	(ppm_sc_code[]){PPM_SC_VFORK, -1},
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_SIGNAL_DELIVER, -1},
	NULL,
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_GETDENTS, -1},
	(ppm_sc_code[]){PPM_SC_GETDENTS, -1},
	(ppm_sc_code[]){PPM_SC_GETDENTS64, -1},
	(ppm_sc_code[]){PPM_SC_GETDENTS64, -1},
	(ppm_sc_code[]){PPM_SC_SETNS, -1},
	(ppm_sc_code[]){PPM_SC_SETNS, -1},
	(ppm_sc_code[]){PPM_SC_FLOCK, -1},
	(ppm_sc_code[]){PPM_SC_FLOCK, -1},
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_ACCEPT, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT4, -1},
	(ppm_sc_code[]){PPM_SC_ACCEPT4, -1},
	(ppm_sc_code[]){PPM_SC_SEMOP, -1},
	(ppm_sc_code[]){PPM_SC_SEMOP, -1},
	(ppm_sc_code[]){PPM_SC_SEMCTL, -1},
	(ppm_sc_code[]){PPM_SC_SEMCTL, -1},
	(ppm_sc_code[]){PPM_SC_PPOLL, -1},
	(ppm_sc_code[]){PPM_SC_PPOLL, -1},
	(ppm_sc_code[]){PPM_SC_MOUNT, -1},
	(ppm_sc_code[]){PPM_SC_MOUNT, -1},
	(ppm_sc_code[]){PPM_SC_UMOUNT2, -1},
	(ppm_sc_code[]){PPM_SC_UMOUNT2, -1},
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_SEMGET, -1},
	(ppm_sc_code[]){PPM_SC_SEMGET, -1},
	(ppm_sc_code[]){PPM_SC_ACCESS, -1},
	(ppm_sc_code[]){PPM_SC_ACCESS, -1},
	(ppm_sc_code[]){PPM_SC_CHROOT, -1},
	(ppm_sc_code[]){PPM_SC_CHROOT, -1},
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_SETSID, -1},
	(ppm_sc_code[]){PPM_SC_SETSID, -1},
	(ppm_sc_code[]){PPM_SC_MKDIR, -1},
	(ppm_sc_code[]){PPM_SC_MKDIR, -1},
	(ppm_sc_code[]){PPM_SC_RMDIR, -1},
	(ppm_sc_code[]){PPM_SC_RMDIR, -1},
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_UNSHARE, -1},
	(ppm_sc_code[]){PPM_SC_UNSHARE, -1},
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_PAGE_FAULT_USER, PPM_SC_PAGE_FAULT_KERNEL, -1},
	NULL,
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_EXECVE, -1},
	(ppm_sc_code[]){PPM_SC_SETPGID, -1},
	(ppm_sc_code[]){PPM_SC_SETPGID, -1},
	(ppm_sc_code[]){PPM_SC_BPF, -1},
	(ppm_sc_code[]){PPM_SC_BPF, -1},
	(ppm_sc_code[]){PPM_SC_SECCOMP, -1},
	(ppm_sc_code[]){PPM_SC_SECCOMP, -1},
	(ppm_sc_code[]){PPM_SC_UNLINK, -1},
	(ppm_sc_code[]){PPM_SC_UNLINK, -1},
	(ppm_sc_code[]){PPM_SC_UNLINKAT, -1},
	(ppm_sc_code[]){PPM_SC_UNLINKAT, -1},
	(ppm_sc_code[]){PPM_SC_MKDIRAT, -1},
	(ppm_sc_code[]){PPM_SC_MKDIRAT, -1},
	(ppm_sc_code[]){PPM_SC_OPENAT, -1},
	(ppm_sc_code[]){PPM_SC_OPENAT, -1},
	(ppm_sc_code[]){PPM_SC_LINK, -1},
	(ppm_sc_code[]){PPM_SC_LINK, -1},
	(ppm_sc_code[]){PPM_SC_LINKAT, -1},
	(ppm_sc_code[]){PPM_SC_LINKAT, -1},
	(ppm_sc_code[]){PPM_SC_FCHMODAT, -1},
	(ppm_sc_code[]){PPM_SC_FCHMODAT, -1},
	(ppm_sc_code[]){PPM_SC_CHMOD, -1},
	(ppm_sc_code[]){PPM_SC_CHMOD, -1},
	(ppm_sc_code[]){PPM_SC_FCHMOD, -1},
	(ppm_sc_code[]){PPM_SC_FCHMOD, -1},
	(ppm_sc_code[]){PPM_SC_RENAMEAT2, -1},
	(ppm_sc_code[]){PPM_SC_RENAMEAT2, -1},
	(ppm_sc_code[]){PPM_SC_USERFAULTFD, -1},
	(ppm_sc_code[]){PPM_SC_USERFAULTFD, -1},
	NULL,
	NULL,
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_OPENAT2, -1},
	(ppm_sc_code[]){PPM_SC_OPENAT2, -1},
	(ppm_sc_code[]){PPM_SC_MPROTECT, -1},
	(ppm_sc_code[]){PPM_SC_MPROTECT, -1},
	(ppm_sc_code[]){PPM_SC_EXECVEAT, -1},
	(ppm_sc_code[]){PPM_SC_EXECVEAT, -1},
	(ppm_sc_code[]){PPM_SC_COPY_FILE_RANGE, -1},
	(ppm_sc_code[]){PPM_SC_COPY_FILE_RANGE, -1},
	(ppm_sc_code[]){PPM_SC_CLONE3, -1},
	(ppm_sc_code[]){PPM_SC_CLONE3, -1},
	(ppm_sc_code[]){PPM_SC_OPEN_BY_HANDLE_AT, -1},
	(ppm_sc_code[]){PPM_SC_OPEN_BY_HANDLE_AT, -1},
	(ppm_sc_code[]){PPM_SC_IO_URING_SETUP, -1},
	(ppm_sc_code[]){PPM_SC_IO_URING_SETUP, -1},
	(ppm_sc_code[]){PPM_SC_IO_URING_ENTER, -1},
	(ppm_sc_code[]){PPM_SC_IO_URING_ENTER, -1},
	(ppm_sc_code[]){PPM_SC_IO_URING_REGISTER, -1},
	(ppm_sc_code[]){PPM_SC_IO_URING_REGISTER, -1},
	(ppm_sc_code[]){PPM_SC_MLOCK, -1},
	(ppm_sc_code[]){PPM_SC_MLOCK, -1},
	(ppm_sc_code[]){PPM_SC_MUNLOCK, -1},
	(ppm_sc_code[]){PPM_SC_MUNLOCK, -1},
	(ppm_sc_code[]){PPM_SC_MLOCKALL, -1},
	(ppm_sc_code[]){PPM_SC_MLOCKALL, -1},
	(ppm_sc_code[]){PPM_SC_MUNLOCKALL, -1},
	(ppm_sc_code[]){PPM_SC_MUNLOCKALL, -1},
	(ppm_sc_code[]){PPM_SC_CAPSET, -1},
	(ppm_sc_code[]){PPM_SC_CAPSET, -1},
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_DUP2, -1},
	(ppm_sc_code[]){PPM_SC_DUP2, -1},
	(ppm_sc_code[]){PPM_SC_DUP3, -1},
	(ppm_sc_code[]){PPM_SC_DUP3, -1},
	(ppm_sc_code[]){PPM_SC_DUP, -1},
	(ppm_sc_code[]){PPM_SC_DUP, -1},
	(ppm_sc_code[]){PPM_SC_BPF, -1},
	(ppm_sc_code[]){PPM_SC_BPF, -1},
	(ppm_sc_code[]){PPM_SC_MLOCK2, -1},
	(ppm_sc_code[]){PPM_SC_MLOCK2, -1},
	(ppm_sc_code[]){PPM_SC_FSCONFIG, -1},
	(ppm_sc_code[]){PPM_SC_FSCONFIG, -1},
	(ppm_sc_code[]){PPM_SC_EPOLL_CREATE, -1},
	(ppm_sc_code[]){PPM_SC_EPOLL_CREATE, -1},
	(ppm_sc_code[]){PPM_SC_EPOLL_CREATE1, -1},
	(ppm_sc_code[]){PPM_SC_EPOLL_CREATE1, -1},
	(ppm_sc_code[]){PPM_SC_CHOWN, -1},
	(ppm_sc_code[]){PPM_SC_CHOWN, -1},
	(ppm_sc_code[]){PPM_SC_LCHOWN, -1},
	(ppm_sc_code[]){PPM_SC_LCHOWN, -1},
	(ppm_sc_code[]){PPM_SC_FCHOWN, -1},
	(ppm_sc_code[]){PPM_SC_FCHOWN, -1},
	(ppm_sc_code[]){PPM_SC_FCHOWNAT, -1},
	(ppm_sc_code[]){PPM_SC_FCHOWNAT, -1},
};

int scap_get_modifies_state_ppm_sc(OUT uint8_t ppm_sc_array[PPM_SC_MAX])
{
	if(ppm_sc_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(ppm_sc_array, 0, sizeof(*ppm_sc_array) * PPM_SC_MAX);

	uint8_t events_array[PPM_EVENT_MAX] = {0};
	// Collect EF_MODIFIES_STATE events
	for (int event_nr = 2; event_nr < PPM_EVENT_MAX; event_nr++)
	{
		if (g_event_info[event_nr].flags & EF_MODIFIES_STATE &&
		   (g_event_info[event_nr].category & EC_SYSCALL ||
		    g_event_info[event_nr].category & EC_TRACEPOINT))
		{
			events_array[event_nr] = 1;
		}
	}

	// Transform them into ppm_sc
	scap_get_ppm_sc_from_events(events_array, ppm_sc_array);

	// Append UF_NEVER_DROP syscalls too!
	for (int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if (g_syscall_table[syscall_nr].flags & UF_NEVER_DROP)
		{
			uint32_t code = g_syscall_table[syscall_nr].ppm_sc;
			ppm_sc_array[code] = 1;
		}
	}
	return SCAP_SUCCESS;
}

int scap_get_events_from_ppm_sc(IN const uint8_t ppm_sc_array[PPM_SC_MAX], OUT uint8_t events_array[PPM_EVENT_MAX])
{
	if(ppm_sc_array == NULL || events_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(events_array, 0, sizeof(*events_array) * PPM_EVENT_MAX);

	// Load associated events from event_table, skip generics
	for(int ev = 0; ev < PPM_EVENT_MAX; ev++)
	{
		const ppm_sc_code *sc_codes = g_events_to_sc_map[ev];
		while (sc_codes && *sc_codes != -1)
		{
			const ppm_sc_code sc_code = *sc_codes;
			sc_codes++;
			if(ppm_sc_array[sc_code])
			{
				events_array[ev] = 1;
				break;
			}
		}
	}

	return SCAP_SUCCESS;
}

int scap_get_ppm_sc_from_events(IN const uint8_t events_array[PPM_EVENT_MAX], OUT uint8_t ppm_sc_array[PPM_SC_MAX])
{
	if (events_array == NULL || ppm_sc_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(ppm_sc_array, 0, sizeof(*ppm_sc_array) * PPM_SC_MAX);

	bool at_least_one_syscall = false;
	// Load associated ppm_sc from event_table
	for (int ev = 0; ev < PPM_EVENT_MAX; ev++)
	{
		if(!events_array[ev])
		{
			continue;
		}

		const ppm_sc_code *sc_codes = g_events_to_sc_map[ev];
		while (sc_codes && *sc_codes != -1)
		{
			ppm_sc_array[*sc_codes] = 1;
			at_least_one_syscall |= *sc_codes < PPM_SC_SYSCALL_END;
			sc_codes++;
		}
	}

	// Force-set tracepoints that are not mapped to a single event
	// Ie: PPM_SC_SYS_ENTER, PPM_SC_SYS_EXIT, PPM_SC_SCHED_PROCESS_FORK, PPM_SC_SCHED_PROCESS_EXEC
	if (at_least_one_syscall)
	{
		// If there is at least one syscall,
		// make sure to include sys_enter and sys_exit!
		ppm_sc_array[PPM_SC_SYS_ENTER] = 1;
		ppm_sc_array[PPM_SC_SYS_EXIT] = 1;
	}

	// If users requested CLONE3, CLONE, FORK, VFORK,
	// enable also tracepoint to receive them on arm64
	if (ppm_sc_array[PPM_SC_FORK] ||
	   ppm_sc_array[PPM_SC_VFORK] ||
	   ppm_sc_array[PPM_SC_CLONE] ||
	   ppm_sc_array[PPM_SC_CLONE3])
	{
		ppm_sc_array[PPM_SC_SCHED_PROCESS_FORK] = 1;
	}

	// If users requested EXECVE, EXECVEAT
	// enable also tracepoint to receive them on arm64
	if (ppm_sc_array[PPM_SC_EXECVE] ||
	   ppm_sc_array[PPM_SC_EXECVEAT])
	{
		ppm_sc_array[PPM_SC_SCHED_PROCESS_EXEC] = 1;
	}

	return SCAP_SUCCESS;
}

ppm_sc_code scap_ppm_sc_from_name(const char *name)
{
	int start = 0;
	int max = PPM_SC_MAX;
	const char *sc_name = name;

	// Find last '/' occurrence to take only the basename
	// This is useful when used internally, eg: to parse
	// raw_tracepoint/raw_syscalls/sys_enter.
	// This is a small optimization.
	const char *tp_name = strrchr(name, '/');
	if (tp_name && strlen(tp_name) > 1)
	{
		start = PPM_SC_TP_START;
		sc_name = tp_name + 1;
	}
	// else, perhaps users passed a tracepoint name like `signal_deliver` or a syscall name.
	// Since we do not know, try everything.

	const struct ppm_syscall_desc *info_table = scap_get_syscall_info_table();
	for (int i = start; i < max; i++)
	{
		if (strcmp(sc_name, info_table[i].name) == 0)
		{
			return i;
		}
	}
	return -1;
}

ppm_sc_code scap_native_id_to_ppm_sc(int native_id)
{
	if (native_id < 0 || native_id >= SYSCALL_TABLE_SIZE)
	{
		return -1;
	}
	return g_syscall_table[native_id].ppm_sc;
}