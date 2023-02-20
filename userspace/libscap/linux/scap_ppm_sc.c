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

static const ppm_sc_code *g_events_to_sc_map[PPM_EVENT_MAX] = {
	(ppm_sc_code[]){-1}, // TODO
	(ppm_sc_code[]){-1}, // TODO
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
	NULL,
	NULL,
	(ppm_sc_code[]){PPM_SC_SENDTO, -1},
	(ppm_sc_code[]){PPM_SC_SENDTO, -1},
	NULL,
	NULL,
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
	(ppm_sc_code[]){PPM_SC_LSTAT64, -1},
	(ppm_sc_code[]){PPM_SC_LSTAT64, -1},
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
	(ppm_sc_code[]){PPM_SC_INOTIFY_INIT, -1},
	(ppm_sc_code[]){PPM_SC_INOTIFY_INIT, -1},
	(ppm_sc_code[]){PPM_SC_GETRLIMIT, -1},
	(ppm_sc_code[]){PPM_SC_GETRLIMIT, -1},
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
	(ppm_sc_code[]){PPM_SC_SENDFILE, -1},
	(ppm_sc_code[]){PPM_SC_SENDFILE, -1},
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
	(ppm_sc_code[]){PPM_SC_SIGNAL_DELIVER, -1},
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
	(ppm_sc_code[]){PPM_SC_UMOUNT, PPM_SC_UMOUNT2, -1},
	(ppm_sc_code[]){PPM_SC_UMOUNT, PPM_SC_UMOUNT2, -1},
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
			if(!ppm_sc_array[sc_code])
			{
				continue;
			}
			events_array[ev] = 1;
			break;
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
	if (tp_name && strlen(tp_name) > 0)
	{
		start = PPM_SC_TP_START;
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