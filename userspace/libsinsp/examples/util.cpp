/*
Copyright (C) 2021 SecureWorks Corp.

This file is part of sysdig.

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

#include "util.h"
#include <sinsp.h>

//
// Get the string representation of a ppm_event_category
//
std::string get_event_category(ppm_event_category category)
{
    switch(category)
    {
        case EC_UNKNOWN: return "UNKNOWN";
        case EC_OTHER: return "OTHER";
        case EC_FILE: return "FILE";
        case EC_NET: return "NET";
        case EC_IPC: return "IPC";
        case EC_MEMORY: return "MEMORY";
        case EC_PROCESS: return "PROCESS";
        case EC_SLEEP: return "SLEEP";
        case EC_SYSTEM: return "SYSTEM";
        case EC_SIGNAL: return "SIGNAL";
        case EC_USER: return "USER";
        case EC_TIME: return "TIME";
        case EC_PROCESSING: return "PROCESSING";
        case EC_IO_READ: return "IO_READ";
        case EC_IO_WRITE: return "IO_WRITE";
        case EC_IO_OTHER: return "IO_OTHER";
        case EC_WAIT: return "WAIT";
        case EC_SCHEDULER: return "SCHEDULER";
        case EC_INTERNAL: return "INTERNAL";
        default: return "ERROR CONDITION";
    };
}

//
// Get the string representation of a ppm_event_type
//
std::string get_event_type(uint16_t type)
{
    switch(type)
    {
        //
        // File syscalls
        //
        case PPME_SYSCALL_ACCESS_E:
        case PPME_SYSCALL_ACCESS_X: return "access";
        case PPME_SYSCALL_CHMOD_E: 
        case PPME_SYSCALL_CHMOD_X: return "chmod";
        case PPME_SYSCALL_CLOSE_E:
        case PPME_SYSCALL_CLOSE_X: return "close";
        case PPME_SYSCALL_CREAT_E: 
        case PPME_SYSCALL_CREAT_X: return "creat";
        case PPME_SYSCALL_DUP_E:
        case PPME_SYSCALL_DUP_X: return "dup";
        case PPME_SYSCALL_EPOLLWAIT_E:
        case PPME_SYSCALL_EPOLLWAIT_X: return "epollwait";
        case PPME_SYSCALL_EVENTFD_E:
        case PPME_SYSCALL_EVENTFD_X: return "eventfd";
        case PPME_SYSCALL_FCHMODAT_E:
        case PPME_SYSCALL_FCHMODAT_X: return "fchmodat";
        case PPME_SYSCALL_FLOCK_E:
        case PPME_SYSCALL_FLOCK_X: return "flock";
        case PPME_SYSCALL_FSTAT_E:
        case PPME_SYSCALL_FSTAT_X: return "fstat";
        case PPME_SYSCALL_FSTAT64_E:
        case PPME_SYSCALL_FSTAT64_X: return "fstat64";
        case PPME_SYSCALL_GETDENTS_E:
        case PPME_SYSCALL_GETDENTS_X: return "getdents";
        case PPME_SYSCALL_GETDENTS64_E:
        case PPME_SYSCALL_GETDENTS64_X: return "getdents64";
        case PPME_SYSCALL_GETRLIMIT_E:
        case PPME_SYSCALL_GETRLIMIT_X: return "getrlimit";
        case PPME_SYSCALL_GETEGID_E:
        case PPME_SYSCALL_GETEGID_X: return "getegid";
        case PPME_SYSCALL_GETEUID_E:
        case PPME_SYSCALL_GETEUID_X: return "geteuid";
        case PPME_SYSCALL_GETGID_E:
        case PPME_SYSCALL_GETGID_X: return "getgid";
        case PPME_SYSCALL_GETRESGID_E:
        case PPME_SYSCALL_GETRESGID_X: return "getresgid";
        case PPME_SYSCALL_GETRESUID_E:
        case PPME_SYSCALL_GETRESUID_X: return "getresuid";
        case PPME_SYSCALL_GETUID_E:
        case PPME_SYSCALL_GETUID_X: return "getuid";
        case PPME_SYSCALL_IOCTL_2_E:
        case PPME_SYSCALL_IOCTL_3_E:
        case PPME_SYSCALL_IOCTL_2_X:
        case PPME_SYSCALL_IOCTL_3_X: return "ioctl";
        case PPME_SYSCALL_LINK_E:
        case PPME_SYSCALL_LINK_2_E:
        case PPME_SYSCALL_LINK_X:
        case PPME_SYSCALL_LINK_2_X: return "link";
        case PPME_SYSCALL_LINKAT_E:
        case PPME_SYSCALL_LINKAT_2_E:
        case PPME_SYSCALL_LINKAT_X:
        case PPME_SYSCALL_LINKAT_2_X: return "linkat";
        case PPME_SYSCALL_LSEEK_E:
        case PPME_SYSCALL_LSEEK_X: return "lseek";
        case PPME_SYSCALL_LLSEEK_E:
        case PPME_SYSCALL_LLSEEK_X: return "llseek";
        case PPME_SYSCALL_LSTAT_E:
        case PPME_SYSCALL_LSTAT_X: return "lstat";
        case PPME_SYSCALL_LSTAT64_E:
        case PPME_SYSCALL_LSTAT64_X: return "lstat64";
        case PPME_SYSCALL_MKDIR_E:
        case PPME_SYSCALL_MKDIR_2_E:
        case PPME_SYSCALL_MKDIR_X:
        case PPME_SYSCALL_MKDIR_2_X: return "mkdir";
        case PPME_SYSCALL_MKDIRAT_E:
        case PPME_SYSCALL_MKDIRAT_X: return "mkdirat";
        case PPME_SYSCALL_MOUNT_E:
        case PPME_SYSCALL_MOUNT_X: return "mount";
        case PPME_SYSCALL_NEWSELECT_E:
        case PPME_SYSCALL_NEWSELECT_X: return "newselect";
        case PPME_SYSCALL_OPEN_E:
        case PPME_SYSCALL_OPEN_X: return "open";
        case PPME_SYSCALL_OPENAT_E:
        case PPME_SYSCALL_OPENAT_2_E:
        case PPME_SYSCALL_OPENAT_X:
        case PPME_SYSCALL_OPENAT_2_X: return "openat";
        case PPME_SYSCALL_PIPE_E:
        case PPME_SYSCALL_PIPE_X: return "pipe";
        case PPME_SYSCALL_POLL_E:
        case PPME_SYSCALL_POLL_X: return "poll";
        case PPME_SYSCALL_PPOLL_E:
        case PPME_SYSCALL_PPOLL_X: return "ppoll";
        case PPME_SYSCALL_PREAD_E:
        case PPME_SYSCALL_PREAD_X: return "pread";
        case PPME_SYSCALL_PREADV_E:
        case PPME_SYSCALL_PREADV_X: return "preadv";
        case PPME_SYSCALL_PRLIMIT_E:
        case PPME_SYSCALL_PRLIMIT_X: return "prlimit";
        case PPME_SYSCALL_PWRITE_E:
        case PPME_SYSCALL_PWRITE_X: return "pwrite";
        case PPME_SYSCALL_PWRITEV_E:
        case PPME_SYSCALL_PWRITEV_X: return "pwritev";
        case PPME_SYSCALL_READ_E:
        case PPME_SYSCALL_READ_X: return "read";
        case PPME_SYSCALL_READV_E:
        case PPME_SYSCALL_READV_X: return "readv";
        case PPME_SYSCALL_RENAME_E:
        case PPME_SYSCALL_RENAME_X: return "rename";
        case PPME_SYSCALL_RENAMEAT_E:
        case PPME_SYSCALL_RENAMEAT_X: return "renameat";
        case PPME_SYSCALL_RMDIR_E:
        case PPME_SYSCALL_RMDIR_2_E:
        case PPME_SYSCALL_RMDIR_X:
        case PPME_SYSCALL_RMDIR_2_X: return "rmdir";
        case PPME_SYSCALL_SELECT_E:
        case PPME_SYSCALL_SELECT_X: return "select";
        case PPME_SYSCALL_SENDFILE_E:
        case PPME_SYSCALL_SENDFILE_X: return "sendfile";
        case PPME_SYSCALL_SETGID_X:
        case PPME_SYSCALL_SETGID_E: return "setgid";
        case PPME_SYSCALL_SETRLIMIT_E:
        case PPME_SYSCALL_SETRLIMIT_X: return "setrlimit";
        case PPME_SYSCALL_SETUID_E:
        case PPME_SYSCALL_SETUID_X: return "setuid";
        case PPME_SYSCALL_SIGNALFD_E:
        case PPME_SYSCALL_SIGNALFD_X: return "signalfd";
        case PPME_SYSCALL_SPLICE_E:
        case PPME_SYSCALL_SPLICE_X: return "splice";
        case PPME_SYSCALL_STAT_E:
        case PPME_SYSCALL_STAT_X: return "stat";
        case PPME_SYSCALL_STAT64_E:
        case PPME_SYSCALL_STAT64_X: return "stat64";
        case PPME_SYSCALL_SYMLINK_E:
        case PPME_SYSCALL_SYMLINK_X: return "symlink";
        case PPME_SYSCALL_SYMLINKAT_E:
        case PPME_SYSCALL_SYMLINKAT_X: return "symlinkat";
        case PPME_SYSCALL_TIMERFD_CREATE_E:
        case PPME_SYSCALL_TIMERFD_CREATE_X: return "timerfd_create";
        case PPME_SYSCALL_UNLINK_E:
        case PPME_SYSCALL_UNLINK_2_E:
        case PPME_SYSCALL_UNLINK_X:
        case PPME_SYSCALL_UNLINK_2_X: return "unlink";
        case PPME_SYSCALL_UNLINKAT_E:
        case PPME_SYSCALL_UNLINKAT_2_E:
        case PPME_SYSCALL_UNLINKAT_X:
        case PPME_SYSCALL_UNLINKAT_2_X: return "unlinkat";
        case PPME_SYSCALL_WRITE_E:
        case PPME_SYSCALL_WRITE_X: return "write";

        //
        // Process syscalls
        //      
        case PPME_SYSCALL_BPF_E:
        case PPME_SYSCALL_BPF_X: return "bpf";
        case PPME_SYSCALL_BRK_1_E: 
        case PPME_SYSCALL_BRK_4_E:
        case PPME_SYSCALL_BRK_1_X:
        case PPME_SYSCALL_BRK_4_X: return "brk";
        case PPME_SYSCALL_CHDIR_E:
        case PPME_SYSCALL_CHDIR_X: return "chdir";
        case PPME_SYSCALL_CHROOT_E:
        case PPME_SYSCALL_CHROOT_X: return "chroot";
        case PPME_SYSCALL_CLONE_11_E:
        case PPME_SYSCALL_CLONE_16_E:
        case PPME_SYSCALL_CLONE_17_E:
        case PPME_SYSCALL_CLONE_20_E:
        case PPME_SYSCALL_CLONE_11_X:
        case PPME_SYSCALL_CLONE_16_X:
        case PPME_SYSCALL_CLONE_17_X:
        case PPME_SYSCALL_CLONE_20_X: return "clone";
        case PPME_SYSCALL_EXECVE_8_E:
        case PPME_SYSCALL_EXECVE_13_E:
        case PPME_SYSCALL_EXECVE_14_E:
        case PPME_SYSCALL_EXECVE_15_E:
        case PPME_SYSCALL_EXECVE_16_E:
        case PPME_SYSCALL_EXECVE_17_E:
        case PPME_SYSCALL_EXECVE_18_E:
        case PPME_SYSCALL_EXECVE_19_E:
        case PPME_SYSCALL_EXECVE_8_X:
        case PPME_SYSCALL_EXECVE_13_X:
        case PPME_SYSCALL_EXECVE_14_X:
        case PPME_SYSCALL_EXECVE_15_X:
        case PPME_SYSCALL_EXECVE_16_X:
        case PPME_SYSCALL_EXECVE_17_X:
        case PPME_SYSCALL_EXECVE_18_X:
        case PPME_SYSCALL_EXECVE_19_X: return "execve";
        case PPME_SYSCALL_FCHDIR_E:
        case PPME_SYSCALL_FCHDIR_X: return "fchdir";
        case PPME_SYSCALL_FORK_E:
        case PPME_SYSCALL_FORK_20_E:
        case PPME_SYSCALL_FORK_X:
        case PPME_SYSCALL_FORK_20_X: return "fork";
        case PPME_SYSCALL_FUTEX_E:
        case PPME_SYSCALL_FUTEX_X: return "futex";
        case PPME_SYSCALL_GETCWD_E:
        case PPME_SYSCALL_GETCWD_X: return "getcwd";
        case PPME_SYSCALL_KILL_E:
        case PPME_SYSCALL_KILL_X: return "kill";
        case PPME_SYSCALL_INOTIFY_INIT_E:
        case PPME_SYSCALL_INOTIFY_INIT_X: return "inotify_init";
        case PPME_SYSCALL_MMAP_E:
        case PPME_SYSCALL_MMAP_X: return "mmap";
        case PPME_SYSCALL_MUNMAP_E:
        case PPME_SYSCALL_MUNMAP_X: return "munmap";
        case PPME_SYSCALL_NANOSLEEP_E:
        case PPME_SYSCALL_NANOSLEEP_X: return "nanosleep";
        case PPME_SYSCALL_SETPGID_E:
        case PPME_SYSCALL_SETPGID_X: return "setpgid";
        case PPME_SYSCALL_PTRACE_E:
        case PPME_SYSCALL_PTRACE_X: return "ptrace";
        case PPME_SYSCALL_QUOTACTL_E:
        case PPME_SYSCALL_QUOTACTL_X: return "quotactl";
        case PPME_SYSCALL_SECCOMP_E:
        case PPME_SYSCALL_SECCOMP_X: return "seccomp";
        case PPME_SYSCALL_SEMCTL_E:
        case PPME_SYSCALL_SEMCTL_X: return "semctl";
        case PPME_SYSCALL_SEMGET_E:
        case PPME_SYSCALL_SEMGET_X: return "semget";
        case PPME_SYSCALL_SEMOP_E:
        case PPME_SYSCALL_SEMOP_X: return "semop";
        case PPME_SYSCALL_SETNS_E:
        case PPME_SYSCALL_SETNS_X: return "setns";
        case PPME_SYSCALL_SETRESGID_E:
        case PPME_SYSCALL_SETRESGID_X: return "setresgid";
        case PPME_SYSCALL_SETRESUID_E:
        case PPME_SYSCALL_SETRESUID_X: return "setresuid";
        case PPME_SYSCALL_SETSID_E:
        case PPME_SYSCALL_SETSID_X: return "setsid";
        case PPME_SYSCALL_TGKILL_E:
        case PPME_SYSCALL_TGKILL_X: return "tgkill";
        case PPME_SYSCALL_TKILL_E:
        case PPME_SYSCALL_TKILL_X: return "tkill";
        case PPME_SYSCALL_UNSHARE_E:
        case PPME_SYSCALL_UNSHARE_X: return "unshare";
        case PPME_SYSCALL_VFORK_E:
        case PPME_SYSCALL_VFORK_20_E:
        case PPME_SYSCALL_VFORK_X:
        case PPME_SYSCALL_VFORK_20_X: return "vfork";

        //
        // Socket syscalls
        // 
        case PPME_SOCKET_SOCKET_E:
        case PPME_SOCKET_SOCKET_X: return "socket";
        case PPME_SOCKET_BIND_E:
        case PPME_SOCKET_BIND_X: return "bind";
        case PPME_SOCKET_CONNECT_E:
        case PPME_SOCKET_CONNECT_X: return "connect";
        case PPME_SOCKET_LISTEN_E:
        case PPME_SOCKET_LISTEN_X: return "listen";
        case PPME_SOCKET_ACCEPT_5_E:
        case PPME_SOCKET_ACCEPT_5_X: return "accept";
        case PPME_SOCKET_GETSOCKNAME_E:
        case PPME_SOCKET_GETSOCKNAME_X: return "getsockname";
        case PPME_SOCKET_GETPEERNAME_E:
        case PPME_SOCKET_GETPEERNAME_X: return "getpeername";
        case PPME_SOCKET_GETSOCKOPT_E:
        case PPME_SOCKET_GETSOCKOPT_X: return "getsockopt";
        case PPME_SOCKET_SOCKETPAIR_E:
        case PPME_SOCKET_SOCKETPAIR_X: return "socketpair";
        case PPME_SOCKET_SENDTO_E:
        case PPME_SOCKET_SENDTO_X: return "sendto";
        case PPME_SOCKET_RECVFROM_E:
        case PPME_SOCKET_RECVFROM_X: return "recvfrom";
        case PPME_SOCKET_SHUTDOWN_E:
        case PPME_SOCKET_SHUTDOWN_X: return "shutdown";
        case PPME_SOCKET_SETSOCKOPT_E:
        case PPME_SOCKET_SETSOCKOPT_X: return "setsocktopt";
        case PPME_SOCKET_SENDMSG_E:
        case PPME_SOCKET_SENDMSG_X: return "sendmsg";
        case PPME_SOCKET_ACCEPT4_5_E:
        case PPME_SOCKET_ACCEPT4_5_X: return "accept";
        case PPME_SOCKET_SENDMMSG_E:
        case PPME_SOCKET_SENDMMSG_X: return "sendmsg";
        case PPME_SOCKET_RECVMSG_E:
        case PPME_SOCKET_RECVMSG_X: return "recvmsg";
        case PPME_SOCKET_RECVMMSG_E:
        case PPME_SOCKET_RECVMMSG_X: return "recvmmsg";
        default: return "UNKNOWN " + to_string(type);
    };
}
