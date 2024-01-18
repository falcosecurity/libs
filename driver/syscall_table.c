// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include "ppm_events_public.h"

#if defined(__KERNEL__) && defined(__mips__)
#define SYSCALL_TABLE_ID0 __NR_Linux
#else
#define SYSCALL_TABLE_ID0 0
#endif


/*
 * SYSCALL TABLE
 * FIXME: kmod only supports SYSCALL_TABLE_ID0
 */
const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
#ifdef __NR_open
	[__NR_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X, PPM_SC_OPEN},
#endif
#ifdef __NR_creat
	[__NR_creat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X, PPM_SC_CREAT},
#endif
	[__NR_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X, PPM_SC_CLOSE},
	[__NR_brk - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_BRK_4_E, PPME_SYSCALL_BRK_4_X, PPM_SC_BRK},
	[__NR_read - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X, PPM_SC_READ},
	[__NR_write - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X, PPM_SC_WRITE},
	[__NR_execve - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EXECVE_19_E, PPME_SYSCALL_EXECVE_19_X, PPM_SC_EXECVE},
	[__NR_clone - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CLONE_20_E, PPME_SYSCALL_CLONE_20_X, PPM_SC_CLONE},
#ifdef __NR_fork
	[__NR_fork - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FORK_20_E, PPME_SYSCALL_FORK_20_X, PPM_SC_FORK},
#endif
#ifdef __NR_vfork
	[__NR_vfork - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_VFORK_20_E, PPME_SYSCALL_VFORK_20_X, PPM_SC_VFORK},
#endif
#ifdef __NR_pipe
	[__NR_pipe - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X, PPM_SC_PIPE},
#endif
#ifdef __NR_pipe2
	[__NR_pipe2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE2_E, PPME_SYSCALL_PIPE2_X, PPM_SC_PIPE2},
#endif	
#ifdef __NR_eventfd
	[__NR_eventfd - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X, PPM_SC_EVENTFD},
#endif
#ifdef __NR_eventfd2
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD2_E, PPME_SYSCALL_EVENTFD2_X, PPM_SC_EVENTFD2},
#endif
	[__NR_futex - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X, PPM_SC_FUTEX},
#ifdef __NR_stat
	[__NR_stat - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X, PPM_SC_STAT},
#endif
#ifdef __NR_lstat
	[__NR_lstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X, PPM_SC_LSTAT},
#endif
	[__NR_fstat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X, PPM_SC_FSTAT},
#ifdef __NR_epoll_wait
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X, PPM_SC_EPOLL_WAIT},
#endif
#ifdef __NR_poll
	[__NR_poll - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X, PPM_SC_POLL},
#endif
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X, PPM_SC_SELECT},
#endif
	[__NR_lseek - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X, PPM_SC_LSEEK},
	[__NR_ioctl - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_IOCTL_3_E, PPME_SYSCALL_IOCTL_3_X, PPM_SC_IOCTL},
	[__NR_getcwd - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X, PPM_SC_GETCWD},
#ifdef __NR_capset
	[__NR_capset - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_CAPSET_E, PPME_SYSCALL_CAPSET_X, PPM_SC_CAPSET},
#endif
	[__NR_chdir - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X, PPM_SC_CHDIR},
	[__NR_fchdir - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X, PPM_SC_FCHDIR},
#ifdef __NR_mkdir
	[__NR_mkdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MKDIR_2_E, PPME_SYSCALL_MKDIR_2_X, PPM_SC_MKDIR},
#endif
#ifdef __NR_rmdir
	[__NR_rmdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_RMDIR_2_E, PPME_SYSCALL_RMDIR_2_X, PPM_SC_RMDIR},
#endif
	[__NR_openat - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X, PPM_SC_OPENAT},
	[__NR_mkdirat - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_MKDIRAT_E, PPME_SYSCALL_MKDIRAT_X, PPM_SC_MKDIRAT},
#ifdef __NR_link
	[__NR_link - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_LINK_2_E, PPME_SYSCALL_LINK_2_X, PPM_SC_LINK},
#endif
	[__NR_linkat - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_LINKAT_2_E, PPME_SYSCALL_LINKAT_2_X, PPM_SC_LINKAT},
#ifdef __NR_unlink
	[__NR_unlink - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_UNLINK_2_E, PPME_SYSCALL_UNLINK_2_X, PPM_SC_UNLINK},
#endif
	[__NR_unlinkat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_UNLINKAT_2_E, PPME_SYSCALL_UNLINKAT_2_X, PPM_SC_UNLINKAT},
	[__NR_pread64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X, PPM_SC_PREAD64},
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X, PPM_SC_PWRITE64},
	[__NR_readv - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X, PPM_SC_READV},
	[__NR_writev - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X, PPM_SC_WRITEV},
	[__NR_preadv - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X, PPM_SC_PREADV},
	[__NR_pwritev - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X, PPM_SC_PWRITEV},
	[__NR_dup - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_1_E, PPME_SYSCALL_DUP_1_X, PPM_SC_DUP},
#ifdef __NR_dup2
	[__NR_dup2 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP2_E, PPME_SYSCALL_DUP2_X, PPM_SC_DUP2},
#endif
	[__NR_dup3 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP3_E, PPME_SYSCALL_DUP3_X, PPM_SC_DUP3},
#ifdef __NR_signalfd
	[__NR_signalfd - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X, PPM_SC_SIGNALFD},
#endif
#ifdef __NR_signalfd4
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD4_E, PPME_SYSCALL_SIGNALFD4_X, PPM_SC_SIGNALFD4},
#endif
	[__NR_kill - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X, PPM_SC_KILL},
	[__NR_tkill - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X, PPM_SC_TKILL},
	[__NR_tgkill - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X, PPM_SC_TGKILL},
	[__NR_nanosleep - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X, PPM_SC_NANOSLEEP},
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] =             {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X, PPM_SC_TIMERFD_CREATE},
#ifdef __NR_inotify_init
	[__NR_inotify_init - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X, PPM_SC_INOTIFY_INIT},
#endif
#ifdef __NR_inotify_init1
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] =              {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT1_E, PPME_SYSCALL_INOTIFY_INIT1_X, PPM_SC_INOTIFY_INIT1},
#endif
	[__NR_fchmodat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_FCHMODAT_E, PPME_SYSCALL_FCHMODAT_X, PPM_SC_FCHMODAT},
	[__NR_fchmod - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_FCHMOD_E, PPME_SYSCALL_FCHMOD_X, PPM_SC_FCHMOD},
#ifdef __NR_getrlimit
	[__NR_getrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X, PPM_SC_GETRLIMIT},
#endif
	[__NR_setrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X, PPM_SC_SETRLIMIT},
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X, PPM_SC_PRLIMIT64},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X, PPM_SC_UGETRLIMIT},
#endif
	[__NR_fcntl - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X, PPM_SC_FCNTL},
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X, PPM_SC_FCNTL64},
#endif
#ifdef __NR_chmod
	[__NR_chmod - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_CHMOD_E, PPME_SYSCALL_CHMOD_X, PPM_SC_CHMOD},
#endif
	[__NR_mount - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MOUNT_E, PPME_SYSCALL_MOUNT_X, PPM_SC_MOUNT},
#ifdef __NR_umount2
	[__NR_umount2 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_UMOUNT2_E, PPME_SYSCALL_UMOUNT2_X, PPM_SC_UMOUNT2},
#endif
	[__NR_ptrace - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PTRACE_E, PPME_SYSCALL_PTRACE_X, PPM_SC_PTRACE},
#ifdef __NR_socket
	[__NR_socket - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X, PPM_SC_SOCKET},
#endif
#ifdef __NR_bind
	[__NR_bind - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X, PPM_SC_BIND},
#endif
#ifdef __NR_connect
	[__NR_connect - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X, PPM_SC_CONNECT},
#endif
#ifdef __NR_listen
	[__NR_listen - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X, PPM_SC_LISTEN},
#endif
#ifdef __NR_accept
	[__NR_accept - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_ACCEPT_5_E, PPME_SOCKET_ACCEPT_5_X, PPM_SC_ACCEPT},
#endif
#ifdef __NR_getsockname
	[__NR_getsockname - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X, PPM_SC_GETSOCKNAME},
#endif
#ifdef __NR_getpeername
	[__NR_getpeername - SYSCALL_TABLE_ID0] =                {UF_USED | UF_ALWAYS_DROP, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X, PPM_SC_GETPEERNAME},
#endif
#ifdef __NR_socketpair
	[__NR_socketpair - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X, PPM_SC_SOCKETPAIR},
#endif
#ifdef __NR_sendto
	[__NR_sendto - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X, PPM_SC_SENDTO},
#endif
#ifdef __NR_recvfrom
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X, PPM_SC_RECVFROM},
#endif
#ifdef __NR_shutdown
	[__NR_shutdown - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X, PPM_SC_SHUTDOWN},
#endif
#ifdef __NR_setsockopt
	[__NR_setsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X, PPM_SC_SETSOCKOPT},
#endif
#ifdef __NR_getsockopt
	[__NR_getsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X, PPM_SC_GETSOCKOPT},
#endif
#ifdef __NR_sendmsg
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X, PPM_SC_SENDMSG},
#endif
#ifdef __NR_accept4
	[__NR_accept4 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_ACCEPT4_6_E, PPME_SOCKET_ACCEPT4_6_X, PPM_SC_ACCEPT4},
#endif
#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X, PPM_SC_SENDMMSG},
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X, PPM_SC_RECVMSG},
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X, PPM_SC_RECVMMSG},
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X, PPM_SC_STAT64},
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X, PPM_SC_FSTAT64},
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X, PPM_SC__LLSEEK},
#endif
#ifdef __NR_mmap
	[__NR_mmap - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_MMAP_E, PPME_SYSCALL_MMAP_X, PPM_SC_MMAP},
#endif
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MMAP2_E, PPME_SYSCALL_MMAP2_X, PPM_SC_MMAP2},
#endif
	[__NR_munmap - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_MUNMAP_E, PPME_SYSCALL_MUNMAP_X, PPM_SC_MUNMAP},
	[__NR_splice - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SPLICE_E, PPME_SYSCALL_SPLICE_X, PPM_SC_SPLICE},

#ifdef __NR_rename
	[__NR_rename - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_RENAME_E, PPME_SYSCALL_RENAME_X, PPM_SC_RENAME},
#endif
#ifdef __NR_renameat
	[__NR_renameat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_RENAMEAT_E, PPME_SYSCALL_RENAMEAT_X, PPM_SC_RENAMEAT},
#endif
#ifdef __NR_symlink
	[__NR_symlink - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SYMLINK_E, PPME_SYSCALL_SYMLINK_X, PPM_SC_SYMLINK},
#endif
	[__NR_symlinkat - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SYMLINKAT_E, PPME_SYSCALL_SYMLINKAT_X, PPM_SC_SYMLINKAT},
	[__NR_sendfile - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X, PPM_SC_SENDFILE},
#ifdef __NR_sendfile64
	[__NR_sendfile64 - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SYSCALL_SENDFILE_E, PPME_SYSCALL_SENDFILE_X, PPM_SC_SENDFILE64},
#endif
#ifdef __NR_quotactl
	[__NR_quotactl - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_QUOTACTL_E, PPME_SYSCALL_QUOTACTL_X, PPM_SC_QUOTACTL},
#endif
#ifdef __NR_setresuid
	[__NR_setresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X, PPM_SC_SETRESUID},
#endif
#ifdef __NR_setresuid32
	[__NR_setresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_SETRESUID_E, PPME_SYSCALL_SETRESUID_X, PPM_SC_SETRESUID32},
#endif
#ifdef __NR_setresgid
	[__NR_setresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X, PPM_SC_SETRESGID},
#endif
#ifdef __NR_setresgid32
	[__NR_setresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_SETRESGID_E, PPME_SYSCALL_SETRESGID_X, PPM_SC_SETRESGID32},
#endif
#ifdef __NR_setuid
	[__NR_setuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X, PPM_SC_SETUID},
#endif
#ifdef __NR_setuid32
	[__NR_setuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SETUID_E, PPME_SYSCALL_SETUID_X, PPM_SC_SETUID32},
#endif
#ifdef __NR_setgid
	[__NR_setgid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X, PPM_SC_SETGID},
#endif
#ifdef __NR_setgid32
	[__NR_setgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_SETGID_E, PPME_SYSCALL_SETGID_X, PPM_SC_SETGID32},
#endif
#ifdef __NR_getuid
	[__NR_getuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X, PPM_SC_GETUID},
#endif
#ifdef __NR_getuid32
	[__NR_getuid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X, PPM_SC_GETUID32},
#endif
#ifdef __NR_geteuid
	[__NR_geteuid - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X, PPM_SC_GETEUID},
#endif
#ifdef __NR_geteuid32
	[__NR_geteuid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X, PPM_SC_GETEUID32},
#endif
#ifdef __NR_getgid
	[__NR_getgid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X, PPM_SC_GETGID},
#endif
#ifdef __NR_getgid32
	[__NR_getgid32 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X, PPM_SC_GETGID32},
#endif
#ifdef __NR_getegid
	[__NR_getegid - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X, PPM_SC_GETEGID},
#endif
#ifdef __NR_getegid32
	[__NR_getegid32 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X, PPM_SC_GETEGID32},
#endif
#ifdef __NR_getresuid
	[__NR_getresuid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X, PPM_SC_GETRESUID},
#endif
#ifdef __NR_getresuid32
	[__NR_getresuid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_GETRESUID_E, PPME_SYSCALL_GETRESUID_X, PPM_SC_GETRESUID32},
#endif
#ifdef __NR_getresgid
	[__NR_getresgid - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X, PPM_SC_GETRESGID},
#endif
#ifdef __NR_getresgid32
	[__NR_getresgid32 - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SYSCALL_GETRESGID_E, PPME_SYSCALL_GETRESGID_X, PPM_SC_GETRESGID32},
#endif
#ifdef __NR_getdents
	[__NR_getdents - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETDENTS_E, PPME_SYSCALL_GETDENTS_X, PPM_SC_GETDENTS},
#endif
	[__NR_getdents64 - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_GETDENTS64_E, PPME_SYSCALL_GETDENTS64_X, PPM_SC_GETDENTS64},
#ifdef __NR_setns
	[__NR_setns - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_SETNS_E, PPME_SYSCALL_SETNS_X, PPM_SC_SETNS},
#endif
#ifdef __NR_unshare
	[__NR_unshare - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_UNSHARE_E, PPME_SYSCALL_UNSHARE_X, PPM_SC_UNSHARE},
#endif
	[__NR_flock - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_FLOCK_E, PPME_SYSCALL_FLOCK_X, PPM_SC_FLOCK},
#ifdef __NR_semop
	[__NR_semop - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMOP_E, PPME_SYSCALL_SEMOP_X, PPM_SC_SEMOP},
#endif
#ifdef __NR_semget
	[__NR_semget - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMGET_E, PPME_SYSCALL_SEMGET_X, PPM_SC_SEMGET},
#endif
#ifdef __NR_semctl
	[__NR_semctl - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SEMCTL_E, PPME_SYSCALL_SEMCTL_X, PPM_SC_SEMCTL},
#endif
	[__NR_ppoll - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_PPOLL_E, PPME_SYSCALL_PPOLL_X, PPM_SC_PPOLL},
#ifdef __NR_access
	[__NR_access - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_ACCESS_E, PPME_SYSCALL_ACCESS_X, PPM_SC_ACCESS},
#endif
#ifdef __NR_chroot
	[__NR_chroot - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHROOT_E, PPME_SYSCALL_CHROOT_X, PPM_SC_CHROOT},
#endif
	[__NR_setsid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SETSID_E, PPME_SYSCALL_SETSID_X, PPM_SC_SETSID},
	[__NR_setpgid - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_SETPGID_E, PPME_SYSCALL_SETPGID_X, PPM_SC_SETPGID},
#ifdef __NR_bpf
	[__NR_bpf - SYSCALL_TABLE_ID0] =                        {UF_USED, PPME_SYSCALL_BPF_2_E, PPME_SYSCALL_BPF_2_X, PPM_SC_BPF},
#endif
#ifdef __NR_seccomp
	[__NR_seccomp - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_SECCOMP_E, PPME_SYSCALL_SECCOMP_X, PPM_SC_SECCOMP},
#endif
#ifdef __NR_renameat2
	[__NR_renameat2 - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_RENAMEAT2_E, PPME_SYSCALL_RENAMEAT2_X, PPM_SC_RENAMEAT2},
#endif
#ifdef __NR_userfaultfd
	[__NR_userfaultfd - SYSCALL_TABLE_ID0] =                {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_USERFAULTFD_E, PPME_SYSCALL_USERFAULTFD_X, PPM_SC_USERFAULTFD},
#endif
#ifdef __NR_openat2
	[__NR_openat2 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_OPENAT2_E, PPME_SYSCALL_OPENAT2_X, PPM_SC_OPENAT2},
#endif
#ifdef __NR_clone3
	[__NR_clone3 - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CLONE3_E, PPME_SYSCALL_CLONE3_X, PPM_SC_CLONE3},
#endif
#ifdef __NR_mprotect
	[__NR_mprotect - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_MPROTECT_E, PPME_SYSCALL_MPROTECT_X, PPM_SC_MPROTECT},
#endif
#ifdef __NR_execveat
	[__NR_execveat - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EXECVEAT_E, PPME_SYSCALL_EXECVEAT_X, PPM_SC_EXECVEAT},
#endif
#ifdef __NR_io_uring_setup
	[__NR_io_uring_setup - SYSCALL_TABLE_ID0] =		{UF_USED, PPME_SYSCALL_IO_URING_SETUP_E, PPME_SYSCALL_IO_URING_SETUP_X, PPM_SC_IO_URING_SETUP},
#endif
#ifdef __NR_io_uring_enter
	[__NR_io_uring_enter - SYSCALL_TABLE_ID0] =		{UF_USED, PPME_SYSCALL_IO_URING_ENTER_E, PPME_SYSCALL_IO_URING_ENTER_X, PPM_SC_IO_URING_ENTER},
#endif
#ifdef __NR_io_uring_register
	[__NR_io_uring_register - SYSCALL_TABLE_ID0] =		{UF_USED, PPME_SYSCALL_IO_URING_REGISTER_E, PPME_SYSCALL_IO_URING_REGISTER_X, PPM_SC_IO_URING_REGISTER},
#endif
#ifdef __NR_copy_file_range
	[__NR_copy_file_range - SYSCALL_TABLE_ID0] =            {UF_USED, PPME_SYSCALL_COPY_FILE_RANGE_E, PPME_SYSCALL_COPY_FILE_RANGE_X, PPM_SC_COPY_FILE_RANGE},
#endif
#ifdef __NR_open_by_handle_at
	[__NR_open_by_handle_at - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, PPM_SC_OPEN_BY_HANDLE_AT},
#endif
#ifdef __NR_mlock
	[__NR_mlock - SYSCALL_TABLE_ID0] =			{UF_USED, PPME_SYSCALL_MLOCK_E, PPME_SYSCALL_MLOCK_X, PPM_SC_MLOCK},
#endif
#ifdef __NR_munlock
	[__NR_munlock - SYSCALL_TABLE_ID0] =			{UF_USED, PPME_SYSCALL_MUNLOCK_E, PPME_SYSCALL_MUNLOCK_X, PPM_SC_MUNLOCK},
#endif
#ifdef __NR_mlockall
	[__NR_mlockall - SYSCALL_TABLE_ID0] =			{UF_USED, PPME_SYSCALL_MLOCKALL_E, PPME_SYSCALL_MLOCKALL_X, PPM_SC_MLOCKALL},
#endif
#ifdef __NR_munlockall
	[__NR_munlockall - SYSCALL_TABLE_ID0] =			{UF_USED, PPME_SYSCALL_MUNLOCKALL_E, PPME_SYSCALL_MUNLOCKALL_X, PPM_SC_MUNLOCKALL},
#endif
#ifdef __NR_mlock2
	[__NR_mlock2 - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_MLOCK2_E, PPME_SYSCALL_MLOCK2_X, PPM_SC_MLOCK2},
#endif
#ifdef __NR_fsconfig
	[__NR_fsconfig - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_FSCONFIG_E, PPME_SYSCALL_FSCONFIG_X, PPM_SC_FSCONFIG},
#endif
#ifdef __NR_epoll_create
	[__NR_epoll_create - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EPOLL_CREATE_E, PPME_SYSCALL_EPOLL_CREATE_X, PPM_SC_EPOLL_CREATE},
#endif
#ifdef __NR_epoll_create1
	[__NR_epoll_create1 - SYSCALL_TABLE_ID0] = {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EPOLL_CREATE1_E, PPME_SYSCALL_EPOLL_CREATE1_X, PPM_SC_EPOLL_CREATE1},
#endif
#ifdef __NR_lstat64
	[__NR_lstat64 - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_LSTAT64_E, PPME_SYSCALL_LSTAT64_X, PPM_SC_LSTAT64},
#endif
#ifdef __NR_umount
	[__NR_umount - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_UMOUNT_1_E, PPME_SYSCALL_UMOUNT_1_X, PPM_SC_UMOUNT},
#endif
#ifdef __NR_recv
	[__NR_recv - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SOCKET_RECV_E, PPME_SOCKET_RECV_X, PPM_SC_RECV},
#endif
#ifdef __NR_send
	[__NR_send - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SOCKET_SEND_E, PPME_SOCKET_SEND_X, PPM_SC_SEND},
#endif
#ifdef __NR_prctl
	[__NR_prctl - SYSCALL_TABLE_ID0] = { UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRCTL_E, PPME_SYSCALL_PRCTL_X, PPM_SC_PRCTL },
#endif
#ifdef __NR_memfd_create
	[__NR_memfd_create - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_MEMFD_CREATE_E, PPME_SYSCALL_MEMFD_CREATE_X, PPM_SC_MEMFD_CREATE},
#endif
#ifdef __NR_pidfd_open
	[__NR_pidfd_open - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_PIDFD_OPEN_E, PPME_SYSCALL_PIDFD_OPEN_X, PPM_SC_PIDFD_OPEN},
#endif
#ifdef __NR_pidfd_getfd
	[__NR_pidfd_getfd - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_PIDFD_GETFD_E, PPME_SYSCALL_PIDFD_GETFD_X, PPM_SC_PIDFD_GETFD},
#endif
#ifdef __NR_init_module
	[__NR_init_module - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_INIT_MODULE_E, PPME_SYSCALL_INIT_MODULE_X, PPM_SC_INIT_MODULE},
#endif
#ifdef __NR_finit_module
	[__NR_finit_module - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_FINIT_MODULE_E, PPME_SYSCALL_FINIT_MODULE_X, PPM_SC_FINIT_MODULE},
#endif
#ifdef __NR_mknod
	[__NR_mknod - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_MKNOD_E, PPME_SYSCALL_MKNOD_X, PPM_SC_MKNOD},
#endif
#ifdef __NR_mknodat
	[__NR_mknodat - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_MKNODAT_E, PPME_SYSCALL_MKNODAT_X, PPM_SC_MKNODAT},
#endif
#ifdef __NR_newfstatat
	[__NR_newfstatat - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_NEWFSTATAT_E, PPME_SYSCALL_NEWFSTATAT_X, PPM_SC_NEWFSTATAT},
#endif
	[__NR_restart_syscall - SYSCALL_TABLE_ID0] = { .ppm_sc = PPM_SC_RESTART_SYSCALL },
	[__NR_exit - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EXIT},
#ifdef __NR_time
	[__NR_time - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIME},
#endif
	[__NR_getpid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETPID},
	[__NR_sync - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYNC},
	[__NR_times - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMES},
	[__NR_acct - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_ACCT},
	[__NR_umask - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_UMASK},
#ifdef __NR_ustat
	[__NR_ustat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_USTAT},
#endif
	[__NR_getppid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETPPID},
#ifdef __NR_getpgrp
	[__NR_getpgrp - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETPGRP},
#endif
	[__NR_sethostname - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETHOSTNAME},
	[__NR_getrusage - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETRUSAGE},
	[__NR_gettimeofday - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETTIMEOFDAY},
	[__NR_settimeofday - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETTIMEOFDAY},
#ifdef __NR_readlink
	[__NR_readlink - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_READLINK},
#endif
	[__NR_swapon - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_SWAPON},
	[__NR_reboot - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_REBOOT},
	[__NR_truncate - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TRUNCATE},
	[__NR_ftruncate - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FTRUNCATE},
	[__NR_getpriority - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_GETPRIORITY},
	[__NR_setpriority - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_SETPRIORITY},
	[__NR_statfs - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_STATFS},
	[__NR_fstatfs - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_FSTATFS},
	[__NR_setitimer - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_SETITIMER},
	[__NR_getitimer - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_GETITIMER},
	[__NR_uname - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_UNAME},
	[__NR_vhangup - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_VHANGUP},
	[__NR_wait4 - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_WAIT4},
	[__NR_swapoff - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_SWAPOFF},
	[__NR_sysinfo - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_SYSINFO},
	[__NR_fsync - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_FSYNC},
	[__NR_setdomainname - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_SETDOMAINNAME},
	[__NR_adjtimex - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_ADJTIMEX},
	[__NR_delete_module - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_DELETE_MODULE},
	[__NR_getpgid - SYSCALL_TABLE_ID0] = {.ppm_sc= PPM_SC_GETPGID},
#ifdef __NR_sysfs
	[__NR_sysfs - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYSFS},
#endif
	[__NR_personality - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PERSONALITY},
	[__NR_msync - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MSYNC},
	[__NR_getsid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETSID},
	[__NR_fdatasync - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FDATASYNC},
	[__NR_sched_setscheduler - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_SETSCHEDULER},
	[__NR_sched_getscheduler - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_GETSCHEDULER},
	[__NR_sched_yield - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_YIELD},
	[__NR_sched_get_priority_max - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_GET_PRIORITY_MAX},
	[__NR_sched_get_priority_min - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_GET_PRIORITY_MIN},
	[__NR_sched_rr_get_interval - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_RR_GET_INTERVAL},
	[__NR_mremap - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MREMAP},
#ifdef __NR_arch_prctl
	[__NR_arch_prctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_ARCH_PRCTL},
#endif
	[__NR_rt_sigaction - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGACTION},
	[__NR_rt_sigprocmask - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGPROCMASK},
	[__NR_rt_sigpending - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGPENDING},
	[__NR_rt_sigtimedwait - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGTIMEDWAIT},
	[__NR_rt_sigqueueinfo - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGQUEUEINFO},
	[__NR_rt_sigsuspend - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGSUSPEND},
	[__NR_capget - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CAPGET},

	[__NR_setreuid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETREUID},
	[__NR_setregid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETREGID},
	[__NR_getgroups - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETGROUPS},
	[__NR_setgroups - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETGROUPS},
#ifdef __NR_fchown
	[__NR_fchown - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_FCHOWN_E, PPME_SYSCALL_FCHOWN_X, PPM_SC_FCHOWN},
#endif
#ifdef __NR_chown
	[__NR_chown - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_CHOWN_E, PPME_SYSCALL_CHOWN_X, PPM_SC_CHOWN},
#endif
	[__NR_setfsuid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETFSUID},
	[__NR_setfsgid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETFSGID},
	[__NR_pivot_root - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PIVOT_ROOT},
	[__NR_mincore - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MINCORE},
	[__NR_madvise - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MADVISE},
	[__NR_gettid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETTID},
	[__NR_setxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SETXATTR},
	[__NR_lsetxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LSETXATTR},
	[__NR_fsetxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FSETXATTR},
	[__NR_getxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETXATTR},
	[__NR_lgetxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LGETXATTR},
	[__NR_fgetxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FGETXATTR},
	[__NR_listxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LISTXATTR},
	[__NR_llistxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LLISTXATTR},
	[__NR_flistxattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FLISTXATTR},
	[__NR_removexattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_REMOVEXATTR},
	[__NR_lremovexattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LREMOVEXATTR},
	[__NR_fremovexattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FREMOVEXATTR},
	[__NR_sched_setaffinity - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_SETAFFINITY},
	[__NR_sched_getaffinity - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_GETAFFINITY},
#ifdef __NR_set_thread_area
	[__NR_set_thread_area - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SET_THREAD_AREA},
#endif
#ifdef __NR_get_thread_area
	[__NR_get_thread_area - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GET_THREAD_AREA},
#endif
	[__NR_io_setup - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IO_SETUP},
	[__NR_io_destroy - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IO_DESTROY},
	[__NR_io_getevents - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IO_GETEVENTS},
	[__NR_io_submit - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IO_SUBMIT},
	[__NR_io_cancel - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IO_CANCEL},
	[__NR_exit_group - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EXIT_GROUP},
	[__NR_remap_file_pages - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_REMAP_FILE_PAGES},
	[__NR_set_tid_address - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SET_TID_ADDRESS},
	[__NR_timer_create - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMER_CREATE},
	[__NR_timer_settime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMER_SETTIME},
	[__NR_timer_gettime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMER_GETTIME},
	[__NR_timer_getoverrun - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMER_GETOVERRUN},
	[__NR_timer_delete - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMER_DELETE},
	[__NR_clock_settime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CLOCK_SETTIME},
	[__NR_clock_gettime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CLOCK_GETTIME},
	[__NR_clock_getres - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CLOCK_GETRES},
	[__NR_clock_nanosleep - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CLOCK_NANOSLEEP},
#ifdef __NR_utimes
	[__NR_utimes - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_UTIMES},
#endif
	[__NR_mq_open - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MQ_OPEN},
	[__NR_mq_unlink - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MQ_UNLINK},
	[__NR_mq_timedsend - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MQ_TIMEDSEND},
	[__NR_mq_timedreceive - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MQ_TIMEDRECEIVE},
	[__NR_mq_notify - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MQ_NOTIFY},
	[__NR_mq_getsetattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MQ_GETSETATTR},
	[__NR_kexec_load - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_KEXEC_LOAD},
	[__NR_waitid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_WAITID},
	[__NR_add_key - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_ADD_KEY},
	[__NR_request_key - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_REQUEST_KEY},
	[__NR_keyctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_KEYCTL},
	[__NR_ioprio_set - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IOPRIO_SET},
	[__NR_ioprio_get - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IOPRIO_GET},
	[__NR_inotify_add_watch - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_INOTIFY_ADD_WATCH},
	[__NR_inotify_rm_watch - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_INOTIFY_RM_WATCH},
#ifdef __NR_fchownat
	[__NR_fchownat - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_FCHOWNAT_E, PPME_SYSCALL_FCHOWNAT_X, PPM_SC_FCHOWNAT},
#endif
#ifdef __NR_futimesat
	[__NR_futimesat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FUTIMESAT},
#endif
	[__NR_readlinkat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_READLINKAT},
	[__NR_faccessat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FACCESSAT},
	[__NR_set_robust_list - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SET_ROBUST_LIST},
	[__NR_get_robust_list - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GET_ROBUST_LIST},
	[__NR_tee - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TEE},
	[__NR_vmsplice - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_VMSPLICE},
#ifdef __NR_getcpu
	[__NR_getcpu - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETCPU},
#endif
	[__NR_epoll_pwait - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EPOLL_PWAIT},
	[__NR_utimensat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_UTIMENSAT},
	[__NR_timerfd_settime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMERFD_SETTIME},
	[__NR_timerfd_gettime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMERFD_GETTIME},
	[__NR_rt_tgsigqueueinfo - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_TGSIGQUEUEINFO},
	[__NR_perf_event_open - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PERF_EVENT_OPEN},
#ifdef __NR_fanotify_init
	[__NR_fanotify_init - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FANOTIFY_INIT},
#endif
#ifdef __NR_clock_adjtime
	[__NR_clock_adjtime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CLOCK_ADJTIME},
#endif
#ifdef __NR_syncfs
	[__NR_syncfs - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYNCFS},
#endif
#ifdef __NR_msgsnd
	[__NR_msgsnd - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MSGSND},
#endif
#ifdef __NR_msgrcv
	[__NR_msgrcv - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MSGRCV},
#endif
#ifdef __NR_msgget
	[__NR_msgget - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MSGGET},
#endif
#ifdef __NR_msgctl
	[__NR_msgctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MSGCTL},
#endif
#ifdef __NR_shmdt
	[__NR_shmdt - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SHMDT},
#endif
#ifdef __NR_shmget
	[__NR_shmget - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SHMGET},
#endif
#ifdef __NR_shmctl
	[__NR_shmctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SHMCTL},
#endif
#ifdef __NR_statfs64
	[__NR_statfs64 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_STATFS64},
#endif
#ifdef __NR_fstatfs64
	[__NR_fstatfs64 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FSTATFS64},
#endif
#ifdef __NR_fstatat64
	[__NR_fstatat64 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FSTATAT64},
#endif
#ifdef __NR_bdflush
	[__NR_bdflush - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_BDFLUSH},
#endif
#ifdef __NR_sigprocmask
	[__NR_sigprocmask - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGPROCMASK},
#endif
#ifdef __NR_ipc
	[__NR_ipc - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IPC},
#endif
#ifdef __NR__newselect
	[__NR__newselect - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC__NEWSELECT},
#endif
#ifdef __NR_sgetmask
	[__NR_sgetmask - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SGETMASK},
#endif
#ifdef __NR_ssetmask
	[__NR_ssetmask - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SSETMASK},
#endif
#ifdef __NR_sigpending
	[__NR_sigpending - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGPENDING},
#endif
#ifdef __NR_olduname
	[__NR_olduname - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_OLDUNAME},
#endif
#ifdef __NR_signal
	[__NR_signal - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGNAL},
#endif
#ifdef __NR_nice
	[__NR_nice - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_NICE},
#endif
#ifdef __NR_stime
	[__NR_stime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_STIME},
#endif
#ifdef __NR_waitpid
	[__NR_waitpid - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_WAITPID},
#endif
#ifdef __NR_shmat
	[__NR_shmat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SHMAT},
#endif
#ifdef __NR_rt_sigreturn
	[__NR_rt_sigreturn - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RT_SIGRETURN},
#endif
#ifdef __NR_fallocate
	[__NR_fallocate - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FALLOCATE},
#endif
#ifdef __NR_sigaltstack
	[__NR_sigaltstack - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGALTSTACK},
#endif
#ifdef __NR_getrandom
	[__NR_getrandom - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETRANDOM},
#endif
#ifdef __NR_fadvise64
	[__NR_fadvise64 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FADVISE64},
#endif
#ifdef __NR_socketcall
	[__NR_socketcall - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SOCKETCALL },
#endif
#ifdef __NR_fspick
	[__NR_fspick - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FSPICK},
#endif
#ifdef __NR_fsmount
	[__NR_fsmount - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FSMOUNT},
#endif
#ifdef __NR_fsopen
	[__NR_fsopen - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FSOPEN},
#endif
#ifdef __NR_open_tree
	[__NR_open_tree - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_OPEN_TREE},
#endif
#ifdef __NR_move_mount
	[__NR_move_mount - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MOVE_MOUNT},
#endif
#ifdef __NR_mount_setattr
	[__NR_mount_setattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MOUNT_SETATTR},
#endif
#ifdef __NR_memfd_secret
	[__NR_memfd_secret - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MEMFD_SECRET},
#endif
#ifdef __NR_ioperm
	[__NR_ioperm - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IOPERM},
#endif
#ifdef __NR_kexec_file_load
	[__NR_kexec_file_load - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_KEXEC_FILE_LOAD},
#endif
#ifdef __NR_pidfd_send_signal
	[__NR_pidfd_send_signal - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PIDFD_SEND_SIGNAL},
#endif
#ifdef __NR_pkey_alloc
	[__NR_pkey_alloc - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PKEY_ALLOC},
#endif
#ifdef __NR_pkey_mprotect
	[__NR_pkey_mprotect - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PKEY_MPROTECT},
#endif
#ifdef __NR_pkey_free
	[__NR_pkey_free - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PKEY_FREE},
#endif
#ifdef __NR_landlock_create_ruleset
	[__NR_landlock_create_ruleset - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LANDLOCK_CREATE_RULESET},
#endif
#ifdef __NR_quotactl_fd
	[__NR_quotactl_fd - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_QUOTACTL_FD},
#endif
#ifdef __NR_landlock_restrict_self
	[__NR_landlock_restrict_self - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LANDLOCK_RESTRICT_SELF},
#endif
#ifdef __NR_landlock_add_rule
	[__NR_landlock_add_rule - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LANDLOCK_ADD_RULE},
#endif
#ifdef __NR_epoll_pwait2
	[__NR_epoll_pwait2 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EPOLL_PWAIT2},
#endif
#ifdef __NR_migrate_pages
	[__NR_migrate_pages - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MIGRATE_PAGES},
#endif
#ifdef __NR_move_pages
	[__NR_move_pages - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MOVE_PAGES},
#endif
#ifdef __NR_preadv2
	[__NR_preadv2 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PREADV2},
#endif
#ifdef __NR_pwritev2
	[__NR_pwritev2 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PWRITEV2},
#endif
#ifdef __NR_query_module
	[__NR_query_module - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_QUERY_MODULE},
#endif
#ifdef __NR_statx
	[__NR_statx - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_STATX},
#endif
#ifdef __NR_set_mempolicy
	[__NR_set_mempolicy - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SET_MEMPOLICY},
#endif
#ifdef __NR_fanotify_mark
	[__NR_fanotify_mark - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FANOTIFY_MARK},
#endif
#ifdef __NR_sync_file_range
	[__NR_sync_file_range - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYNC_FILE_RANGE},
#endif
#ifdef __NR_readahead
	[__NR_readahead - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_READAHEAD},
#endif
#ifdef __NR_process_mrelease
	[__NR_process_mrelease - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PROCESS_MRELEASE},
#endif
#ifdef __NR_mbind
	[__NR_mbind - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MBIND},
#endif
#ifdef __NR_process_madvise
	[__NR_process_madvise - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PROCESS_MADVISE},
#endif
#ifdef __NR_membarrier
	[__NR_membarrier - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MEMBARRIER},
#endif
#ifdef __NR_modify_ldt
	[__NR_modify_ldt - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MODIFY_LDT},
#endif
#ifdef __NR_semtimedop
	[__NR_semtimedop - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SEMTIMEDOP},
#endif
#ifdef __NR_name_to_handle_at
	[__NR_name_to_handle_at - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_NAME_TO_HANDLE_AT},
#endif
#ifdef __NR_kcmp
	[__NR_kcmp - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_KCMP},
#endif
#ifdef __NR_epoll_ctl_old
	[__NR_epoll_ctl_old - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EPOLL_CTL_OLD},
#endif
#ifdef __NR_epoll_wait_old
	[__NR_epoll_wait_old - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EPOLL_WAIT_OLD},
#endif
#ifdef __NR_futex_waitv
	[__NR_futex_waitv - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FUTEX_WAITV},
#endif
#ifdef __NR_create_module
	[__NR_create_module - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CREATE_MODULE},
#endif
#ifdef __NR__sysctl
	[__NR__sysctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC__SYSCTL},
#endif
#ifdef __NR_lookup_dcookie
	[__NR_lookup_dcookie - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_LOOKUP_DCOOKIE},
#endif
#ifdef __NR_iopl
	[__NR_iopl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IOPL},
#endif
#ifdef __NR_io_pgetevents
	[__NR_io_pgetevents - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IO_PGETEVENTS},
#endif
#ifdef __NR_getpmsg
	[__NR_getpmsg - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GETPMSG},
#endif
#ifdef __NR_sched_setattr
	[__NR_sched_setattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_SETATTR},
#endif
#ifdef __NR_get_kernel_syms
	[__NR_get_kernel_syms - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GET_KERNEL_SYMS},
#endif
#ifdef __NR_rseq
	[__NR_rseq - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RSEQ},
#endif
#ifdef __NR_close_range
	[__NR_close_range - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CLOSE_RANGE},
#endif
#ifdef __NR_get_mempolicy
	[__NR_get_mempolicy - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_GET_MEMPOLICY},
#endif
#ifdef __NR_sched_getattr
	[__NR_sched_getattr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_GETATTR},
#endif
#ifdef __NR_nfsservctl
	[__NR_nfsservctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_NFSSERVCTL},
#endif
#ifdef __NR_set_mempolicy_home_node
	[__NR_set_mempolicy_home_node - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SET_MEMPOLICY_HOME_NODE},
#endif
#ifdef __NR_faccessat2
	[__NR_faccessat2 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FACCESSAT2},
#endif
#ifdef __NR_epoll_ctl
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_EPOLL_CTL},
#endif
#ifdef __NR_process_vm_writev
	[__NR_process_vm_writev - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PROCESS_VM_WRITEV},
#endif
#ifdef __NR_sched_getparam
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_GETPARAM},
#endif
#ifdef __NR_pselect6
	[__NR_pselect6 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PSELECT6},
#endif
#ifdef __NR_sched_setparam
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SCHED_SETPARAM},
#endif
#ifdef __NR_process_vm_readv
	[__NR_process_vm_readv - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PROCESS_VM_READV},
#endif
#ifdef __NR_pause
	[__NR_pause - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PAUSE},
#endif
#ifdef __NR_utime
	[__NR_utime - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_UTIME},
#endif
#ifdef __NR_syslog
	[__NR_syslog - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYSLOG},
#endif
#ifdef __NR_uselib
	[__NR_uselib - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_USELIB},
#endif
#ifdef __NR_lchown
	[__NR_lchown - SYSCALL_TABLE_ID0] = {UF_USED, PPME_SYSCALL_LCHOWN_E, PPME_SYSCALL_LCHOWN_X, PPM_SC_LCHOWN},
#endif
#ifdef __NR_alarm
	[__NR_alarm - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_ALARM},
#endif
#ifdef __NR_s390_pci_mmio_write
	[__NR_s390_pci_mmio_write - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_S390_PCI_MMIO_WRITE},
#endif
#ifdef __NR_s390_guarded_storage
	[__NR_s390_guarded_storage - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_S390_GUARDED_STORAGE},
#endif
#ifdef __NR_readdir
	[__NR_readdir - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_READDIR},
#endif
#ifdef __NR_s390_sthyi
	[__NR_s390_sthyi - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_S390_STHYI},
#endif
#ifdef __NR_s390_runtime_instr
	[__NR_s390_runtime_instr - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_S390_RUNTIME_INSTR},
#endif
#ifdef __NR_sigreturn
	[__NR_sigreturn - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGRETURN},
#endif
#ifdef __NR_timerfd
	[__NR_timerfd - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_TIMERFD},
#endif
#ifdef __NR_sigaction
	[__NR_sigaction - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGACTION},
#endif
#ifdef __NR_idle
	[__NR_idle - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_IDLE},
#endif
#ifdef __NR_s390_pci_mmio_read
	[__NR_s390_pci_mmio_read - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_S390_PCI_MMIO_READ},
#endif
#ifdef __NR_sigsuspend
	[__NR_sigsuspend - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SIGSUSPEND},
#endif
#ifdef __NR_cachestat
	[__NR_cachestat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_CACHESTAT},
#endif
#ifdef __NR_fchmodat2
	[__NR_fchmodat2 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FCHMODAT2},
#endif
#ifdef __NR_map_shadow_stack
	[__NR_map_shadow_stack - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MAP_SHADOW_STACK},
#endif
#ifdef __NR_riscv_flush_icache
	[__NR_riscv_flush_icache - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RISCV_FLUSH_ICACHE},
#endif
#ifdef __NR_riscv_hwprobe
	[__NR_riscv_hwprobe - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RISCV_HWPROBE},
#endif
#ifdef __NR_futex_wake
	[__NR_futex_wake - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FUTEX_WAKE},
#endif
#ifdef __NR_futex_requeue
	[__NR_futex_requeue - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FUTEX_REQUEUE},
#endif
#ifdef __NR_futex_wait
	[__NR_futex_wait - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_FUTEX_WAIT},
#endif
#ifdef __NR_rtas
	[__NR_rtas - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_RTAS},
#endif
#ifdef __NR_subpage_prot
	[__NR_subpage_prot - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SUBPAGE_PROT},
#endif
#ifdef __NR_sync_file_range2
	[__NR_sync_file_range2 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYNC_FILE_RANGE2},
#endif
#ifdef __NR_sys_debug_setcontext
	[__NR_sys_debug_setcontext - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SYS_DEBUG_SETCONTEXT},
#endif
#ifdef __NR_vm86
	[__NR_vm86 - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_VM86},
#endif
#ifdef __NR_oldstat
	[__NR_oldstat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_OLDSTAT},
#endif
#ifdef __NR_switch_endian
	[__NR_switch_endian - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SWITCH_ENDIAN},
#endif
#ifdef __NR_spu_run
	[__NR_spu_run - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SPU_RUN},
#endif
#ifdef __NR_pciconfig_iobase
	[__NR_pciconfig_iobase - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PCICONFIG_IOBASE},
#endif
#ifdef __NR_multiplexer
	[__NR_multiplexer - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_MULTIPLEXER},
#endif
#ifdef __NR_oldlstat
	[__NR_oldlstat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_OLDLSTAT},
#endif
#ifdef __NR_oldolduname
	[__NR_oldolduname - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_OLDOLDUNAME},
#endif
#ifdef __NR_spu_create
	[__NR_spu_create - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SPU_CREATE},
#endif
#ifdef __NR_pciconfig_read
	[__NR_pciconfig_read - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PCICONFIG_READ},
#endif
#ifdef __NR_oldfstat
	[__NR_oldfstat - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_OLDFSTAT},
#endif
#ifdef __NR_swapcontext
	[__NR_swapcontext - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_SWAPCONTEXT},
#endif
#ifdef __NR_pciconfig_write
	[__NR_pciconfig_write - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_PCICONFIG_WRITE},
#endif
};
