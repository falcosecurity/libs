// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_FILLERS_H_
#define PPM_FILLERS_H_

#define FILLER_LIST_MAPPER(FN)           \
	FN(sys_autofill)                     \
	FN(sys_generic)                      \
	FN(sys_empty)                        \
	FN(sys_getcwd_x)                     \
	FN(sys_getdents_x)                   \
	FN(sys_getdents64_x)                 \
	FN(sys_single)                       \
	FN(sys_single_x)                     \
	FN(sys_fstat_x)                      \
	FN(sys_open_e)                       \
	FN(sys_open_x)                       \
	FN(sys_read_x)                       \
	FN(sys_write_x)                      \
	FN(proc_startupdate)                 \
	FN(proc_startupdate_2)               \
	FN(proc_startupdate_3)               \
	FN(sys_socketpair_x)                 \
	FN(sys_setsockopt_x)                 \
	FN(sys_getsockopt_x)                 \
	FN(sys_connect_x)                    \
	FN(sys_accept4_x)                    \
	FN(sys_accept_x)                     \
	FN(sys_send_x)                       \
	FN(sys_sendto_x)                     \
	FN(sys_sendmsg_x)                    \
	FN(sys_sendmsg_x_2)                  \
	FN(sys_sendmmsg_x)                   \
	FN(sys_sendmmsg_x_failure)           \
	FN(sys_recv_x)                       \
	FN(sys_recvfrom_x)                   \
	FN(sys_recvmsg_x)                    \
	FN(sys_recvmsg_x_2)                  \
	FN(sys_recvmmsg_x)                   \
	FN(sys_recvmmsg_x_2)                 \
	FN(sys_shutdown_x)                   \
	FN(sys_creat_e)                      \
	FN(sys_creat_x)                      \
	FN(sys_pipe_x)                       \
	FN(sys_eventfd_x)                    \
	FN(sys_futex_x)                      \
	FN(sys_lseek_x)                      \
	FN(sys_llseek_x)                     \
	FN(sys_socket_bind_x)                \
	FN(sys_poll_x)                       \
	FN(sys_writev_x)                     \
	FN(sys_readv_x)                      \
	FN(sys_preadv_x)                     \
	FN(sys_readv_preadv_x)               \
	FN(sys_pwritev_x)                    \
	FN(sys_nanosleep_x)                  \
	FN(sys_getrlimit_x)                  \
	FN(sys_setrlimit_x)                  \
	FN(sys_prlimit_x)                    \
	FN(sched_switch_e)                   \
	FN(sched_drop)                       \
	FN(sys_fcntl_x)                      \
	FN(sys_ptrace_x)                     \
	FN(sys_mmap_x)                       \
	FN(sys_mmap2_x)                      \
	FN(sys_brk_x)                        \
	FN(sys_munmap_x)                     \
	FN(sys_renameat_x)                   \
	FN(sys_renameat2_x)                  \
	FN(sys_symlinkat_x)                  \
	FN(sys_procexit_e)                   \
	FN(sys_sendfile_x)                   \
	FN(sys_quotactl_x)                   \
	FN(sys_getresuid_and_gid_x)          \
	FN(sys_signaldeliver_e)              \
	FN(sys_pagefault_e)                  \
	FN(sys_setns_x)                      \
	FN(sys_unshare_x)                    \
	FN(sys_flock_x)                      \
	FN(cpu_hotplug_e)                    \
	FN(sys_semop_x)                      \
	FN(sys_semget_x)                     \
	FN(sys_semctl_x)                     \
	FN(sys_ppoll_x)                      \
	FN(sys_mount_x)                      \
	FN(sys_access_x)                     \
	FN(sys_socket_x)                     \
	FN(sys_bpf_x)                        \
	FN(sys_seccomp_x)                    \
	FN(sys_unlinkat_x)                   \
	FN(sys_fchmodat_x)                   \
	FN(sys_chmod_x)                      \
	FN(sys_fchmod_x)                     \
	FN(sys_chown_x)                      \
	FN(sys_lchown_x)                     \
	FN(sys_fchown_x)                     \
	FN(sys_fchownat_x)                   \
	FN(sys_mkdirat_x)                    \
	FN(sys_openat_e)                     \
	FN(sys_openat_x)                     \
	FN(sys_openat2_e)                    \
	FN(sys_openat2_x)                    \
	FN(sys_linkat_x)                     \
	FN(sys_mprotect_x)                   \
	FN(execve_extra_tail_1)              \
	FN(execve_extra_tail_2)              \
	FN(sys_copy_file_range_x)            \
	FN(sys_connect_e)                    \
	FN(sys_open_by_handle_at_x)          \
	FN(open_by_handle_at_x_extra_tail_1) \
	FN(sys_io_uring_setup_x)             \
	FN(sys_io_uring_enter_x)             \
	FN(sys_io_uring_register_x)          \
	FN(sys_mlock_x)                      \
	FN(sys_munlock_x)                    \
	FN(sys_mlockall_x)                   \
	FN(sys_munlockall_x)                 \
	FN(sys_capset_x)                     \
	FN(sys_dup2_x)                       \
	FN(sys_dup3_x)                       \
	FN(sys_dup_x)                        \
	FN(sched_prog_exec)                  \
	FN(sched_prog_exec_2)                \
	FN(sched_prog_exec_3)                \
	FN(sched_prog_exec_4)                \
	FN(sched_prog_exec_5)                \
	FN(sched_prog_fork)                  \
	FN(sched_prog_fork_2)                \
	FN(sched_prog_fork_3)                \
	FN(sys_mlock2_x)                     \
	FN(sys_fsconfig_x)                   \
	FN(sys_epoll_create_x)               \
	FN(sys_epoll_create1_x)              \
	FN(sys_epoll_wait_x)                 \
	FN(sys_close_x)                      \
	FN(sys_fchdir_x)                     \
	FN(sys_ioctl_x)                      \
	FN(sys_mkdir_x)                      \
	FN(sys_setgid_x)                     \
	FN(sys_setpgid_x)                    \
	FN(sys_setresgid_x)                  \
	FN(sys_listen_x)                     \
	FN(sys_signalfd_x)                   \
	FN(sys_splice_x)                     \
	FN(sys_umount_x)                     \
	FN(sys_umount2_x)                    \
	FN(sys_pipe2_x)                      \
	FN(sys_timerfd_create_x)             \
	FN(sys_inotify_init_x)               \
	FN(sys_inotify_init1_x)              \
	FN(sys_eventfd2_x)                   \
	FN(sys_signalfd4_x)                  \
	FN(sys_kill_x)                       \
	FN(sys_tkill_x)                      \
	FN(sys_tgkill_x)                     \
	FN(sys_prctl_x)                      \
	FN(sys_memfd_create_x)               \
	FN(sys_pidfd_getfd_x)                \
	FN(sys_pidfd_open_x)                 \
	FN(sys_init_module_x)                \
	FN(sys_finit_module_x)               \
	FN(sys_mknod_x)                      \
	FN(sys_mknodat_x)                    \
	FN(sys_newfstatat_x)                 \
	FN(sys_process_vm_readv_x)           \
	FN(sys_process_vm_writev_x)          \
	FN(sys_delete_module_x)              \
	FN(sys_pread64_x)                    \
	FN(sys_pwrite64_x)                   \
	FN(sys_setuid_x)                     \
	FN(sys_setresuid_x)                  \
	FN(terminate_filler)

#define FILLER_ENUM_FN(x) PPM_FILLER_##x,
enum ppm_filler_id { FILLER_LIST_MAPPER(FILLER_ENUM_FN) PPM_FILLER_MAX };
#undef FILLER_ENUM_FN

#define FILLER_PROTOTYPE_FN(x) int f_##x(struct event_filler_arguments *args);
FILLER_LIST_MAPPER(FILLER_PROTOTYPE_FN)
#undef FILLER_PROTOTYPE_FN

#endif /* PPM_FILLERS_H_ */
