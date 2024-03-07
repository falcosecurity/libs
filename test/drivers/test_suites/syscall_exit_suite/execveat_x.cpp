#include "../../event_class/event_class.h"
#include "../../flags/flags_definitions.h"
#include "../../helpers/proc_parsing.h"

#if defined(__NR_execveat) && defined(__NR_capget) && defined(__NR_clone3) && defined(__NR_wait4) && defined(__NR_execve)

#include <linux/sched.h>

TEST(SyscallExit, execveatX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_execveat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Get all the info from proc. */
	struct proc_info info = {};
	pid_t pid = ::getpid();
	if(!get_proc_info(pid, &info))
	{
		FAIL() << "Unable to get all the info from proc" << std::endl;
	}

	/*
	 * Get the process capabilities.
	 */

	/* On kernels >= 5.8 the suggested version should be `_LINUX_CAPABILITY_VERSION_3` */
	struct __user_cap_header_struct header = {};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	cap_user_header_t hdrp = &header;
	cap_user_data_t datap = data;

	/* Prepare the header. */
	header.pid = 0; /* `0` means the pid of the actual process. */
	header.version = _LINUX_CAPABILITY_VERSION_3;
	assert_syscall_state(SYSCALL_SUCCESS, "capget", syscall(__NR_capget, hdrp, datap), EQUAL, 0);

	/*
	 * Call the `execveat`
	 */
	int dirfd = AT_FDCWD;
	char pathname[] = "//**null-file-path**//";
	const char *newargv[] = {pathname, "first_argv", "second_argv", NULL};
	const char *newenviron[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
	int flags = AT_SYMLINK_NOFOLLOW;
	assert_syscall_state(SYSCALL_FAILURE, "execveat", syscall(__NR_execveat, dirfd, pathname, newargv, newenviron, flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &newargv[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)info.ppid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)info.file_rlimit.rlim_cur);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(9, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(10, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(11, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(12, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(13, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &newenviron[0]);

	/* Parameter 17: tty (type: PT_UINT32) */
	evt_test->assert_numeric_param(17, (uint32_t)info.tty);

	/* Parameter 18: pgid (type: PT_PID) */
	/* If we run in a namespace different from the init one probably this will fail. */
	evt_test->assert_numeric_param(18, (int64_t)info.pgid);

	/* Parameter 19: loginuid (type: PT_UID) */
	evt_test->assert_numeric_param(19, (uint32_t)info.loginuid);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the executable
	 * file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	evt_test->assert_numeric_param(21, (uint64_t)capabilities_to_scap(((unsigned long)data[1].inheritable << 32) | data[0].inheritable));

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	evt_test->assert_numeric_param(22, (uint64_t)capabilities_to_scap(((unsigned long)data[1].permitted << 32) | data[0].permitted));

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	evt_test->assert_numeric_param(23, (uint64_t)capabilities_to_scap(((unsigned long)data[1].effective << 32) | data[0].effective));

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	/* Here we don't call the execveat so the result should be the full path to the drivers test executable */
	evt_test->assert_charbuf_param(28, info.exepath);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(28);
}

/* All architectures return an `EXECVEAT_X` event when the syscall fails, but only
 * `s390x` seems to return an `EXECVEAT_X` event also when the syscall succeeds, other
 * architectures like `x86_64` return an `EXECVE_X` event.
 */
TEST(SyscallExit, execveatX_correct_exit)
{
	auto evt_test = get_syscall_event_test(__NR_execveat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	int dirfd = 0;
	const char *pathname = "/usr/bin/echo";
	const char *argv[] = {pathname, "[OUTPUT] SyscallExit.execveatX_success test", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
	int flags = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The child execveat failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

#if defined(__s390x__) || defined(__riscv) || defined(__powerpc64__)
	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	const char *comm = "echo";

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &argv[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)ret_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)ret_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &envp[0]);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the executable
	 * file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(28);
#else
	/* We search for a child event. */
	evt_test->assert_event_absence(ret_pid);
#endif
}

TEST(SyscallExit, execveatX_execve_exit)
{
	auto evt_test = get_syscall_event_test();

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	int dirfd = 0;
	const char *pathname = "/usr/bin/echo";
	const char *comm = "echo";
	const char *argv[] = {pathname, "[OUTPUT] SyscallExit.execveatX_success test", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
	int flags = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The child execveat failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

/* `s390x` returns an `EXECVEAT_X` event while other architectures retun an `EXECVE_X` */
#if defined(__s390x__) || defined(__riscv) || defined(__powerpc64__)
	/* We search for a child event. */
	evt_test->assert_event_absence(ret_pid, PPME_SYSCALL_EXECVE_19_X);
#else
	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid, PPME_SYSCALL_EXECVE_19_X);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &argv[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)ret_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)ret_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &envp[0]);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the executable
	 * file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(28);
#endif
}

#if defined(__NR_memfd_create) && defined(__NR_openat) && defined(__NR_read) && defined(__NR_write)
#include <sys/mman.h>
TEST(SyscallExit, execveatX_success_memfd)
{
	auto evt_test = get_syscall_event_test(__NR_execveat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mem_fd = syscall(__NR_memfd_create, "malware", MFD_CLOEXEC);
	assert_syscall_state(SYSCALL_SUCCESS, "memfd_create", mem_fd, NOT_EQUAL, -1);

	/* Open the executable to copy */
	int fd_to_read = syscall(__NR_openat, 0, "/usr/bin/echo", O_RDWR);
	if(fd_to_read < 0)
	{
		FAIL() << "failed to open the file to read\n";
	}

	char buf[200];
	ssize_t bytes_read = 200;
	while(bytes_read != 0)
	{
		bytes_read = syscall(__NR_read, fd_to_read, buf, sizeof(buf));
		if(bytes_read < 0)
		{
			syscall(__NR_close, fd_to_read);
			syscall(__NR_close, mem_fd);
			FAIL() << "unable to read from file\n";
		}

		bytes_read = syscall(__NR_write, mem_fd, buf, bytes_read);
		if(bytes_read < 0)
		{
			syscall(__NR_close, fd_to_read);
			syscall(__NR_close, mem_fd);
			FAIL() << "unable to write to file\n";
		}
	}
	syscall(__NR_close, fd_to_read);

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		char pathname[200];
		snprintf(pathname, sizeof(pathname), "/proc/%d/fd/%d", getpid(), mem_fd);
		const char *newargv[] = {pathname, "[OUTPUT] SyscallExit.execveX_success_memfd", NULL};
		const char *newenviron[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
		syscall(__NR_execveat, 0, pathname, newargv, newenviron, 0);
		exit(EXIT_FAILURE);
	}
	syscall(__NR_close, mem_fd);

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL,
			     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The child execve failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

#if defined(__s390x__) || defined(__riscv) || defined(__powerpc64__)
	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the executable
	 * file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE | PPM_EXE_FROM_MEMFD);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	/* In the kmod, we use the "d_path" helper while in BPF we reconstruct the path
	 * by hand so the result is a little bit different.
	 * Please note that in the kernel module, we remove the " (deleted)" suffix while
	 * in BPF we don't add it at all.
	 */
	if(evt_test->is_kmod_engine())
	{
		evt_test->assert_charbuf_param(28, "/memfd:malware");
	}
	else
	{
		/* In BPF drivers we don't have the correct result but we can reconstruct part of it */
		evt_test->assert_charbuf_param(28, "memfd:malware");
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(28);
#else
	/* We search for a child event. */
	evt_test->assert_event_absence(ret_pid);
#endif
}
#endif
#endif
