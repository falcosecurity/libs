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
	struct proc_info info = {0};
	pid_t pid = ::getpid();
	if(!get_proc_info(pid, &info))
	{
		FAIL() << "Unable to get all the info from proc" << std::endl;
	}

	/*
	 * Get the process capabilities.
	 */

	/* On kernels >= 5.8 the suggested version should be `_LINUX_CAPABILITY_VERSION_3` */
	struct __user_cap_header_struct header = {0};
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
	evt_test->assert_numeric_param(11, (uint32_t)info.vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(12, (uint32_t)info.vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(13, (uint32_t)info.vm_swap);

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

	/* Parameter 19: loginuid (type: PT_UINT32) */
	evt_test->assert_numeric_param(19, (uint32_t)info.loginuid);

	/* Parameter 20: flags (type: PT_UINT32) */
	/* Right now we send always `0`. */
	evt_test->assert_numeric_param(20, (uint32_t)0);

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

	/* Parameter 27: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(27);
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
	const char *comm = "echo";
	const char *argv[] = {pathname, "[OUTPUT] SyscallExit.execveatX_success test", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
	int flags = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	struct clone_args cl_args = {0};
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

	if(__WEXITSTATUS(status) == EXIT_FAILURE)
	{
		FAIL() << "The child execveat failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

#if __s390x__
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

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &envp[0]);

	/* Parameter 20: flags (type: PT_UINT32) */
	/* Right now we send always `0`. */
	evt_test->assert_numeric_param(20, (uint32_t)0);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(27);
#else
	/* We search for a child event. */
	evt_test->assert_event_absence(ret_pid);
#endif
}

TEST(SyscallExit, execveatX_execve_exit)
{
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

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
	struct clone_args cl_args = {0};
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

	if(__WEXITSTATUS(status) == EXIT_FAILURE)
	{
		FAIL() << "The child execveat failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

/* Some architectures like aarch64 don't return either an `EXECVEAT_X` or
 * an `EXECVE_X` event, this is a known issue you look at `feature_gates.h`
 * for more info. `s390x` already returns an `EXECVEAT_X` event so here we shouldn't
 * receive anything.
 */
#if defined(__s390x__) || defined(CAPTURE_SCHED_PROC_EXEC)
	/* We search for a child event. */
	evt_test->assert_event_absence(ret_pid);
#else
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

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &envp[0]);

	/* Parameter 20: flags (type: PT_UINT32) */
	/* Right now we send always `0`. */
	evt_test->assert_numeric_param(20, (uint32_t)0);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type: PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(27);
#endif
}
#endif
