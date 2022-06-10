#include "../../event_class/event_class.h"
#include "../../helpers/proc_parsing.h"

#if defined(CAPTURE_SCHED_PROC_EXEC) && defined(__NR_clone3) && defined(__NR_wait4) && defined(__NR_execve)

#include <linux/sched.h>

TEST(GenericTracepoints, sched_proc_exec)
{
	auto evt_test = get_generic_event_test(PPME_SYSCALL_EXECVE_19_X);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	const char *pathname = "/usr/bin/echo";
	const char *comm = "echo";
	const char *argv[] = {pathname, "[OUTPUT] GenericTracepoints.sched_proc_exec test", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	struct clone_args cl_args = {0};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		syscall(__NR_execve, pathname, argv, envp);
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE)
	{
		FAIL() << "The child execve failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

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
}
#endif
