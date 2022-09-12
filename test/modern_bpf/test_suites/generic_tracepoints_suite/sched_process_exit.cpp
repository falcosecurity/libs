#include "../../event_class/event_class.h"

#include <sys/types.h>
#include <sys/wait.h>

#if defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

TEST(GenericTracepoints, sched_proc_exit)
{
	auto evt_test = get_generic_event_test(PPME_PROCEXIT_1_E);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	struct clone_args cl_args = {0};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* Child terminates immediately. */
		exit(5);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	uint8_t sig = 0;
	if(__WIFSIGNALED(status) != 0)
	{
		sig = __WTERMSIG(status);
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* The sched_process_exit hook is called by the thread that is going to die. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: status (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)status);

	/* Parameter 2: ret (type: PT_ERRNO) */
	evt_test->assert_numeric_param(2, (int64_t)__WEXITSTATUS(status));

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	evt_test->assert_numeric_param(3, (uint8_t)sig);

	/* Parameter 4: core (type: PT_UINT8) */
	evt_test->assert_numeric_param(4, (uint8_t)(__WCOREDUMP(status) != 0));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
