#include "../../event_class/event_class.h"

#if defined(__NR_ioctl) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>
#include <sys/ioctl.h>

TEST(SyscallEnter, ioctlE)
{
	auto evt_test = get_syscall_event_test(__NR_ioctl, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* The `fd` must be an open file descriptor. In this case, we pass an invalid
	 * file descriptor so the call will fail.
	 */
	int32_t mock_fd = -1;
	uint64_t request = SIOCGIFCOUNT;
	char* argp = NULL;

	/* Here we need to call the `ioctl` from a child because the main process throws lots of
	 * `ioctl` to manage the kmod.
	 */
	clone_args cl_args = {};
	cl_args.flags = CLONE_FILES;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* In this way in the father we know if the call was successful or not. */
		if(syscall(__NR_ioctl, mock_fd, request, argp) == -1)
		{
			/* SUCCESS because we want the call to fail */
			exit(EXIT_SUCCESS);
		}
		else
		{
			exit(EXIT_FAILURE);
		}
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The ioctl call is successful while it should fail..." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/* Parameter 2: request (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)request);

	/* Parameter 3: argument (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
