#include "../../event_class/event_class.h"

#if defined(__NR_socket) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>
#include <sys/socket.h>

TEST(SyscallEnter, socketE)
{
	auto evt_test = get_syscall_event_test(__NR_socket, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = AF_INET;
	int type = SOCK_RAW;
	int protocol = PF_INET;

	/* Here we need to call the `socket` from a child because the main process throws a `socket`
	 * syscall to calibrate the socket file options if we are using the bpf probe.
	 */
	clone_args cl_args = {};
	cl_args.flags = CLONE_FILES;
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* In this way in the father we know if the call was successful or not. */
		if(syscall(__NR_socket, domain, type, protocol) == -1)
		{
			exit(EXIT_FAILURE);
		}
		else
		{
			exit(EXIT_SUCCESS);
		}
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);
	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0)
	{
		FAIL() << "The socket call failed while it should be successful..." << std::endl;
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

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(1, (uint32_t)PPM_AF_INET);

	/* Parameter 2: type (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)type);

	/* Parameter 3: proto (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)protocol);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
