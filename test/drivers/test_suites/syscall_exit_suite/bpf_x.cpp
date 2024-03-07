#include "../../event_class/event_class.h"

#if defined(__NR_bpf) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>
#include <linux/bpf.h>
#include <sys/mman.h>

TEST(SyscallExit, bpfX_invalid_cmd)
{
	auto evt_test = get_syscall_event_test(__NR_bpf, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t cmd = -1;
	union bpf_attr *attr = NULL;
	uint32_t size = 0;

	/* Here we need to call the `bpf` from a child because the main process throws lots of
	 * `bpf` syscalls to manage the bpf drivers.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* In this way in the father we know if the call was successful or not. */
		if(syscall(__NR_bpf, cmd, attr, size) == -1)
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
		FAIL() << "The bpf call is successful while it should fail..." << std::endl;
	}

	/* This is the errno value we expect from the `bpf` call. */
	int64_t errno_value = -EINVAL;

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
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: cmd (type: PT_INT32) */
	evt_test->assert_numeric_param(2, cmd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}


TEST(SyscallExit, bpfX_MAP_CREATE)
{
	auto evt_test = get_syscall_event_test(__NR_bpf, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t cmd = BPF_MAP_CREATE;
	union bpf_attr *attr = NULL; 
	

	/* Here we need to call the `bpf` from a child because the main process throws lots of
	 * `bpf` syscalls to manage the bpf drivers.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0)
	{
		/* In this way in the father we know if the call was successful or not. */
		if(syscall(__NR_bpf, cmd, attr, sizeof(attr) == -1))
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
		FAIL() << "The bpf call is successful while it should fail..." << std::endl;
	}

	int64_t errno_value = -EINVAL;

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
	evt_test->assert_numeric_param(1, errno_value);
	/* Parameter 2: cmd (type: PT_ENUMFLAGS32)*/
	evt_test->assert_numeric_param(2, PPM_BPF_MAP_CREATE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif
