#include "../../event_class/event_class.h"

#ifdef __NR_pipe2

/* It is useless to test again the logic here since the BPF program is the same as `pipe`.
 * Here we want only to test that the correct BPF program is triggered, so the failure case
 * is enough.
 */

TEST(SyscallExit, pipe2X_failure)
{
	/* Please note:
	 * the syscall `pipe2` is mapped to `PPME_SYSCALL_PIPE_X` event
	 * like `pipe`. The same BPF program will be used for both the syscalls.
	 *
	 * TODO: we can add a new event for `pipe2` since here we don't catch the
	 * `flag` param.
	 */

	auto evt_test = new event_test(__NR_pipe2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t* pipefd = NULL;
	int flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "pipe2", syscall(__NR_pipe2, pipefd, flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd1 (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)-1);

	/* Parameter 3: fd2 (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)-1);

	/* Parameter 4: ino (type: PT_UINT64)*/
	evt_test->assert_numeric_param(4, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

#endif /* __NR_pipe */
