#include "../../event_class/event_class.h"

#ifdef __NR_pipe

#if defined(__NR_fstat) && defined(__NR_close)

TEST(SyscallExit, pipeX_success)
{
	auto evt_test = get_syscall_event_test(__NR_pipe, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t pipefd[2];
	assert_syscall_state(SYSCALL_SUCCESS, "pipe", syscall(__NR_pipe, pipefd), NOT_EQUAL, -1);

	struct stat file_stat;
	assert_syscall_state(SYSCALL_SUCCESS, "fstat", syscall(__NR_fstat, pipefd[0], &file_stat), NOT_EQUAL, -1);
	uint64_t inode = file_stat.st_ino;

	syscall(__NR_close, pipefd[0]);
	syscall(__NR_close, pipefd[1]);

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
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: fd1 (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)pipefd[0]);

	/* Parameter 3: fd2 (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)pipefd[1]);

	/* Parameter 4: ino (type: PT_UINT64)*/
	evt_test->assert_numeric_param(4, (uint64_t)inode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

#endif /* defined(__NR_fstat) && defined(__NR_close) */

TEST(SyscallExit, pipeX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_pipe, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t* pipefd = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "pipe", syscall(__NR_pipe, pipefd));
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
