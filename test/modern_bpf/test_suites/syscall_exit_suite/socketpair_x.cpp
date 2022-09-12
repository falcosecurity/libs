#include "../../event_class/event_class.h"

#if defined(__NR_socketpair) && defined(__NR_close)

#include <sys/socket.h>

TEST(SyscallExit, socketpairX_success)
{
	auto evt_test = get_syscall_event_test(__NR_socketpair, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = PF_LOCAL;
	int type = SOCK_STREAM;
	int protocol = 0;
	int32_t fd[2];
	assert_syscall_state(SYSCALL_SUCCESS, "socketpair", syscall(__NR_socketpair, domain, type, protocol, fd), NOT_EQUAL, -1);
	syscall(__NR_close, fd[0]);
	syscall(__NR_close, fd[1]);

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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: fd1 (type: PT_FD)*/
	evt_test->assert_numeric_param(2, (int64_t)fd[0]);

	/* Parameter 3: fd2 (type: PT_FD)*/
	evt_test->assert_numeric_param(3, (int64_t)fd[1]);

	/* Parameter 4: source (type: PT_UINT64)*/
	/* Here we have a kernel pointer, we don't know the exact value. */
	evt_test->assert_numeric_param(4, (uint64_t)0, NOT_EQUAL);

	/* Parameter 5: peer (type: PT_UINT64)*/
	/* Here we have a kernel pointer, we don't know the exact value. */
	evt_test->assert_numeric_param(5, (uint64_t)0, NOT_EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

TEST(SyscallExit, socketpairX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_socketpair, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int domain = PF_LOCAL;
	int type = SOCK_STREAM;
	int protocol = 0;
	int32_t* fd = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "socketpair", syscall(__NR_socketpair, domain, type, protocol, fd));
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

	/* Parameter 4: source (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)0);

	/* Parameter 5: peer (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, (uint64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif
