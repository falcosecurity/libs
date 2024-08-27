#include "../../event_class/event_class.h"

#ifdef __NR_poll

#include <poll.h>

TEST(SyscallExit, pollX_success)
{
	auto evt_test = get_syscall_event_test(__NR_poll, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	struct pollfd fds[2];

	fds[0].fd = -1;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	fds[1].fd = -10;
	fds[1].events = POLLWRBAND;
	fds[1].revents = 0;

	nfds_t nfds = 2;
	int timeout = 0;

	/* We will use this array for assertions */
	struct fd_poll expected[2];

	expected[0].fd = fds[0].fd;
	/* Here we will catch the returned events `revents`. Since the file descriptor is negative
	 * according to the the `poll` man the `revents` should be `0`.
	 */
	expected[0].flags = 0;

	expected[1].fd = fds[1].fd;
	expected[1].flags = 0;

	assert_syscall_state(SYSCALL_SUCCESS, "poll", syscall(__NR_poll, fds, nfds, timeout), NOT_EQUAL, -1);

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

	/* Parameter 1: ret (type: PT_FD) */
	/* The return value should be 0 since timeout is `0` and `poll` should
	 * return `0` when timed out before any file descriptors became read.
	 */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: fds (type: PT_FDLIST) */
	evt_test->assert_fd_list(2, (struct fd_poll *)&expected, 2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif
