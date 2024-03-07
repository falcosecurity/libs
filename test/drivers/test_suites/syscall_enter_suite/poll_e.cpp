#include "../../event_class/event_class.h"

#ifdef __NR_poll

#include <poll.h>
/* Right now this is our limit in the drivers */
#define MAX_FDS 16

TEST(SyscallEnter, pollE_null_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_poll, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	struct pollfd *fds = NULL;
	uint32_t nfds = 5;
	int timeout = 0;
	assert_syscall_state(SYSCALL_FAILURE, "poll", syscall(__NR_poll, fds, nfds, timeout));

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

	/* Parameter 1: fds (type: PT_FDLIST) */
	/* The pointer is NULL so we should have no `fd` collected */
	evt_test->assert_fd_list(1, NULL, (uint16_t)0);

	/* Parameter 2: timeout (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)timeout);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, pollE_empty_nfds)
{
	auto evt_test = get_syscall_event_test(__NR_poll, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	struct pollfd fds[2];

	fds[0].fd = -1;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	fds[1].fd = -10;
	fds[1].events = POLLWRBAND;
	fds[1].revents = 0;

	/* We send it empty so expect no fd in the structs to be collected */
	uint32_t nfds = 0;
	int timeout = 0;
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

	/* Parameter 1: fds (type: PT_FDLIST) */
	/* `nfds` is 0 so we should have no `fd` collected */
	evt_test->assert_fd_list(1, NULL, (uint16_t)0);

	/* Parameter 2: timeout (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)timeout);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, pollE_not_truncated)
{
	auto evt_test = get_syscall_event_test(__NR_poll, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	struct pollfd fds[2];

	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLPRI | POLLOUT | POLLRDHUP | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	fds[0].revents = 0;

	fds[1].fd = -10;
	fds[1].events = POLLWRBAND;
	fds[1].revents = 0;

	nfds_t nfds = 2;
	int timeout = 0;

	/* We will use this array for assertions */
	struct fd_poll expected[2];

	expected[0].fd = fds[0].fd;
	expected[0].flags = PPM_POLLIN | PPM_POLLPRI | PPM_POLLOUT | PPM_POLLRDHUP | PPM_POLLERR | PPM_POLLHUP | PPM_POLLNVAL | PPM_POLLRDNORM | PPM_POLLRDBAND | PPM_POLLWRNORM | PPM_POLLWRBAND;

	expected[1].fd = fds[1].fd;
	expected[1].flags = PPM_POLLWRBAND;

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

	/* Parameter 1: fds (type: PT_FDLIST) */
	evt_test->assert_fd_list(1, (struct fd_poll *)&expected, 2);

	/* Parameter 2: timeout (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)timeout);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallEnter, pollE_truncated)
{
	auto evt_test = get_syscall_event_test(__NR_poll, ENTER_EVENT);

	if(evt_test->is_kmod_engine())
	{
		GTEST_SKIP() << "[POLL_E]: the kmod is not subject to params truncation like BPF drivers" << std::endl;
	}

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* We push more than MAX_FDS structs. We should obtain only `MAX_FDS` structs */
	struct pollfd fds[MAX_FDS + 1] = {};
	nfds_t nfds = MAX_FDS + 1;
	int timeout = 0;

	/* We expect only `MAX_FDS` structs */
	struct fd_poll expected[MAX_FDS] = {};

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

	/* Parameter 1: fds (type: PT_FDLIST) */
	evt_test->assert_fd_list(1, (struct fd_poll *)&expected, MAX_FDS);

	/* Parameter 2: timeout (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)timeout);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

#endif
