#include "../../event_class/event_class.h"

#ifdef __NR_ppoll

#include <poll.h>

TEST(SyscallExit, ppollX)
{
	auto evt_test = get_syscall_event_test(__NR_ppoll, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we are not interested in testing the `fd` collection logic we have already
	 * tested it with `poll` syscall.
	 */
	struct pollfd* fds = NULL;
	struct timespec* timestamp = NULL;
	sigset_t* sigmask = NULL;
	uint32_t nfds = 5;
	assert_syscall_state(SYSCALL_FAILURE, "ppoll", syscall(__NR_ppoll, fds, nfds, timestamp, sigmask));
	int64_t errno_value = -errno;

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
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fds (type: PT_FDLIST) */
	/* The pointer is NULL so we should have no `fd` collected */
	evt_test->assert_fd_list(2, NULL, (uint16_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif
