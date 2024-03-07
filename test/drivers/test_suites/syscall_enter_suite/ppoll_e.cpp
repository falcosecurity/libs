#include "../../event_class/event_class.h"

#ifdef __NR_ppoll

#include <poll.h>
#include <signal.h>

TEST(SyscallEnter, ppollE_null_pointers)
{
	auto evt_test = get_syscall_event_test(__NR_ppoll, ENTER_EVENT);

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

	/* Parameter 2: timeout (type: PT_RELTIME) */
	/* The pointer is NULL so we should have `0` */
	evt_test->assert_numeric_param(2, (uint64_t)0);

	/* Parameter 3: sigmask (type: PT_SIGSET) */
	/* The pointer is NULL so we should have `0` */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallEnter, ppollE_valid_pointers)
{
	auto evt_test = get_syscall_event_test(__NR_ppoll, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Here we are not interested in testing the `fd` collection logic we have already
	 * tested it with `poll` syscall.
	 */
	struct pollfd* fds = NULL;
	struct timespec timestamp = {};
	timestamp.tv_sec = 2;
	timestamp.tv_nsec = 250;
	sigset_t sigmask;
	sigmask.__val[0] = SIGIO;
	sigmask.__val[1] = SIGTERM;
	uint32_t nfds = 5;
	assert_syscall_state(SYSCALL_FAILURE, "ppoll", syscall(__NR_ppoll, fds, nfds, &timestamp, &sigmask));

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

	/* Parameter 2: timeout (type: PT_RELTIME) */
	/* The pointer is NULL so we should have UINT64_MAX */
	evt_test->assert_numeric_param(2, ((uint64_t)timestamp.tv_sec * SEC_FACTOR) + timestamp.tv_nsec);

	/* Parameter 3: sigmask (type: PT_SIGSET) */
	evt_test->assert_numeric_param(3, (uint32_t)SIGIO);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

#endif
