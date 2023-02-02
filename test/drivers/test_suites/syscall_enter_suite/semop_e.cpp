#include "../../event_class/event_class.h"

#ifdef __NR_semop

#include <sys/sem.h>

TEST(SyscallEnter, semopE)
{
	auto evt_test = get_syscall_event_test(__NR_semop, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int semid = -1;
	struct sembuf *sops = NULL;
	size_t nsops = 0;
	assert_syscall_state(SYSCALL_FAILURE, "semop", syscall(__NR_semop, semid, sops, nsops));

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

	/* Parameter 1: semid (type: PT_INT32)*/
	evt_test->assert_numeric_param(1, (int32_t)semid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
