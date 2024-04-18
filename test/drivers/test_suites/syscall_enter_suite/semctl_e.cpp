#include "../../event_class/event_class.h"

#ifdef __NR_semctl

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

TEST(SyscallEnter, semctlE)
{
	auto evt_test = get_syscall_event_test(__NR_semctl, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t semid = -1;
	int32_t semnum = 0;
	uint16_t cmd = SETVAL;
	int32_t val = 1;
	assert_syscall_state(SYSCALL_FAILURE, "semctl", syscall(__NR_semctl, semid, semnum, cmd, val));

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

	/* Parameter 1: semid (type: PT_INT32) */
	evt_test->assert_numeric_param(1, (int32_t)semid);

	/* Parameter 2: semnum (type: PT_INT32) */
	evt_test->assert_numeric_param(2, (int32_t)semnum);

	/* Parameter 3: cmd (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(3, (uint16_t)PPM_SETVAL);

	/* Parameter 4: val (type: PT_INT32) */
	evt_test->assert_numeric_param(4, (int32_t)val);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif