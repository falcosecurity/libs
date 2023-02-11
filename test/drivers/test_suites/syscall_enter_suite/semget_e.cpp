#include "../../event_class/event_class.h"

#ifdef __NR_semget

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

TEST(SyscallEnter, semgetE)
{
	auto evt_test = get_syscall_event_test(__NR_semget, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	key_t key = 0;
	int32_t nsems = -1;
	int32_t semflg = IPC_CREAT;
	assert_syscall_state(SYSCALL_FAILURE, "semget", syscall(__NR_semget, key, nsems, semflg));

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

	/* Parameter 1: key (type: PT_INT32) */
	evt_test->assert_numeric_param(1, (int32_t)key);

	/* Parameter 2: nsems (type: PT_INT32) */
	evt_test->assert_numeric_param(2, (int32_t)nsems);

	/* Parameter 3: semflg (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (int32_t)PPM_IPC_CREAT);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif