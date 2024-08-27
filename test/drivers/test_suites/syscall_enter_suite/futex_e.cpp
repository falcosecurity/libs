#include "../../event_class/event_class.h"

#include <linux/futex.h>
#include <stdint.h>
#include <sys/time.h>

#ifdef __NR_futex
TEST(SyscallEnter, futexE)
{
	auto evt_test = get_syscall_event_test(__NR_futex, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t futex_word;
	int futex_op = FUTEX_PRIVATE_FLAG;
	uint32_t val = 7;
	assert_syscall_state(SYSCALL_FAILURE, "futex", syscall(__NR_futex, &futex_word, futex_op, val, NULL, NULL, 0));

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

	/* Parameter 1: addr (type: PT_UINT64) */
	evt_test->assert_numeric_param(1, (uint64_t)&futex_word);

	/* Parameter 2: op (type: PT_ENUMFLAGS16) */
	evt_test->assert_numeric_param(2, (uint16_t)PPM_FU_FUTEX_PRIVATE_FLAG);

	/* Parameter 3: val (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)val);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
