#include "../../event_class/event_class.h"

#ifdef __NR_quotactl

#include <sys/quota.h>

TEST(SyscallEnter, quotactlE)
{
	auto evt_test = get_syscall_event_test(__NR_quotactl, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int cmd = QCMD(Q_SYNC, USRQUOTA);
	const char* special = "/dev//*null";
	int id = 1;
	struct if_dqblk addr = {};
	assert_syscall_state(SYSCALL_FAILURE, "quotactl", syscall(__NR_quotactl, cmd, special, id, &addr));

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

	/* Parameter 1: cmd (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(1, (uint16_t)PPM_Q_SYNC);

	/* Parameter 2: type (type: PT_FLAGS8) */
	evt_test->assert_numeric_param(2, (uint8_t)PPM_USRQUOTA);

	/* Parameter 3: id (type: PT_UINT32) */
	/* With `PPM_Q_SYNC` we expect `0` */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 4: quota_fmt (type: PT_FLAGS8) */
	/* With `PPM_Q_SYNC` we expect `PPM_QFMT_NOT_USED` */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_QFMT_NOT_USED);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
