#include "../../event_class/event_class.h"

#ifdef __NR_quotactl

#include <sys/quota.h>

TEST(SyscallExit, quotactlX)
{
	auto evt_test = get_syscall_event_test(__NR_quotactl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int cmd = QCMD(Q_SYNC, USRQUOTA);
	const char* special = "/dev//*null";
	int id = 1;
	struct if_dqblk addr = {};
	assert_syscall_state(SYSCALL_FAILURE, "quotactl", syscall(__NR_quotactl, cmd, special, id, &addr));
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

	/* Parameter 1: res (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: special (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, special);

	/* Parameter 3: quotafilepath (type: PT_CHARBUF) */
	/* We get `quotafilepath` only for `QUOTAON` cmd. */
	evt_test->assert_empty_param(3);

	/* Since we use `PPM_Q_SYNC` we expect `0` for all params from 4 to 13 */

	/* Parameter 4: dqb_bhardlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)0);

	/* Parameter 5: dqb_bsoftlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, (uint64_t)0);

	/* Parameter 6: dqb_curspace (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, (uint64_t)0);

	/* Parameter 7: dqb_ihardlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(7, (uint64_t)0);

	/* Parameter 8: dqb_isoftlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)0);

	/* Parameter 9: dqb_btime (type: PT_RELTIME) */
	evt_test->assert_numeric_param(9, (uint64_t)0);

	/* Parameter 10: dqb_itime (type: PT_RELTIME) */
	evt_test->assert_numeric_param(10, (uint64_t)0);

	/* Parameter 11: dqi_bgrace (type: PT_RELTIME) */
	evt_test->assert_numeric_param(11, (uint64_t)0);

	/* Parameter 12: dqi_igrace (type: PT_RELTIME) */
	evt_test->assert_numeric_param(12, (uint64_t)0);

	/* Parameter 13: dqi_flags (type: PT_FLAGS8) */
	evt_test->assert_numeric_param(13, (uint8_t)0);

	/* Parameter 14: quota_fmt_out (type: PT_FLAGS8) */
	evt_test->assert_numeric_param(14, (uint8_t)PPM_QFMT_NOT_USED);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(14);
}

/// TODO: Probably we can add further tests on this exit event

#endif
