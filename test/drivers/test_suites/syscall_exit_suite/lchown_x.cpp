#include "../../event_class/event_class.h"

#ifdef __NR_lchown
TEST(SyscallExit, lchownX)
{
	auto evt_test = get_syscall_event_test(__NR_lchown, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const char* filename = "*//null";
	uint32_t uid = 0;
	uint32_t gid = 0;
	assert_syscall_state(SYSCALL_FAILURE, "lchown", syscall(__NR_lchown, filename, uid, gid));
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, errno_value);

	/* Parameter 2: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, filename);

	/* Parameter 3: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)uid);

	/* Parameter 4: gid (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)gid);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
