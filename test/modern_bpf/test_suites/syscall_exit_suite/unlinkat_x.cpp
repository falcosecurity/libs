#include "../../event_class/event_class.h"

#ifdef __NR_unlinkat
TEST(SyscallExit, unlinkatX)
{
	auto evt_test = get_syscall_event_test(__NR_unlinkat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_dirfd = -1;
	const char* path = "//**null**//";
	uint32_t flags = AT_REMOVEDIR;
	assert_syscall_state(SYSCALL_FAILURE, "unlinkat", syscall(__NR_unlinkat, mock_dirfd, path, flags));
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
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_dirfd);

	/* Parameter 3: name (type: PT_FSRELPATH) */
	evt_test->assert_charbuf_param(3, path);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (uint32_t)PPM_AT_REMOVEDIR);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
