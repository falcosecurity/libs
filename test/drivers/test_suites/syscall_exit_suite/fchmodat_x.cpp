#include "../../event_class/event_class.h"

#ifdef __NR_fchmodat
TEST(SyscallExit, fchmodatX)
{
	auto evt_test = get_syscall_event_test(__NR_fchmodat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_dirfd = -1;
	const char* pathname = "*//null";
	uint32_t mode = S_IXUSR;
	uint32_t flags = 0;
	assert_syscall_state(SYSCALL_FAILURE, "fchmodat", syscall(__NR_fchmodat, mock_dirfd, pathname, mode, flags));
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

	/* Parameter 3: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: mode (type: PT_MODE) */
	evt_test->assert_numeric_param(4, (uint32_t)PPM_S_IXUSR);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
