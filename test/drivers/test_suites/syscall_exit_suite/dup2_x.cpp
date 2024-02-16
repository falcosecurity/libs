#include "../../event_class/event_class.h"
#include "../../helpers/file_opener.h"
#include <fcntl.h>

#if defined(__NR_dup2) && defined(__NR_openat) && defined(__NR_close)
TEST(SyscallExit, dup2X)
{
	auto evt_test = get_syscall_event_test(__NR_dup2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	auto fo = file_opener(".", (O_RDWR | O_TMPFILE));
	int32_t old_fd = fo.get_fd();

	int32_t new_fd = old_fd;
	int32_t res = syscall(__NR_dup2, old_fd, new_fd);
	assert_syscall_state(SYSCALL_SUCCESS, "dup2", res, NOT_EQUAL, -1);

	syscall(__NR_close, new_fd);
	syscall(__NR_close, res);

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
	evt_test->assert_numeric_param(1, (int64_t)res);

	/* Parameter 2: oldfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)old_fd);

	/* Parameter 3: newfd (type: PT_FD) */
	evt_test->assert_numeric_param(3, (int64_t)new_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
