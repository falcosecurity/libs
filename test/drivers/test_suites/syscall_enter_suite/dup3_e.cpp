#include "../../event_class/event_class.h"
#include "../../helpers/file_opener.h"

#if defined(__NR_dup3) && defined(__NR_openat) && defined(__NR_close)
TEST(SyscallEnter, dup3E)
{
	auto evt_test = get_syscall_event_test(__NR_dup3, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	auto fo = file_opener(".", (O_RDWR | O_TMPFILE));
	int32_t old_fd = fo.get_fd();

	/* If `oldfd` equals `newfd`, then dup3() fails with the error `EINVAL`. */
	int32_t new_fd = old_fd;
	int32_t flags = O_CLOEXEC;
	int32_t res = syscall(__NR_dup3, old_fd, new_fd, flags);
	assert_syscall_state(SYSCALL_FAILURE, "dup3", res);

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

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)old_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
