#include "../../event_class/event_class.h"

#ifdef __NR_mkdir
TEST(SyscallExit, mkdirX)
{
	auto evt_test = new event_test(__NR_mkdir, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	uint32_t mode = 7;
	const char* path = "*//null";
	evt_test->assert_syscall_failure(syscall(__NR_mkdir, path, mode), "mkdir");
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* 1° Parameter: res (type: PT_ERRNO)*/
	evt_test->assert_s64_param(1, errno_value);

	/* 2° Parameter: path (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, path);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}
#endif