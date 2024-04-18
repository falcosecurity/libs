#include "../../event_class/event_class.h"

#if defined(__NR_init_module)

TEST(SyscallExit, init_moduleX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_init_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	const unsigned data_len = DEFAULT_SNAPLEN / 2;
	char mock_img[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";
	char mock_buf[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";

	/*
	 * Call the `init_module`
	 */
	assert_syscall_state(SYSCALL_FAILURE, "init_module", syscall(__NR_init_module, (void*)mock_img, data_len, (void *)mock_buf));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (uint64_t)errno_value);

	/* Parameter 2: img (type: PT_BYTEBUF) */
	evt_test->assert_bytebuf_param(2, mock_img, data_len);

	/* Parameter 3: length (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)data_len);

	/* Parameter 4: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(4, mock_buf);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

#endif
