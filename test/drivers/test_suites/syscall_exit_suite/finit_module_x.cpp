#include "../../event_class/event_class.h"

#if defined(__NR_finit_module)
#include <linux/module.h>

TEST(SyscallExit, finit_moduleX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_finit_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char mock_buf[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";
	int flags = 3;

	/*
	 * Call the `finit_module`
	 */

	int64_t kmod_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "finit_module", syscall(__NR_finit_module, kmod_fd, (void*)mock_buf, flags));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)kmod_fd);

	/* Parameter 3: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(3, mock_buf);

	/* Parameter 4: flags (type: PT_INT32) */
	evt_test->assert_numeric_param(4, flags);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

#ifdef MODULE_INIT_IGNORE_MODVERSIONS
TEST(SyscallExit, finit_moduleX_failure_IGNORE_MODVERSIONS)
{
	auto evt_test = get_syscall_event_test(__NR_finit_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char mock_buf[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";
	int flags = MODULE_INIT_IGNORE_MODVERSIONS;

	/*
	 * Call the `finit_module`
	 */

	int64_t kmod_fd = 99;
	assert_syscall_state(SYSCALL_FAILURE, "finit_module", syscall(__NR_finit_module, kmod_fd, (void*)mock_buf, flags));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)kmod_fd);

	/* Parameter 3: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(3, mock_buf);

	/* Parameter 4: flags (type: PT_INT32) */
	evt_test->assert_numeric_param(4, PPM_MODULE_INIT_IGNORE_MODVERSIONS);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

#ifdef MODULE_INIT_IGNORE_VERMAGIC
TEST(SyscallExit, finit_moduleX_failure_IGNORE_VERMAGIC)
{
	auto evt_test = get_syscall_event_test(__NR_finit_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char mock_buf[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";
	int flags = MODULE_INIT_IGNORE_VERMAGIC;

	/*
	 * Call the `finit_module`
	 */

	int64_t kmod_fd = 99;
	assert_syscall_state(SYSCALL_FAILURE, "finit_module", syscall(__NR_finit_module, kmod_fd, (void*)mock_buf, flags));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)kmod_fd);

	/* Parameter 3: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(3, mock_buf);

	/* Parameter 4: flags (type: PT_INT32) */
	evt_test->assert_numeric_param(4, MODULE_INIT_IGNORE_VERMAGIC);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

#ifdef MODULE_INIT_COMPRESSED_FILE
TEST(SyscallExit, finit_moduleX_failure_COMPRESSED_FILE)
{
	auto evt_test = get_syscall_event_test(__NR_finit_module, EXIT_EVENT);
	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char mock_buf[] = "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAA\0";
	int flags = MODULE_INIT_COMPRESSED_FILE;

	/*
	 * Call the `finit_module`
	 */

	int64_t kmod_fd = 99;
	assert_syscall_state(SYSCALL_FAILURE, "finit_module", syscall(__NR_finit_module, kmod_fd, (void*)mock_buf, flags));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)kmod_fd);

	/* Parameter 3: uargs (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(3, mock_buf);

	/* Parameter 4: flags (type: PT_INT32) */
	evt_test->assert_numeric_param(4, PPM_MODULE_INIT_COMPRESSED_FILE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif

#endif
