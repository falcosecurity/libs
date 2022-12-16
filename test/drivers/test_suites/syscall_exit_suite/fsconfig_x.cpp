#include "../../event_class/event_class.h"

#if defined(__NR_fsconfig) && defined(__NR_fspick)
#include <linux/mount.h>

TEST(SyscallExit, fsconfigX_FSCONFIG_SET_STRING)
{
	auto evt_test = get_syscall_event_test(__NR_fsconfig, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int fd = syscall(__NR_fspick, AT_FDCWD, "/sys/kernel/tracing", 0);
	assert_syscall_state(SYSCALL_SUCCESS, "fspick", fd, NOT_EQUAL, -1);

	uint32_t cmd = FSCONFIG_SET_STRING;
	const char* key = "source";
	const char* value = "#grand.central.org:root.cell.";
	int aux = 0;
	int ret = syscall(__NR_fsconfig, fd, cmd, key, value, aux);
	assert_syscall_state(SYSCALL_SUCCESS, "fsconfig", ret, NOT_EQUAL, -1);

	syscall(__NR_close, fd);

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

	/* Parameter 1: ret (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)fd);

	/* Parameter 3: cmd (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(3, PPM_FSCONFIG_SET_STRING);

	/* Parameter 4: key (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(4, key);

	/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(6, value);

	/* Parameter 7: aux (type: PT_INT32) */
	evt_test->assert_numeric_param(7, (int32_t)aux);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}

TEST(SyscallExit, fsconfigX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_fsconfig, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int fd = 0;
	uint32_t cmd = FSCONFIG_SET_FLAG;
	const char* key = "//**invalid-key**//";
	const char* value = "//**invalid-value**//";
	int aux = 100;
	assert_syscall_state(SYSCALL_FAILURE, "fsconfig", syscall(__NR_fsconfig, fd, cmd, key, value, aux));
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

	/* Parameter 1: ret (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)fd);

	/* Parameter 3: cmd (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(3, PPM_FSCONFIG_SET_FLAG);

	/* Parameter 4: key (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(4, key);

	/* Parameter 5: value_bytebuf (type: PT_BYTEBUF) */
	evt_test->assert_empty_param(5);

	/* Parameter 6: value_charbuf (type: PT_CHARBUF) */
	evt_test->assert_empty_param(6);

	/* Parameter 7: aux (type: PT_INT32) */
	evt_test->assert_numeric_param(7, (int32_t)aux);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}
#endif
