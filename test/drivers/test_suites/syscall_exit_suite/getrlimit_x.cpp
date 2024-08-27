#include "../../event_class/event_class.h"

#ifdef __NR_getrlimit

#include <sys/resource.h>

TEST(SyscallExit, getrlimitX_success)
{
	auto evt_test = get_syscall_event_test(__NR_getrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int resource = RLIMIT_NPROC;
	struct rlimit rlim = {};
	assert_syscall_state(SYSCALL_SUCCESS, "getrlimit", syscall(__NR_getrlimit, resource, &rlim), NOT_EQUAL, -1);

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
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: cur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)rlim.rlim_cur);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)rlim.rlim_max);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, getrlimitX_wrong_resource)
{
	auto evt_test = get_syscall_event_test(__NR_getrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int resource = -1;
	struct rlimit rlim = {};
	assert_syscall_state(SYSCALL_FAILURE, "getrlimit", syscall(__NR_getrlimit, resource, &rlim));
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

	// The syscall fails so we expect `-1`

	/* Parameter 2: cur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)-1);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)-1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, getrlimitX_null_rlimit_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_getrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int resource = RLIMIT_NOFILE;
	assert_syscall_state(SYSCALL_FAILURE, "getrlimit", syscall(__NR_getrlimit, resource, NULL));
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

	/* Parameter 2: cur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)-1);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)-1);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
