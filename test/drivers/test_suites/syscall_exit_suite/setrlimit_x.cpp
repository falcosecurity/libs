#include "../../event_class/event_class.h"

#ifdef __NR_setrlimit

#include <sys/resource.h>

TEST(SyscallExit, setrlimitX_null_rlimit_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_setrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	// In case of `NULL` rlimit pointer we expect `cur` and `max` equal to `0`
	// The syscall will fail and a NULL pointer is equivalent to all `0`.
	int resource = RLIMIT_NOFILE;
	assert_syscall_state(SYSCALL_FAILURE, "setrlimit", syscall(__NR_setrlimit, resource, NULL));
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
	evt_test->assert_numeric_param(2, (int64_t)0);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)0);

	/* Parameter 4: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)resource);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, setrlimitX_wrong_resource)
{
	auto evt_test = get_syscall_event_test(__NR_setrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	// In case of a wrong resource we expect that `cur` and `max` are populated.
	// The syscall will fail but we will catch what the user passes in any case.
	int resource = -1;
	struct rlimit rlim;
	rlim.rlim_cur = 50;
	rlim.rlim_max = 10020;
	assert_syscall_state(SYSCALL_FAILURE, "setrlimit", syscall(__NR_setrlimit, resource, &rlim));
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
	evt_test->assert_numeric_param(2, (int64_t)rlim.rlim_cur);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)rlim.rlim_max);

	/* Parameter 4: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)resource);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, setrlimitX_success)
{
	auto evt_test = get_syscall_event_test(__NR_setrlimit, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int resource = RLIMIT_MEMLOCK;
	struct rlimit rlim;
	rlim.rlim_cur = 50;
	rlim.rlim_max = 10020;

	int ret = syscall(__NR_setrlimit, resource, &rlim);
	assert_syscall_state(SYSCALL_SUCCESS, "setrlimit", ret, NOT_EQUAL, -1);
	// On success, setrlimit return 0.

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
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/* Parameter 2: cur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)rlim.rlim_cur);

	/* Parameter 3: max (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)rlim.rlim_max);

	/* Parameter 4: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)resource);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
