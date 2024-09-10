#include "../../event_class/event_class.h"

#if defined(__NR_prlimit64) && defined(__NR_getrlimit)

#include <sys/resource.h>

TEST(SyscallExit, prlimit64X_success) {
	auto evt_test = get_syscall_event_test(__NR_prlimit64, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* Take the old limits for two reasons:
	 * 1. Assert them against `prlimit64` old limits.
	 * 2. Set them as new limits so nothing will change.
	 */
	struct rlimit file_rlimit;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "getrlimit",
	                     syscall(__NR_getrlimit, RLIMIT_NOFILE, &file_rlimit),
	                     NOT_EQUAL,
	                     -1);

	struct rlimit old_rlimit;
	struct rlimit new_rlimit;
	new_rlimit.rlim_cur = file_rlimit.rlim_cur;
	new_rlimit.rlim_max = file_rlimit.rlim_max;
	pid_t pid = ::getpid();
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "prlimit64",
	                     syscall(__NR_prlimit64, pid, RLIMIT_NOFILE, &new_rlimit, &old_rlimit),
	                     NOT_EQUAL,
	                     -1);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: newcur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)file_rlimit.rlim_cur);

	/* Parameter 3: newmax (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)file_rlimit.rlim_max);

	/* Parameter 4: oldcur (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)file_rlimit.rlim_cur);

	/* Parameter 5: oldmax (type: PT_INT64) */
	evt_test->assert_numeric_param(5, (int64_t)file_rlimit.rlim_max);

	/* Parameter 6: pid (type: PT_INT64) */
	evt_test->assert_numeric_param(6, (int64_t)pid);

	/* Parameter 7: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(7, (uint8_t)PPM_RLIMIT_NOFILE);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}

TEST(SyscallExit, prlimit64X_failure) {
	auto evt_test = get_syscall_event_test(__NR_prlimit64, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	pid_t pid = -1;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "prlimit64",
	                     syscall(__NR_prlimit64, pid, RLIMIT_RSS, NULL, NULL));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, errno_value);

	// The new limits are set by the user so we always read what the user sets

	/* Parameter 2: newcur (type: PT_INT64) */
	evt_test->assert_numeric_param(2, (int64_t)0);

	/* Parameter 3: newmax (type: PT_INT64) */
	evt_test->assert_numeric_param(3, (int64_t)0);

	// The old limits are read by the kernel so when the syscall fails we return `-1`

	/* Parameter 4: oldcur (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)-1);

	/* Parameter 5: oldmax (type: PT_INT64) */
	evt_test->assert_numeric_param(5, (int64_t)-1);

	/* Parameter 6: pid (type: PT_INT64) */
	evt_test->assert_numeric_param(6, (int64_t)pid);

	/* Parameter 7: resource (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(7, (uint8_t)PPM_RLIMIT_RSS);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(7);
}
#endif
