#include "../../event_class/event_class.h"

#if defined(__NR_keyctl)

#include <linux/keyctl.h>

TEST(SyscallExit, keyctlX_failure) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Use an invalid operation to force a failure.
	 * The kernel returns -EOPNOTSUPP for unknown operations.
	 */
	int operation = -3;
	unsigned long arg2 = 47;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	assert_syscall_state(SYSCALL_FAILURE,
	                     "keyctl",
	                     syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: operation (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)operation);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) — empty for unsupported operations */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) — unsupported operations don't claim arg2 */
	evt_test->assert_numeric_param(4, (int64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, keyctlX_get_keyring_id) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_GET_KEYRING_ID looks up the session keyring — always works.
	 * arg2 = KEY_SPEC_SESSION_KEYRING (-3), an integer key serial.
	 * Falls into the default (integer) branch: arg2_str empty, arg2_int = arg2.
	 */
	int operation = KEYCTL_GET_KEYRING_ID;
	long arg2 = KEY_SPEC_SESSION_KEYRING; /* -3 */
	int create = 0;

	long ret = syscall(__NR_keyctl, operation, arg2, create, 0, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "keyctl", ret, NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/* Parameter 2: operation (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_GET_KEYRING_ID);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) — empty, arg2 is an integer */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) */
	evt_test->assert_numeric_param(4, (int64_t)arg2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, keyctlX_join_session_keyring) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_JOIN_SESSION_KEYRING with a name: arg2 is a char* keyring name.
	 * Falls into the string branch: arg2_str = name, arg2_int = 0.
	 */
	int operation = KEYCTL_JOIN_SESSION_KEYRING;
	const char *keyring_name = "falco-test-keyring";

	long ret = syscall(__NR_keyctl, operation, keyring_name, 0, 0, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "keyctl", ret, NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/* Parameter 2: operation (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_JOIN_SESSION_KEYRING);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) — the keyring name */
	evt_test->assert_charbuf_param(3, keyring_name);

	/* Parameter 4: arg2_int (type: PT_INT64) — 0 for string branch */
	evt_test->assert_numeric_param(4, (int64_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, keyctlX_describe) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_DESCRIBE: arg2 = key_serial_t (integer key ID), arg3 = output buffer.
	 * arg2 must be captured as an integer (default branch), NOT as a string.
	 * Regression test for the review finding that DESCRIBE was incorrectly grouped
	 * with JOIN_SESSION_KEYRING in the string branch.
	 */
	int operation = KEYCTL_DESCRIBE;
	long arg2 = KEY_SPEC_SESSION_KEYRING; /* -3, an integer key serial */
	char buf[256] = {};
	unsigned long buflen = sizeof(buf);

	long ret = syscall(__NR_keyctl, operation, arg2, buf, buflen, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "keyctl", ret, NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/* Parameter 2: operation (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_DESCRIBE);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) — must be EMPTY: arg2 is a key serial, not a string
	 */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) — the key serial */
	evt_test->assert_numeric_param(4, (int64_t)arg2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

TEST(SyscallExit, keyctlX_get_security) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_GET_SECURITY: arg2 = key_serial_t (integer key ID), arg3 = output buffer.
	 * arg2 must be captured as an integer (default branch), NOT as a string.
	 * Regression test for the review finding that GET_SECURITY was incorrectly grouped
	 * with JOIN_SESSION_KEYRING in the string branch.
	 */
	int operation = KEYCTL_GET_SECURITY;
	long arg2 = KEY_SPEC_SESSION_KEYRING; /* -3, an integer key serial */
	char buf[256] = {};
	unsigned long buflen = sizeof(buf);

	long ret = syscall(__NR_keyctl, operation, arg2, buf, buflen, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "keyctl", ret, NOT_EQUAL, -1);

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)ret);

	/* Parameter 2: operation (type: PT_ENUMFLAGS32) */
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_GET_SECURITY);

	/* Parameter 3: arg2_str (type: PT_CHARBUF) — must be EMPTY: arg2 is a key serial, not a string
	 */
	evt_test->assert_empty_param(3);

	/* Parameter 4: arg2_int (type: PT_INT64) — the key serial */
	evt_test->assert_numeric_param(4, (int64_t)arg2);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

#endif /* __NR_keyctl */
