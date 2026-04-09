#include "../../event_class/event_class.h"

#if defined(__NR_keyctl)

#include <linux/keyctl.h>

TEST(SyscallExit, keyctlX_failure) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Use an invalid operation to force a failure.
	 * The kernel returns -EOPNOTSUPP for unknown operations.
	 * Unknown operations have 0 args: all arg fields should be zero integers.
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

	/* Parameter 3: arg2 (type: PT_DYN) — 0-arg op: INT64(0) */
	evt_test->assert_keyctl_arg(3, 0);

	/* Parameter 4: arg3 (type: PT_DYN) */
	evt_test->assert_keyctl_arg(4, 0);

	/* Parameter 5: arg4 (type: PT_DYN) */
	evt_test->assert_keyctl_arg(5, 0);

	/* Parameter 6: arg5 (type: PT_DYN) */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_get_keyring_id) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_GET_KEYRING_ID has 2 args: arg2 = key_serial_t, arg3 = int create.
	 * Both captured as PT_DYN INT64.
	 */
	int operation = KEYCTL_GET_KEYRING_ID;
	long arg2 = KEY_SPEC_USER_KEYRING; /* -4 */
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

	/* Parameter 3: arg2 (type: PT_DYN) — the key serial */
	evt_test->assert_keyctl_arg(3, arg2);

	/* Parameter 4: arg3 (type: PT_DYN) — create flag */
	evt_test->assert_keyctl_arg(4, create);

	/* Parameter 5: arg4 (type: PT_DYN) — 0: only 2 args */
	evt_test->assert_keyctl_arg(5, 0);

	/* Parameter 6: arg5 (type: PT_DYN) — 0: only 2 args */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_join_session_keyring) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_JOIN_SESSION_KEYRING has 1 arg: arg2 = const char *name (string).
	 * Captured as PT_DYN CHARBUF.
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

	/* Parameter 3: arg2 (type: PT_DYN) — the keyring name string */
	evt_test->assert_keyctl_arg(3, keyring_name);

	/* Parameters 4-5: arg3/arg4 (type: PT_DYN) — 0: only 1 arg */
	evt_test->assert_keyctl_arg(4, 0);
	evt_test->assert_keyctl_arg(5, 0);

	/* Parameter 6: arg5 (type: PT_DYN) */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_describe) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_DESCRIBE has 3 args: arg2 = key_serial_t, arg3 = char *buf (out),
	 * arg4 = size_t buflen. All captured as PT_DYN INT64.
	 */
	int operation = KEYCTL_DESCRIBE;
	long arg2 = KEY_SPEC_USER_KEYRING; /* -4 */
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

	/* Parameter 3: arg2 (type: PT_DYN) — the key serial */
	evt_test->assert_keyctl_arg(3, arg2);

	/* Parameter 4: arg3 (type: PT_DYN) — output buffer pointer */
	evt_test->assert_keyctl_arg(4, (unsigned long)buf);

	/* Parameter 5: arg4 (type: PT_DYN) — buflen */
	evt_test->assert_keyctl_arg(5, buflen);

	/* Parameter 6: arg5 (type: PT_DYN) — 0: only 3 args */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_get_security) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_GET_SECURITY has 3 args: arg2 = key_serial_t, arg3 = char *buf (out),
	 * arg4 = size_t buflen. All captured as PT_DYN INT64.
	 */
	int operation = KEYCTL_GET_SECURITY;
	long arg2 = KEY_SPEC_USER_KEYRING; /* -4 */
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

	/* Parameter 3: arg2 (type: PT_DYN) — the key serial */
	evt_test->assert_keyctl_arg(3, arg2);

	/* Parameter 4: arg3 (type: PT_DYN) — output buffer pointer */
	evt_test->assert_keyctl_arg(4, (unsigned long)buf);

	/* Parameter 5: arg4 (type: PT_DYN) — buflen */
	evt_test->assert_keyctl_arg(5, buflen);

	/* Parameter 6: arg5 (type: PT_DYN) — 0: only 3 args */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_search) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_SEARCH has 4 args: arg2 = keyring (INT64), arg3 = type (CHARBUF),
	 * arg4 = description (CHARBUF), arg5 = dest_keyring (INT64).
	 * The search fails with ENOKEY since the key doesn't exist, but args
	 * are still captured.
	 */
	long arg2 = KEY_SPEC_USER_KEYRING;
	const char *type = "user";
	const char *description = "falco-test-search-key";
	long arg5 = 0;

	long ret = syscall(__NR_keyctl, KEYCTL_SEARCH, arg2, type, description, arg5);
	int64_t errno_value = (ret == -1) ? -errno : ret;

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
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_SEARCH);

	/* Parameter 3: arg2 (type: PT_DYN) — keyring serial */
	evt_test->assert_keyctl_arg(3, arg2);

	/* Parameter 4: arg3 (type: PT_DYN) — key type string */
	evt_test->assert_keyctl_arg(4, type);

	/* Parameter 5: arg4 (type: PT_DYN) — key description string */
	evt_test->assert_keyctl_arg(5, description);

	/* Parameter 6: arg5 (type: PT_DYN) — destination keyring */
	evt_test->assert_keyctl_arg(6, arg5);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_session_to_parent) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* SESSION_TO_PARENT always fails with EPERM in a multi-threaded process
	 * (GTest always has worker threads), giving a deterministic 0-arg path.
	 */
	assert_syscall_state(SYSCALL_FAILURE,
	                     "keyctl",
	                     syscall(__NR_keyctl, KEYCTL_SESSION_TO_PARENT, 0, 0, 0, 0));
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
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_SESSION_TO_PARENT);

	/* Parameters 3-5: all INT64(0) — SESSION_TO_PARENT takes no extra args */
	evt_test->assert_keyctl_arg(3, 0);
	evt_test->assert_keyctl_arg(4, 0);
	evt_test->assert_keyctl_arg(5, 0);

	/* Parameter 6: arg5 (type: PT_DYN) */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, keyctlX_pkey_query) {
	auto evt_test = get_syscall_event_test(__NR_keyctl, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* KEYCTL_PKEY_QUERY: keyctl(KEYCTL_PKEY_QUERY, key_id, 0, info, result)
	 * arg2 = key_id (INT64), arg3 = 0 reserved (INT64), arg4 = info (CHARBUF).
	 * Non-existent key serial → fails with ENOKEY deterministically; input
	 * registers are still captured by the probe at exit time.
	 */
	long key_id = 0x7fffffff;
	const char *info = "enc=pkcs1 hash=sha256";
	struct keyctl_pkey_query result = {};

	long ret = syscall(__NR_keyctl, KEYCTL_PKEY_QUERY, key_id, 0, info, &result);
	int64_t errno_value = (ret == -1) ? -errno : ret;

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
	evt_test->assert_numeric_param(2, (uint32_t)PPM_KEYCTL_PKEY_QUERY);

	/* Parameter 3: arg2 (type: PT_DYN) — the key serial */
	evt_test->assert_keyctl_arg(3, key_id);

	/* Parameter 4: arg3 (type: PT_DYN) — reserved (always 0) */
	evt_test->assert_keyctl_arg(4, 0);

	/* Parameter 5: arg4 (type: PT_DYN) — info algorithm string */
	evt_test->assert_keyctl_arg(5, info);

	/* Parameter 6: arg5 (type: PT_DYN) — result struct not captured */
	evt_test->assert_keyctl_arg(6, 0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

#endif /* __NR_keyctl */
