#include "../../event_class/event_class.h"

#ifdef __NR_openat2

#include <linux/openat2.h> /* Definition of RESOLVE_* constants */

TEST(SyscallEnter, openat2E)
{
	auto evt_test = get_syscall_event_test(__NR_openat2, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * With `O_TMPFILE` flag the pathname must be a directory
	 * but here it is a filename so the call will fail!
	 */

	int dirfd = AT_FDCWD;
	const char* pathname = "mock_path";
	struct open_how how;
	how.flags = O_RDWR | O_TMPFILE | O_DIRECTORY;
	how.mode = 0;
	how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
	assert_syscall_state(SYSCALL_FAILURE, "openat2", syscall(__NR_openat2, dirfd, pathname, &how, sizeof(struct open_how)));

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

	/* Parameter 1: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)PPM_AT_FDCWD);

	/* Parameter 2: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDWR | PPM_O_TMPFILE | PPM_O_DIRECTORY);

	/* Parameter 4: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)how.mode);

	/* Parameter 5: resolve (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(5, (uint32_t)PPM_RESOLVE_BENEATH | PPM_RESOLVE_NO_MAGICLINKS);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}
#endif
