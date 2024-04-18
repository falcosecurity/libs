#include "../../event_class/event_class.h"

#ifdef __NR_fchownat
TEST(SyscallExit, fchownatX)
{
	auto evt_test = get_syscall_event_test(__NR_fchownat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_dirfd = -1;
	const char* pathname = "*//null";
	uint32_t uid = 0;
	uint32_t gid = 0;
	uint32_t flags = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;
	assert_syscall_state(SYSCALL_FAILURE, "fchownat", syscall(__NR_fchownat, mock_dirfd, pathname, uid, gid, flags));
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

	/* Parameter 2: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_dirfd);

	/* Parameter 3: pathname (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(3, pathname);

	/* Parameter 4: uid (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)uid);

	/* Parameter 5: gid (type: PT_UINT32) */
	evt_test->assert_numeric_param(5, (uint32_t)gid);

	/* Parameter 6: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(6, (uint32_t)(PPM_AT_SYMLINK_FOLLOW | PPM_AT_EMPTY_PATH));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif
