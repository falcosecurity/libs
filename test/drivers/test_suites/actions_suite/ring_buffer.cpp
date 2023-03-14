#include "../../event_class/event_class.h"

#include <sys/types.h>
#include <sys/wait.h>

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_ioctl)
TEST(Actions, read_in_order_from_buffer)
{
	/* Here we capture all syscalls... this process will send some
	 * specific syscalls and we have to check that they are extracted in order
	 * from the buffers.
	 */
	auto evt_test = get_syscall_event_test();

	evt_test->enable_capture();

	/* 1. Generate a `close` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, -1));

	/* 2. Generate an `openat` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "openat", syscall(__NR_openat, AT_FDCWD, "mock_path", 0, 0));

	/* 3. Generate an `ioctl` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "ioctl", syscall(__NR_ioctl, -1, 0, NULL));

	/* 4. Generate an `accept4` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "accept4", syscall(__NR_accept4, -1, NULL, NULL, 0));

	/* Disable the capture: no more events from now. */
	evt_test->disable_capture();

	/* Retrieve events in order. */
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_CLOSE_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_CLOSE_X);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_OPENAT_2_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_OPENAT_2_X);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_IOCTL_3_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_IOCTL_3_X);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_ACCEPT4_6_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_ACCEPT4_6_X);
}
#endif
