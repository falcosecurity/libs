#include "../../event_class/event_class.h"

#ifdef __NR_mmap2

#include <sys/mman.h>

TEST(SyscallExit, mmap2X)
{
	auto evt_test = get_syscall_event_test(__NR_mmap2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	void *mock_addr = (void *)0;
	size_t mock_length = 0;
	int mock_prot = 0;
	int mock_flags = MAP_SHARED;
	int mock_fd = -1;
	off_t mock_offset = 0;

	assert_syscall_state(SYSCALL_FAILURE, "mmap", syscall(__NR_mmap2, mock_addr, mock_length, mock_prot, mock_flags, mock_fd, mock_offset));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0, GREATER_EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
