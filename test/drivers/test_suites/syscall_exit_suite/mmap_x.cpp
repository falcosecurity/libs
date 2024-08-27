#include "../../event_class/event_class.h"

#ifdef __NR_mmap

#include <sys/mman.h>

TEST(SyscallExit, mmapX)
{
	auto evt_test = get_syscall_event_test(__NR_mmap, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	void *mock_addr = (void *)0;
	size_t mock_length = 4096;
	int mock_prot = PROT_EXEC | PROT_READ;
	int mock_flags = MAP_SHARED;
	int mock_fd = -1;
	off_t mock_offset = 1023;

	assert_syscall_state(SYSCALL_FAILURE, "mmap", syscall(__NR_mmap, mock_addr, mock_length, mock_prot, mock_flags, mock_fd, mock_offset));
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
	evt_test->assert_only_param_len(2, sizeof(uint32_t));

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	evt_test->assert_only_param_len(3, sizeof(uint32_t));

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	evt_test->assert_only_param_len(4, sizeof(uint32_t));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
