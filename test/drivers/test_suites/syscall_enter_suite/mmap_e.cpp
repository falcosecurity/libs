#include "../../event_class/event_class.h"

#ifdef __NR_mmap

#include <sys/mman.h>

TEST(SyscallEnter, mmapE)
{
	auto evt_test = get_syscall_event_test(__NR_mmap, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	void *mock_addr = NULL;
	size_t mock_length = 1024;
	int mock_prot = PROT_EXEC | PROT_READ;
	int mock_flags = MAP_SHARED;
	int mock_fd = 3;
	off_t mock_offset = 1023;

	assert_syscall_state(SYSCALL_FAILURE, "mmap", syscall(__NR_mmap, mock_addr, mock_length, mock_prot, mock_flags, mock_fd, mock_offset));

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

	/* Parameter 1: addr (type: PT_UINT64) */
	evt_test->assert_only_param_len(1, sizeof(uint64_t));

	/* Parameter 2: length (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)mock_length);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)mock_prot);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (uint32_t)mock_flags);

	/* Parameter 5: fd (type: PT_FD) */
	evt_test->assert_numeric_param(5, (uint64_t)mock_fd);
	
	/* Parameter 6: offset/pgprot (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, (uint64_t)mock_offset);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}
#endif
