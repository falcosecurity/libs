#include "../../event_class/event_class.h"

#ifdef __NR_mmap2

#include <sys/mman.h>

TEST(SyscallExit, mmap2X) {
	auto evt_test = get_syscall_event_test(__NR_mmap2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	void *mock_addr = (void *)0;
	size_t mock_length = 0;
	int mock_prot = 0;
	int mock_flags = MAP_SHARED;
	int mock_fd = -1;
	off_t mock_offset = 0;

	assert_syscall_state(SYSCALL_FAILURE,
	                     "mmap",
	                     syscall(__NR_mmap2,
	                             mock_addr,
	                             mock_length,
	                             mock_prot,
	                             mock_flags,
	                             mock_fd,
	                             mock_offset));
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 5: addr (type: PT_UINT64) */
	evt_test->assert_numeric_param(5, (uint64_t)mock_addr);

	/* Parameter 6: length (type: PT_UINT64) */
	evt_test->assert_numeric_param(6, (uint64_t)mock_length);

	/* Parameter 7: prot (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(7, (uint32_t)mock_prot);

	/* Parameter 8: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(8, (uint32_t)mock_flags);

	/* Parameter 9: fd (type: PT_FD) */
	evt_test->assert_numeric_param(9, (int64_t)mock_fd);

	/* Parameter 10: pgoffset (type: PT_UINT64) */
	evt_test->assert_numeric_param(10, (uint64_t)mock_offset);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(10);
}
#endif
