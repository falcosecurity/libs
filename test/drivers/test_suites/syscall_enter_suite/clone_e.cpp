#include "../../event_class/event_class.h"

#ifdef __NR_clone
TEST(SyscallEnter, cloneE)
{
	auto evt_test = get_syscall_event_test(__NR_clone, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* flags are invalid so the syscall will fail. */
	unsigned long clone_flags = (unsigned long)-1;
	unsigned long newsp = 0;
	int parent_tid = -1;
	int child_tid = -1;
	unsigned long tls = 0;

	/* Please note: Some systems are compiled with kernel config like `CONFIG_CLONE_BACKWARDS2`, so the order of clone params
	 * is not the same as for all architectures. `/kernel/fork.c` from kernel source tree.
	 *
	 *  #ifdef CONFIG_CLONE_BACKWARDS
	 *	SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,  	  <-- `aarch64` systems use this.
	 *			int __user *, parent_tidptr,
	 *			unsigned long, tls,
	 *			int __user *, child_tidptr)
	 *	#elif defined(CONFIG_CLONE_BACKWARDS2)
	 *	SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,      <-- `s390x` systems use this.
	 *			int __user *, parent_tidptr,
	 *			int __user *, child_tidptr,
	 *			unsigned long, tls)
	 *	#elif defined(CONFIG_CLONE_BACKWARDS3)
	 *	SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,
	 *			int, stack_size,
	 *			int __user *, parent_tidptr,
	 *			int __user *, child_tidptr,
	 *			unsigned long, tls)
	 *	#else
	 *	SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,      <-- `x86_64` systems use this.
	 *			int __user *, parent_tidptr,
	 *			int __user *, child_tidptr,
	 *			unsigned long, tls)
	 *	#endif
	 *
	 */
#ifdef __s390x__
	assert_syscall_state(SYSCALL_FAILURE, "clone", syscall(__NR_clone, newsp, clone_flags, &parent_tid, &child_tid, tls));
#elif defined(__aarch64__) || defined(__riscv)
	assert_syscall_state(SYSCALL_FAILURE, "clone", syscall(__NR_clone, clone_flags, newsp, &parent_tid, tls, &child_tid));
#else
	assert_syscall_state(SYSCALL_FAILURE, "clone", syscall(__NR_clone, clone_flags, newsp, &parent_tid, &child_tid, tls));
#endif

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

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif
