/* The vfork() function has the same effect as fork(), except that the
 * behavior is undefined if the process created by vfork() either modifies
 * any data other than a variable of type pid_t used to store the return
 * value from vfork(), or returns from the function in which vfork() was
 * called, or calls any other function before successfully calling _exit()
 * or one of the exec() family of functions.
 *
 * For this reason right now we are not able to call the `vfork()` without
 * a segmentation fault...
 */

// #include "../../event_class/event_class.h"

// #if defined(__NR_vfork) && defined(__NR_wait4)

// TEST(SyscallEnter, vforkE)
// {
// 	auto evt_test = get_syscall_event_test(__NR_vfork, ENTER_EVENT);

// 	evt_test->enable_capture();

// 	/*=============================== TRIGGER SYSCALL ===========================*/

// 	pid_t ret_pid = syscall(__NR_vfork);
// 	if(ret_pid == 0)
// 	{
// 		/* Child terminates immediately. */
// 		exit(EXIT_SUCCESS);
// 	}

// 	assert_syscall_state(SYSCALL_SUCCESS, "vfork", ret_pid, NOT_EQUAL, -1);
// 	int status = 0;
// 	int options = 0;
// 	assert_syscall_state(SYSCALL_SUCCESS, "wait4", syscall(__NR_wait4, ret_pid, &status, options, NULL), NOT_EQUAL, -1);

// 	/*=============================== TRIGGER SYSCALL ===========================*/

// 	evt_test->disable_capture();

// 	evt_test->assert_event_presence();

// 	if(HasFatalFailure())
// 	{
// 		return;
// 	}

// 	evt_test->parse_event();

// 	evt_test->assert_header();

// 	/*=============================== ASSERT PARAMETERS  ===========================*/

// 	// Here we have no parameters to assert.

// 	/*=============================== ASSERT PARAMETERS  ===========================*/

// 	evt_test->assert_num_params_pushed(0);
// }
// #endif
