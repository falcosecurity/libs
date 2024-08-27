#include "../../event_class/event_class.h"

#ifdef __NR_pidfd_getfd

TEST(SyscallExit, pidfd_getfdX)
{
    auto evt_test = get_syscall_event_test(__NR_pidfd_getfd, EXIT_EVENT);

    evt_test->enable_capture();
    

    /*=============================== TRIGGER SYSCALL ===========================*/

    int pid_fd = -1;
    int target_fd = -1;
    uint32_t flags = 1;
    int64_t errno_value = -EINVAL;

    /*
      The syscall should fail when flag is not equal to zero
      See https://elixir.bootlin.com/linux/latest/source/kernel/pid.c#L731
    */

    assert_syscall_state(SYSCALL_FAILURE, "pidfd_getfd", syscall(__NR_pidfd_getfd, pid_fd, target_fd, flags));

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

     /* Parameter 2: pidfd (type: PT_FD)*/
     evt_test->assert_numeric_param(2, (int64_t)pid_fd);

     /* Parameter 3: targetfd (type: PT_FD)*/
     evt_test->assert_numeric_param(3, (int64_t)target_fd);

     /* Parameter 4: flags (type: PT_FLAGS32)*/
     evt_test->assert_numeric_param(4, flags);

	/*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(4);

}
#endif