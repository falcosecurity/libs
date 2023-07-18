#include "../../event_class/event_class.h"

#include <unistd.h>


#ifdef __NR_pidfd_open

#ifdef __NR_fork
TEST(SyscallExit, pidfd_openX_success)
{
    auto evt_test = get_syscall_event_test(__NR_pidfd_open, EXIT_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/
    /*
      PIDFD_NONBLOCK is available only on kernal versions > 5.10.0. No other flags are supported
      See https://elixir.bootlin.com/linux/v5.10.185/source/include/uapi/linux/pidfd.h#L10
    */
    
    int flags = 0;
    pid_t pid = syscall(__NR_fork);
    if(pid == 0)
    { 
        exit(EXIT_SUCCESS);
    }
    assert_syscall_state(SYSCALL_SUCCESS, "fork", pid, NOT_EQUAL, -1);

    int pidfd = syscall(__NR_pidfd_open, pid, flags);
    assert_syscall_state(SYSCALL_SUCCESS, "pidfd_open", pidfd, NOT_EQUAL, -1);
    syscall(__NR_close);

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

    /* Parameter 1: ret (type: PT_FD)*/
    evt_test->assert_numeric_param(1, (int64_t)pidfd);

    /* Parameter 2: pid (type: PT_PID)*/
    evt_test->assert_numeric_param(2, (int64_t)pid);

    /* Parameter 3: flags (type: PT_FLAGS32) */
    evt_test->assert_numeric_param(3, (uint32_t)0);

    /*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(3);
}
#endif

TEST(SyscallExit, pidfd_openX_failure)
{
    auto evt_test = get_syscall_event_test(__NR_pidfd_open, EXIT_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    int flags = O_NONBLOCK;
#ifdef PIDFD_NONBLOCK
    flags = PIDFD_NONBLOCK;
#endif
    pid_t pid = 0;
    int64_t errno_value = -EINVAL;
    assert_syscall_state(SYSCALL_FAILURE, "pidfd_open", syscall(__NR_pidfd_open, pid, flags));

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

    /* Parameter 1: ret (type: PT_FD)*/
    evt_test->assert_numeric_param(1, (int64_t)errno_value);

    /* Parameter 2: pid (type: PT_PID)*/
    evt_test->assert_numeric_param(2, (int64_t)pid);

    /* Parameter 3: flags (type: PT_FLAGS32) */ 
    evt_test->assert_numeric_param(3, (uint32_t)PPM_PIDFD_NONBLOCK);

    /*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(3);
}
#endif
