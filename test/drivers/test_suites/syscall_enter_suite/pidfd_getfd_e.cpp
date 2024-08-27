#include "../../event_class/event_class.h"

#ifdef __NR_pidfd_getfd

TEST(SyscallEnter, pidfd_getfdE)
{
    auto evt_test = get_syscall_event_test(__NR_pidfd_getfd, ENTER_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    int pidfd = 0;
    int targetfd = 0;
    int flags = 0;
    assert_syscall_state(SYSCALL_FAILURE, "pidfd_getfd", syscall(__NR_pidfd_getfd, pidfd, targetfd, flags));

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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif