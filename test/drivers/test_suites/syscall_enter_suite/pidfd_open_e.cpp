#include "../../event_class/event_class.h"
#include <unistd.h>

#ifdef __NR_pidfd_open

TEST(SyscallEnter, pidfd_openE)
{
    auto evt_test = get_syscall_event_test(__NR_pidfd_open, ENTER_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    int pid = 0;
    int flags = 0;
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif