#include "../../event_class/event_class.h"

#ifdef __NR_setreuid
TEST(SyscallEnter, setreuidE)
{
    auto evt_test = get_syscall_event_test(__NR_setreuid, ENTER_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    uid_t ruid = (uint32_t)-1;
    uid_t euid = (uint32_t)-1;
    /* If one of the arguments equals -1, the corresponding value is not changed. */
    assert_syscall_state(SYSCALL_SUCCESS, "setreuid", syscall(__NR_setreuid, ruid, euid), NOT_EQUAL, -1);

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

	// Here we have no parameters to assert.

    /*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(0);
}
#endif
