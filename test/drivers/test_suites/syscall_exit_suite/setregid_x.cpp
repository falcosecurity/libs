#include "../../event_class/event_class.h"

#ifdef __NR_setresgid
TEST(SyscallExit, setregidX)
{
    auto evt_test = get_syscall_event_test(__NR_setregid, EXIT_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    gid_t rgid = (uint32_t)-1;
    gid_t egid = (uint32_t)-1;
    /* If one of the arguments equals -1, the corresponding value is not changed. */
    assert_syscall_state(SYSCALL_SUCCESS, "setregid", syscall(__NR_setregid, rgid, egid), NOT_EQUAL, -1);

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

    /* Parameter 1: res (type: PT_ERRNO) */
    evt_test->assert_numeric_param(1, (int64_t)0);

    /*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(1);
}
#endif
