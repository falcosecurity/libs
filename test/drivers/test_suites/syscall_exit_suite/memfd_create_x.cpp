#include "../../event_class/event_class.h"

#include <sys/mman.h>

#ifdef __NR_memfd_create

TEST(SyscallExit, memfd_createX)
{
    auto evt_test = get_syscall_event_test(__NR_memfd_create, EXIT_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    const char* name = NULL;
    int flags = 0;
    assert_syscall_state(SYSCALL_FAILURE,"memfd_create",syscall(__NR_memfd_create,name,flags));

     /*=============================== TRIGGER SYSCALL ===========================*/

     evt_test->disable_capture();

     evt_test->assert_event_presence();

     if(HasFatalFailure()){
        return;
     }

     evt_test->parse_event();

     evt_test->assert_header();

    /*=============================== ASSERT PARAMETERS  ===========================*/

    /*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(3);

}

#endif