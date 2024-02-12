#include "../../event_class/event_class.h"

#include <sys/mman.h>

#if defined(__NR_memfd_create) && defined(MFD_ALLOW_SEALING)

TEST(SyscallExit, memfd_createX_success)
{
    auto evt_test = get_syscall_event_test(__NR_memfd_create, EXIT_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    const char* fileName = "test";
    int flags = MFD_ALLOW_SEALING | MFD_CLOEXEC;
    int fd = syscall(__NR_memfd_create, fileName, flags);
    assert_syscall_state(SYSCALL_SUCCESS, "memfd_create", fd, NOT_EQUAL, -1);
    close(fd);

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
    evt_test->assert_numeric_param(1, (int64_t)fd);

    /* Parameter 2: name (type: PT_CHARBUF) */
    evt_test->assert_charbuf_param(2, fileName);

    /* Parameter 3: flags (type: PT_FLAGS32) */
    evt_test->assert_numeric_param(3, (uint32_t)PPM_MFD_ALLOW_SEALING | PPM_MFD_CLOEXEC);

    /*=============================== ASSERT PARAMETERS  ===========================*/    

    evt_test->assert_num_params_pushed(3);
}


TEST(SyscallExit, memfd_createX_failure)
{
    auto evt_test = get_syscall_event_test(__NR_memfd_create, EXIT_EVENT);

    evt_test->enable_capture();

    /*=============================== TRIGGER SYSCALL ===========================*/

    const char* name = "test";
    int flags = -1;
    assert_syscall_state(SYSCALL_FAILURE, "memfd_create",syscall(__NR_memfd_create,name,flags));
    int64_t errno_value = -errno;

     /*=============================== TRIGGER SYSCALL ===========================*/

     evt_test->disable_capture();

     evt_test->assert_event_presence();

     if(HasFatalFailure()){
        return;
     }

     evt_test->parse_event();

     evt_test->assert_header();

    /*=============================== ASSERT PARAMETERS  ===========================*/

     /* Parameter 1: ret (type: PT_FD)*/
    evt_test->assert_numeric_param(1, (int64_t)errno_value);

    /* Parameter 2: name (type: PT_CHARBUF) */
    evt_test->assert_charbuf_param(2, name);

    /* Parameter 3: flags (type: PT_FLAGS32) */
    evt_test->assert_numeric_param(3, (uint32_t)PPM_MFD_ALLOW_SEALING | PPM_MFD_CLOEXEC | PPM_MFD_HUGETLB);


    /*=============================== ASSERT PARAMETERS  ===========================*/

    evt_test->assert_num_params_pushed(3);

}

#endif
