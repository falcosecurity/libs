#include "../../event_class/event_class.h"

#ifdef __NR_semop

#include <sys/sem.h>

TEST(SyscallExit, semopX_null_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_semop, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int semid = -1;
	struct sembuf *sops = NULL;
	size_t nsops = 12;
	assert_syscall_state(SYSCALL_FAILURE, "semop", syscall(__NR_semop, semid, sops, nsops));
	int64_t errno_value = -errno;

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: nsops (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)nsops);

	/* Parameter 3: sem_num_0 (type: PT_UINT16) */
	evt_test->assert_numeric_param(3, (uint16_t)0);

	/* Parameter 4: sem_op_0 (type: PT_INT16) */
	evt_test->assert_numeric_param(4, (int16_t)0);

	/* Parameter 5: sem_flg_0 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(5, (uint16_t)0);

	/* Parameter 6: sem_num_1 (type: PT_UINT16) */
	evt_test->assert_numeric_param(6, (uint16_t)0);

	/* Parameter 7: sem_op_1 (type: PT_INT16) */
	evt_test->assert_numeric_param(7, (int16_t)0);

	/* Parameter 8: sem_flg_1 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(8, (uint16_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);
}

#if defined(__NR_semget) && defined(__NR_semctl)

/* This case was not managed correctly by old drivers, if we don't check for the syscall return value
 * there is the risk to send junk data to userspace when `nops` is wrong.
 */
TEST(SyscallExit, semopX_wrong_nops)
{
	auto evt_test = get_syscall_event_test(__NR_semop, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create a semaphore set with 1 semaphore */
	key_t key = 29; /* Random number */
	int semid = syscall(__NR_semget, key, 1, 0666 | IPC_CREAT);
	assert_syscall_state(SYSCALL_SUCCESS, "semget", semid, NOT_EQUAL, -1);

	struct sembuf sops = {};
	sops.sem_num = 0;
	sops.sem_op = 3;
	sops.sem_flg = SEM_UNDO;
	/* Here we have just one `ops` but we are trying to read a huge number, if we don't check
	 * the syscall failure in the kernel there is the risk to read junk data.
	 */
	size_t nsops = (size_t)-1;
	assert_syscall_state(SYSCALL_FAILURE, "semop", syscall(__NR_semop, semid, &sops, nsops));
	int64_t errno_value = -errno;

	/* Close a semaphore */
	syscall(__NR_semctl, semid, 0, IPC_RMID);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: nsops (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)nsops);

	/* Parameter 3: sem_num_0 (type: PT_UINT16) */
	evt_test->assert_numeric_param(3, (uint16_t)0);

	/* Parameter 4: sem_op_0 (type: PT_INT16) */
	evt_test->assert_numeric_param(4, (int16_t)0);

	/* Parameter 5: sem_flg_0 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(5, (uint16_t)0);

	/* Parameter 6: sem_num_1 (type: PT_UINT16) */
	evt_test->assert_numeric_param(6, (uint16_t)0);

	/* Parameter 7: sem_op_1 (type: PT_INT16) */
	evt_test->assert_numeric_param(7, (int16_t)0);

	/* Parameter 8: sem_flg_1 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(8, (uint16_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);
}

TEST(SyscallExit, semopX_1_operation)
{
	auto evt_test = get_syscall_event_test(__NR_semop, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create a semaphore set with 1 semaphore: */
	key_t key = 28; /* Random number */
	int semid = syscall(__NR_semget, key, 1, 0666 | IPC_CREAT);
	assert_syscall_state(SYSCALL_SUCCESS, "semget", semid, NOT_EQUAL, -1);

	struct sembuf sops = {};
	sops.sem_num = 0;
	sops.sem_op = 3;
	sops.sem_flg = SEM_UNDO;
	size_t nsops = 1;
	assert_syscall_state(SYSCALL_SUCCESS, "semop", syscall(__NR_semop, semid, &sops, nsops), NOT_EQUAL, -1);

	/* Close a semaphore */
	syscall(__NR_semctl, semid, 0, IPC_RMID);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: nsops (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)nsops);

	/* Parameter 3: sem_num_0 (type: PT_UINT16) */
	evt_test->assert_numeric_param(3, (uint16_t)sops.sem_num);

	/* Parameter 4: sem_op_0 (type: PT_INT16) */
	evt_test->assert_numeric_param(4, (int16_t)sops.sem_op);

	/* Parameter 5: sem_flg_0 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(5, (uint16_t)PPM_SEM_UNDO);

	/* We use just one option so the second one will be empty */

	/* Parameter 6: sem_num_1 (type: PT_UINT16) */
	evt_test->assert_numeric_param(6, (uint16_t)0);

	/* Parameter 7: sem_op_1 (type: PT_INT16) */
	evt_test->assert_numeric_param(7, (int16_t)0);

	/* Parameter 8: sem_flg_1 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(8, (uint16_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);
}

TEST(SyscallExit, semopX_2_operation)
{
	auto evt_test = get_syscall_event_test(__NR_semop, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Create a semaphore set with 1 semaphore */
	key_t key = 29; /* Random number */
	int semid = syscall(__NR_semget, key, 2, 0666 | IPC_CREAT);
	assert_syscall_state(SYSCALL_SUCCESS, "semget", semid, NOT_EQUAL, -1);

	struct sembuf sops[2] = {};
	sops[0].sem_num = 0;
	sops[0].sem_op = 3;
	sops[0].sem_flg = SEM_UNDO;
	sops[1].sem_num = 1;
	sops[1].sem_op = 7;
	sops[1].sem_flg = IPC_NOWAIT;
	size_t nsops = 2;
	assert_syscall_state(SYSCALL_SUCCESS, "semop", syscall(__NR_semop, semid, sops, nsops), NOT_EQUAL, -1);

	/* Close a semaphore */
	syscall(__NR_semctl, semid, 0, IPC_RMID);

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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: nsops (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)nsops);

	/* Parameter 3: sem_num_0 (type: PT_UINT16) */
	evt_test->assert_numeric_param(3, (uint16_t)sops[0].sem_num);

	/* Parameter 4: sem_op_0 (type: PT_INT16) */
	evt_test->assert_numeric_param(4, (int16_t)sops[0].sem_op);

	/* Parameter 5: sem_flg_0 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(5, (uint16_t)PPM_SEM_UNDO);

	/* Parameter 6: sem_num_1 (type: PT_UINT16) */
	evt_test->assert_numeric_param(6, (uint16_t)sops[1].sem_num);

	/* Parameter 7: sem_op_1 (type: PT_INT16) */
	evt_test->assert_numeric_param(7, (int16_t)sops[1].sem_op);

	/* Parameter 8: sem_flg_1 (type: PT_FLAGS16) */
	evt_test->assert_numeric_param(8, (uint16_t)PPM_IPC_NOWAIT);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);
}

#endif

#endif
