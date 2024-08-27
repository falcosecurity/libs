#include "../../event_class/event_class.h"

#if defined(__NR_unshare)
TEST(Actions, sampling_ratio_UF_ALWAYS_DROP)
{
	/* Here we set just one `UF_ALWAYS_DROP` syscall as interesting... this process will send
	 * only this specific syscall and we have to check that the corresponding event is dropped when
	 * the sampling logic is enabled and not dropped when the logic is disabled.
	 */
	auto evt_test = get_syscall_event_test(__NR_unshare, ENTER_EVENT);

	/* We are not sampling, we are just removing the `UF_ALWAYS_DROP` events */
	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* Call the `UF_ALWAYS_DROP` syscall */
	syscall(__NR_unshare, 0);

	evt_test->assert_event_absence();

	evt_test->disable_sampling_logic();

	/* Call again the `UF_ALWAYS_DROP` syscall */
	syscall(__NR_unshare, 0);

	/* This time we should be able to find the event */
	evt_test->assert_event_presence();

	evt_test->disable_capture();
}
#endif

#if defined(__NR_eventfd) && defined(__NR_close)
TEST(Actions, sampling_ratio_UF_NEVER_DROP)
{
	/* Here we set just one `UF_NEVER_DROP` syscall as interesting... this process will send
	 * only this specific syscall and we have to check that the corresponding event is
	 * not dropped when the sampling logic is enabled.
	 */
	auto evt_test = get_syscall_event_test(__NR_eventfd, ENTER_EVENT);

	evt_test->enable_capture();

	/* Even sampling with the maximum frequency we shouldn't drop `UF_NEVER_DROP` events */
	evt_test->enable_sampling_logic(128);

	/* Call the `UF_NEVER_DROP` syscall */
	int32_t fd = syscall(__NR_eventfd, 3);
	syscall(__NR_close, fd);

	/* We should find the event */
	evt_test->assert_event_presence();

	evt_test->disable_sampling_logic();

	evt_test->disable_capture();
}
#endif

#if defined(__NR_capset)
TEST(Actions, sampling_ratio_NO_FLAGS)
{
	/* Here we set just one syscall with no flags (UF_ALWAYS_DROP/UF_NEVER_DROP)
	 * as interesting... this process will send only this specific syscall and
	 * we have to check that the corresponding event is not dropped when the
	 * sampling logic is enabled with ratio==1.
	 */
	auto evt_test = get_syscall_event_test(__NR_capset, ENTER_EVENT);

	/* With sampling==1 we shouldn't drop events without flags */
	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* Call the syscall */
	syscall(__NR_capset, NULL, NULL);

	/* We should find the event */
	evt_test->assert_event_presence();

	evt_test->disable_sampling_logic();

	evt_test->disable_capture();
}
#endif

#ifdef __NR_fcntl
#include <fcntl.h>
TEST(Actions, sampling_ratio_dropping_FCNTL_E)
{
	auto evt_test = get_syscall_event_test(__NR_fcntl, ENTER_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* If called with `F_DUPFD_CLOEXEC` flag the fcntl event shouldn't be dropped by the dropping logic */
	int32_t invalid_fd = -1;
	int cmd = F_DUPFD_CLOEXEC;
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

	evt_test->assert_event_presence();

	/* This fcntl event should be dropped now since the flag is `F_NOTIFY` */
	cmd = F_NOTIFY;
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

	evt_test->assert_event_absence();

	evt_test->disable_sampling_logic();

	/* Now that the sampling logic is disabled we should catch the event */
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}

TEST(Actions, sampling_ratio_dropping_FCNTL_X)
{
	auto evt_test = get_syscall_event_test(__NR_fcntl, EXIT_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* If called with `F_DUPFD_CLOEXEC` flag the fcntl event shouldn't be dropped by the dropping logic */
	int32_t invalid_fd = -1;
	int cmd = F_DUPFD_CLOEXEC;
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

	evt_test->assert_event_presence();

	/* This fcntl event should be dropped now since the flag is `F_NOTIFY` */
	cmd = F_NOTIFY;
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

	evt_test->assert_event_absence();

	evt_test->disable_sampling_logic();

	/* Now that the sampling logic is disabled we should catch the event */
	assert_syscall_state(SYSCALL_FAILURE, "fcntl", syscall(__NR_fcntl, invalid_fd, cmd));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}
#endif

#if defined(__NR_close) && defined(__NR_socket)
TEST(Actions, sampling_ratio_dropping_CLOSE_E_invalid_fd)
{
	auto evt_test = get_syscall_event_test(__NR_close, ENTER_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* If called an invalid `fd` the close enter event should be dropped */
	int32_t invalid_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, invalid_fd));

	evt_test->disable_sampling_logic();

	evt_test->assert_event_absence();

	/* Now that the sampling logic is disabled we should catch the event */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, invalid_fd));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}

TEST(Actions, sampling_ratio_dropping_CLOSE_E_max_fds)
{
	auto evt_test = get_syscall_event_test(__NR_close, ENTER_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, 8192));

	evt_test->disable_sampling_logic();

	evt_test->assert_event_absence();

	// /* Now that the sampling logic is disabled we should be able to collect this event */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, 8192));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}

TEST(Actions, sampling_ratio_dropping_CLOSE_E_already_closed_fd)
{
	auto evt_test = get_syscall_event_test(__NR_close, ENTER_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	int socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket", socket_fd, NOT_EQUAL, -1);

	/* This close event should be catched since it is called on an existing socket */
	assert_syscall_state(SYSCALL_SUCCESS, "close", syscall(__NR_close, socket_fd), NOT_EQUAL, -1);

	evt_test->assert_event_presence();

	/* Now we call again the close on the already close fd and we shouldn't be able to catch the close enter event */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, socket_fd));

	evt_test->disable_sampling_logic();

	evt_test->assert_event_absence();

	/* Now that the sampling logic is disabled we should be able to collect this event */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, socket_fd));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}

TEST(Actions, sampling_ratio_dropping_CLOSE_X)
{
	auto evt_test = get_syscall_event_test(__NR_close, EXIT_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* If the syscall fails the close exit event should be dropped */
	int32_t invalid_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, invalid_fd));

	evt_test->disable_sampling_logic();

	evt_test->assert_event_absence();

	/* Now that the sampling logic is disabled we should catch the event */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, invalid_fd));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}
#endif

#ifdef __NR_bind
TEST(Actions, sampling_ratio_dropping_BIND_X)
{
	auto evt_test = get_syscall_event_test(__NR_bind, EXIT_EVENT);

	evt_test->enable_sampling_logic(1);

	evt_test->enable_capture();

	/* If the syscall fails the bind exit event should be dropped */
	int32_t invalid_fd = -1;
	assert_syscall_state(SYSCALL_FAILURE, "bind", syscall(__NR_bind, invalid_fd, NULL, 0));

	evt_test->disable_sampling_logic();

	evt_test->assert_event_absence();

	/* Now that the sampling logic is disabled we should catch the event */
	assert_syscall_state(SYSCALL_FAILURE, "bind", syscall(__NR_bind, invalid_fd, NULL, 0));

	evt_test->assert_event_presence();

	evt_test->disable_capture();
}
#endif

TEST(Actions, sampling_ratio_check_DROP_E_DROP_X)
{
	/* Enable all syscalls */
	auto evt_test = get_syscall_event_test();

	evt_test->enable_sampling_logic(128);

	evt_test->enable_capture();

	uint32_t max_events_to_process = 50000;
	uint32_t events_processed = 0;
	uint16_t cpu_id = 0;
	bool drop_e = false;
	bool drop_x = false;
	struct ppm_evt_hdr* evt = NULL;

	while(events_processed < max_events_to_process)
	{
		evt = evt_test->get_event_from_ringbuffer(&cpu_id);
		events_processed++;
		if(evt != NULL)
		{
			if(evt->type == PPME_DROP_E)
			{
				drop_e = true;
			}

			if(evt->type == PPME_DROP_X)
			{
				drop_x = true;
			}

			if(drop_e && drop_x)
			{
				break;
			}
		}
	}

	if(events_processed >= max_events_to_process)
	{
		FAIL() << "Found 'drop_e' = " << drop_e << ", found 'drop_x' = " << drop_x << std::endl;
	}

	evt_test->disable_sampling_logic();

	evt_test->disable_capture();
}
