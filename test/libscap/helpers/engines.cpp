#include <gtest/gtest.h>
#include <syscall.h>
#include <scap.h>

/* We are supposing that if we overcome this threshold, all buffers are full.
 * Probably this threshold is too low, but it depends on the machine's workload.
 * We are running in CI so it is better to be conservative even if tests becomes
 * not so reliable...
 */
#define MAX_ITERATIONS 300

/* Number of events we want to assert */
#define EVENTS_TO_ASSERT 32

void check_event_is_not_overwritten(scap_t* h)
{
	/* Start the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS) << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	/* When the number of events is fixed for `MAX_ITERATIONS` we consider all the buffers full, this is just an approximation */
	scap_stats stats = {};
	uint64_t last_num_events = 0;
	uint16_t iterations = 0;

	while(iterations < MAX_ITERATIONS || stats.n_drops == 0)
	{
		ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS) << "unable to get stats: " << scap_getlasterr(h) << std::endl;
		if(last_num_events == (stats.n_evts - stats.n_drops))
		{
			iterations++;
		}
		else
		{
			iterations = 0;
			last_num_events = (stats.n_evts - stats.n_drops);
		}
	}

	/* Stop the capture */
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS) << "unable to stop the capture: " << scap_getlasterr(h) << std::endl;

	/* The idea here is to check if an event is overwritten while we still have a pointer to it.
	 * Again this is only an approximation, we don't know if new events will be written in the buffer
	 * under test...
	 *
	 * We call `scap_next` keeping the pointer to the event.
	 * An event pointer becomes invalid when we call another `scap_next`, but until that moment it should be valid!
	 */
	scap_evt* evt = NULL;
	uint16_t buffer_id;

	/* The first 'scap_next` could return a `SCAP_TIMEOUT` according to the chosen `buffer_mode` so we ignore it. */
	scap_next(h, &evt, &buffer_id);

	ASSERT_EQ(scap_next(h, &evt, &buffer_id), SCAP_SUCCESS) << "unable to get an event with `scap_next`: " << scap_getlasterr(h) << std::endl;

	last_num_events = 0;
	iterations = 0;

	/* We save some event info to check if they are still valid after some new events */
	uint64_t prev_ts = evt->ts;
	uint64_t prev_tid = evt->tid;
	uint32_t prev_len = evt->len;
	uint16_t prev_type = evt->type;
	uint32_t prev_nparams = evt->nparams;

	/* Start again the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS) << "unable to restart the capture: " << scap_getlasterr(h) << std::endl;

	/* We use the same approximation as before */
	while(iterations < MAX_ITERATIONS)
	{
		ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS) << "unable to get stats: " << scap_getlasterr(h) << std::endl;
		if(last_num_events == (stats.n_evts - stats.n_drops))
		{
			iterations++;
		}
		else
		{
			iterations = 0;
			last_num_events = (stats.n_evts - stats.n_drops);
		}
	}

	/* We check if the previously collected event is still valid */
	ASSERT_EQ(prev_ts, evt->ts) << "different timestamp" << std::endl;
	ASSERT_EQ(prev_tid, evt->tid) << "different thread id" << std::endl;
	ASSERT_EQ(prev_len, evt->len) << "different event len" << std::endl;
	ASSERT_EQ(prev_type, evt->type) << "different event type" << std::endl;
	ASSERT_EQ(prev_nparams, evt->nparams) << "different num params" << std::endl;
}

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_listen) && defined(__NR_accept4) && defined(__NR_getegid) && defined(__NR_getgid) && defined(__NR_geteuid) && defined(__NR_getuid) && defined(__NR_bind) && defined(__NR_connect) && defined(__NR_sendto) && defined(__NR_getsockopt) && defined(__NR_recvmsg) && defined(__NR_recvfrom) && defined(__NR_socket) && defined(__NR_socketpair)

void check_event_order(scap_t* h)
{
	uint32_t events_to_assert[EVENTS_TO_ASSERT] = {PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X, PPME_SOCKET_ACCEPT4_5_E, PPME_SOCKET_ACCEPT4_5_X, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X, PPME_SOCKET_BIND_E, PPME_SOCKET_BIND_X, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X};

	/* Start the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS) << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	/* 1. Generate a `close` event pair */
	syscall(__NR_close, -1);

	/* 2. Generate an `openat` event pair */
	syscall(__NR_openat, 0, "/**mock_path**/", 0, 0);

	/* 3. Generate a `listen` event pair */
	syscall(__NR_listen, -1, -1);

	/* 4. Generate an `accept4` event pair */
	syscall(__NR_accept4, -1, NULL, NULL, 0);

	/* 5. Generate a `getegid` event pair */
	syscall(__NR_getegid);

	/* 6. Generate a `getgid` event pair */
	syscall(__NR_getgid);

	/* 7. Generate a `geteuid` event pair */
	syscall(__NR_geteuid);

	/* 8. Generate a `getuid` event pair */
	syscall(__NR_getuid);

	/* 9. Generate a `bind` event pair */
	syscall(__NR_bind, -1, NULL, 0);

	/* 10. Generate a `connect` event pair */
	syscall(__NR_connect, -1, NULL, 0);

	/* 11. Generate a `sendto` event pair */
	syscall(__NR_sendto, -1, NULL, 0, 0, NULL, 0);

	/* 12. Generate a `getsockopt` event pair */
	syscall(__NR_getsockopt, -1, 0, 0, NULL, NULL);

	/* 13. Generate a `recvmsg` event pair */
	syscall(__NR_recvmsg, -1, NULL, 0);

	/* 14. Generate a `recvmsg` event pair */
	syscall(__NR_recvfrom, -1, NULL, 0, 0, NULL, 0);

	/* 15. Generate a `socket` event pair */
	syscall(__NR_socket, 0, 0, 0);

	/* 16. Generate a `socketpair` event pair */
	syscall(__NR_socketpair, 0, 0, 0, 0);

	/* Stop the capture */
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS) << "unable to stop the capture: " << scap_getlasterr(h) << std::endl;

	scap_evt* evt = NULL;
	uint16_t buffer_id = 0;
	int ret = 0;
	uint64_t acutal_pid = getpid();
	/* if we hit 5 consecutive timeouts it means that all buffers are empty (approximation) */
	uint16_t timeouts = 0;

	for(int i = 0; i < EVENTS_TO_ASSERT; i++)
	{
		while(true)
		{
			ret = scap_next(h, &evt, &buffer_id);
			if(ret == SCAP_SUCCESS)
			{
				timeouts = 0;
				if(evt->tid == acutal_pid && evt->type == events_to_assert[i])
				{
					/* We found our event */
					break;
				}
			}
			else if(ret == SCAP_TIMEOUT)
			{
				timeouts++;
				if(timeouts == 5)
				{
					FAIL() << "we didn't find event '" << events_to_assert[i] << "' at position '" << i << "'" << std::endl;
				}
			}
		}
	}
}

#else

void check_event_order(scap_t* h)
{
	GTEST_SKIP() << "Some syscalls required by the test are not defined" << std::endl;
}
#endif
