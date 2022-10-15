#include "../../event_class/event_class.h"

#include <sys/types.h>
#include <sys/wait.h>

#define CLONE_EVENT_SIZE sizeof(struct ppm_evt_hdr) + sizeof(int64_t) + 2
#define RINGBUF_HEADER 8
/* If the free space in the buffer is less than this we have no space for another
 * event, so we can consider the buffer empty.
 */
#define THRESHOLD CLONE_EVENT_SIZE + RINGBUF_HEADER

#ifdef __NR_close
/* Run this test alone by typing:
 * `sudo ./test/modern_bpf/bpf_test --gtest_filter='Local.ring_buffer_overwrite' --buffer_dim 4096`
 */
TEST(Local, ring_buffer_overwrite)
{
	/* The rationale behind this test is to let the system fill all the ring buffers with
	 * `PPME_SYSCALL_CLOSE_E` and `PPME_SYSCALL_CLOSE_X` events. We choose this particular
	 * syscall because enter and exit events have exactly the same size
	 * (look here /driver/modern_bpf/definitions/events_dimensions.h) so it is easier for
	 * us to understand if our buffers are full! BTW this is not strictly necessary we can
	 * modify the test if these events should change dimensions!
	 *
	 * When the buffers are full we try to extract an event from the buffers and we assert that
	 * this event is not overwritten by others until we read the next event.
	 */

	auto evt_test = get_syscall_event_test(__NR_close, ENTER_EVENT);
	evt_test->disable_capture();
	evt_test->clear_ring_buffers();
	evt_test->enable_capture();

	while(!evt_test->are_all_ringbuffers_full(THRESHOLD))
	{
	};

	/* Remove some events from the buffer (in this case 10)
	 * and keep the pointer to an event to see if this is overwritten
	 */
	struct ppm_evt_hdr* evt = NULL;
	int16_t cpu_id = 0;
	
	for(int i=0; i<10; i++)
	{
		evt = evt_test->get_event_from_ringbuffer(&cpu_id);
		ASSERT_EQ(evt == NULL, false);
	}

	/* Check that the pointer to this event is not overwritten */
	evt = evt_test->get_event_from_ringbuffer(&cpu_id);
	ASSERT_EQ(evt == NULL, false);
	uint64_t prev_ts = evt->ts;
	uint64_t prev_tid = evt->tid;
	uint32_t prev_len = evt->len;
	uint16_t prev_type = evt->type;
	uint32_t prev_nparams = evt->nparams;

	while(!evt_test->are_all_ringbuffers_full(THRESHOLD))
	{
	};

	/* We assert that the event header is not overwritten */
	ASSERT_EQ(prev_ts, evt->ts);
	ASSERT_EQ(prev_tid, evt->tid);
	ASSERT_EQ(prev_len, evt->len);
	ASSERT_EQ(prev_type, evt->type);
	ASSERT_EQ(prev_nparams, evt->nparams);
}
#endif

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_ioctl)
TEST(Local, ring_buffer_read_in_order)
{
	/* Here we capture all syscalls... this process will send some
	 * specific syscalls and we have to check that they are extracted in order
	 * from the buffers.
	 */
	auto evt_test = get_syscall_event_test();
	
	evt_test->enable_capture();

	/* 1. Generate a `close` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "close", syscall(__NR_close, -1));

	/* 2. Generate an `openat` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "openat", syscall(__NR_openat, AT_FDCWD, "mock_path", 0, 0));

	/* 3. Generate an `ioctl` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "ioctl", syscall(__NR_ioctl, -1, 0, NULL));
	
	/* 4. Generate an `accept4` event pair */
	assert_syscall_state(SYSCALL_FAILURE, "accept4", syscall(__NR_accept4, -1, NULL, NULL, 0));

	/* Disable the capture: no more events from now. */
	evt_test->disable_capture();

	/* Retrieve events in order. */
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_CLOSE_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_CLOSE_X);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_OPENAT_2_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_OPENAT_2_X);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_IOCTL_3_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SYSCALL_IOCTL_3_X);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_ACCEPT4_5_E);
	evt_test->assert_event_presence(CURRENT_PID, PPME_SOCKET_ACCEPT4_5_X);
}
#endif
