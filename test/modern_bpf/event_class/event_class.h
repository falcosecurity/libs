#pragma once
#include <stdint.h>
#include <iostream>
#include <sys/syscall.h>
#include <fcntl.h> /* To get different flags. */
#include <vector>
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>

extern "C"
{
#include <libpman.h>
#include <ppm_events_public.h>
}

struct param
{
	char* valptr;
	uint16_t len;
};

class event_test
{
public:
	/* Please note: only methods with `assert` in the name use Google assertions. */

	/////////////////////////////////
	// CONFIGURATION
	/////////////////////////////////

	/**
	 * @brief Construct a new event_test object:
	 * - initialize the event type that we want to assert.
	 * - clean the BPF probe state before starting a new test.
	 *
	 * @param event_type event type that we want to assert.
	 */
	explicit event_test(ppm_event_type event_type);

	/**
	 * @brief Destroy the event_test object
	 *
	 */
	~event_test();

	/**
	 * @brief Mark only the 64-bit syscall with `syscall_id` as interesting.
	 *
	 * @param syscall_id id of the syscall.
	 */
	void mark_single_64bit_syscall_as_interesting(int syscall_id);

	/**
	 * @brief Mark all 64-bit syscalls as uninteresting.
	 *
	 */
	void mark_all_64bit_syscalls_as_uninteresting();

	/**
	 * @brief Tracepoints can start to catch events.
	 *
	 */
	void enable_capture();

	/**
	 * @brief Deny the Tracepoints to catch further events.
	 *
	 */
	void disable_capture();

	/**
	 * @brief Clear the ring buffers from all previous events until they
	 * are all empty.
	 *
	 */
	void clear_ring_buffers();

	/**
	 * @brief Parse information from the event that we have extracted from the buffer:
	 * - Number of parameters.
	 * - Lenght and value of each parameter.
	 * - Total length of the event.
	 *
	 */
	void parse_event();

	/////////////////////////////////
	// GENERIC EVENT ASSERTIONS
	/////////////////////////////////

	/**
	 * @brief Assert if in our buffers there is an event of the specified type.
	 * Search until all buffers are empty. If we don't find any event of this type
	 * we fail.
	 */
	void assert_event_presence();

	/**
	 * @brief Assert some fields of the event header:
	 * - the event params num must match the number of parameters in the event table.
	 * - the overall event length must match the total length written in the header.
	 */
	void assert_header();

	/**
	 * @brief Assert the number of params that bpf-side pushes to userspace
	 *  against the number of params written in the BPF table.
	 *
	 * @param total_params total number of params we send bpf-side
	 */
	void assert_num_params_pushed(int param_num);

	/////////////////////////////////
	// SYSCALL RESULT ASSERTIONS
	/////////////////////////////////

	/**
	 * @brief When we call this function we expect that the syscall will fail.
	 * Please note that not all syscalls return `-1` when they fail, there are some
	 * exceptions... by the way, with this function we can manage the large majority of
	 * cases. When you use this method you must check what is the syscall return value!
	 *
	 * @param syscall_rc the return code of the syscall to assert
	 * @param syscall_name the name of the syscall to assert
	 */
	void assert_syscall_failure(long syscall_rc, const char* syscall_name);

	/**
	 * @brief When we call this function we expect that the syscall will succeed.
	 * Please note that not all syscalls return `-1` when they fail, there are some
	 * exceptions... by the way, with this function we can manage the large majority of
	 * cases. When you use this method you must check what is the syscall return value!
	 *
	 * @param syscall_rc the return code of the syscall to assert
	 * @param syscall_name the name of the syscall to assert
	 */
	void assert_syscall_success(long syscall_rc, const char* syscall_name);

	/////////////////////////////////
	// PARAM ASSERTIONS
	/////////////////////////////////

	/**
	 * @brief Assert only that the param doesn't exceed the boundaries of the event params
	 * and check that the param length is `0`.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 */
	void assert_empty_param(int param_num);

	/**
	 * @brief There are cases in which we cannot assert the param value but only its length.
	 * This method checks that the param doesn't exceed the boundaries of the event params
	 * and that its length is the expected one.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param expected_size expected length of the param.
	 */
	void assert_only_param_len(int param_num, uint16_t expected_size);

	/**
	 * @brief Assert that the parameter is an `uint8` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 * - PT_UINT8
	 * - PT_SIGTYPE
	 * - PT_FLAGS8
	 * - PT_ENUMFLAGS8
	 *
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_u8_param(int param_num, uint8_t param);

	/**
	 * @brief Assert that the parameter is an `uint16` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 * - PT_UINT16
	 * - PT_FLAGS16
	 * - PT_ENUMFLAGS16
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_u16_param(int param_num, uint16_t param);

	/**
	 * @brief Assert that the parameter is an `uint32` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 * - PT_UINT32
	 * - PT_UID
	 * - PT_GID
	 * - PT_SIGSET
	 * - PT_MODE
	 * - PT_FLAGS32
	 * - PT_ENUMFLAGS32
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_u32_param(int param_num, uint32_t param);

	/**
	 * @brief Assert that the parameter is an `uint64` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 * - PT_UINT64
	 * - PT_RELTIME
	 * - PT_ABSTIME
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_u64_param(int param_num, uint64_t param);

	/**
	 * @brief Assert that the parameter is an `int32` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 * - PT_INT32
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_s32_param(int param_num, int32_t param);

	/**
	 * @brief Assert that the parameter is an `int64` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 * - PT_INT64
	 * - PT_ERRNO
	 * - PT_FD
	 * - PT_PID
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_s64_param(int param_num, int64_t param);

	/**
	 * @brief Assert that the parameter is an `uint32` and
	 * check that its value is greater or equal to the expected one.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_u32_param_ge_than(int param_num, uint32_t param);

	/**
	 * @brief Assert that the parameter is an `uint64` and
	 * check that its value is greater or equal to the expected one.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_u64_param_ge_than(int param_num, uint64_t param);

	/**
	 * @brief Assert that the parameter is an `int64` and
	 * check that its value is greater or equal to the expected one.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_s64_param_ge_than(int param_num, uint64_t param);

	/**
	 * @brief Assert that the parameter is a `charbuf` and
	 * compare its value with the expected one.
	 *
	 * Use this method with the following types:
	 *	- PT_CHARBUF
	 *  - PT_FSPATH
	 *  - PT_FSRELPATH
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_charbuf_param(int param_num, const char* param);

	/**
	 * @brief Assert that the parameter is a `bytebuf` and
	 * compare its value with the expected one. The difference between
	 * `charbuf` and `bytebuf` is that with the `bytebuf` we don't care about
	 * the string terminator, we are not considering a `string`, but just a
	 * bunch of bytes.
	 *
	 * Use this method with the following types:
	 *	- PT_BYTEBUF
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_bytebuf_param(int param_num, const char* param, int buf_dimension);

private:
	enum ppm_event_type m_event_type;	  /* type of the event we want to assert in this test. */
	std::vector<struct param> m_event_params; /* all the params of the event (len+value). */
	struct ppm_evt_hdr* m_event_header;	  /* header of the event. */
	uint32_t m_event_len;			  /* total event length. */
	uint32_t m_current_param;		  /* current param that we are analyzing in a single assert method. */

	/**
	 * @brief Performs two main actions:
	 * - Assert if the passed param number exceeds the allowed
	 * boundaries for the event.
	 * - Declare the passed param `current_param`.
	 *
	 * Please note: this assertion must be called by every other parameter assertion
	 * to set the `current_param`.
	 *
	 * @param param_num param number to assert
	 */
	void assert_param_boundaries(int param_num);

	/**
	 * @brief Assert if the length of current param is the expected one
	 *
	 * @param expected_size expected length of the param
	 */
	void assert_param_len(uint16_t expected_size);
};
