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

/* Assertion operators */
enum assertion_operators
{
	EQUAL = 0,
	NOT_EQUAL = 1,
	GREATER = 2,
	LESS = 3,
	GREATER_EQUAL = 4,
	LESS_EQUAL = 5,
};

/* Syscall return code assertions. */
#define SYSCALL_FAILURE 0
#define SYSCALL_SUCCESS 1

/* Event direction. */
#define EXIT_EVENT 0
#define ENTER_EVENT 1

/////////////////////////////////
// SYSCALL RESULT ASSERTIONS
/////////////////////////////////

/**
 * @brief With this method we want to assert the syscall state: `failure` or `success`.
 * Please note that not all syscalls return `-1` when they fail, there are some
 * exceptions, so you have to set the `expected_rc` if it is different from `-1`.
 *
 * When you use this method you must check what is the syscall return value!
 *
 * @param syscall_state it could be `SYSCALL_FAILURE` or `SYSCALL_SUCCESS`
 * @param syscall_name the name of the syscall to assert.
 * @param syscall_rc the return code of the syscall to assert.
 * @param op the operation we want to perform in the assertion.
 * @param expected_rc the return code we expect.
 */
void assert_syscall_state(int syscall_state, const char* syscall_name, long syscall_rc, enum assertion_operators op = EQUAL, long expected_rc = -1);

class event_test
{
public:
	/* Please note: only methods with `assert` in the name use Google assertions. */

	/////////////////////////////////
	// CONFIGURATION
	/////////////////////////////////

	/**
	 * @brief Construct a new event_test object:
	 * - search in the `g_syscall_table` for the right event associated with the syscall-id.
	 * - clean the BPF probe state before starting a new test.
	 *
	 * @param syscall_id syscall that we want to assert.
	 * @param event_direction it could be `ENTER_EVENT` or `EXIT_EVENT`.
	 */
	explicit event_test(int syscall_id, int event_direction);

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
	 * - Length and value of each parameter.
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
	 * @brief Assert that the parameter is of the right type and
	 * compare its value with the expected one.
	 *
	 * `T` must be `uint8_t` for the following types:
	 * - PT_UINT8
	 * - PT_SIGTYPE
	 * - PT_FLAGS8
	 * - PT_ENUMFLAGS8
	 *
	 * `T` must be `uint16_t` for the following types:
	 * - PT_UINT16
	 * - PT_FLAGS16
	 * - PT_ENUMFLAGS16
	 *
	 * `T` must be `uint32_t` for the following types:
	 * - PT_UINT32
	 * - PT_UID
	 * - PT_GID
	 * - PT_SIGSET
	 * - PT_MODE
	 * - PT_FLAGS32
	 * - PT_ENUMFLAGS32
	 *
	 * `T` must be `uint64_t` for the following types:
	 * - PT_UINT64
	 * - PT_RELTIME
	 * - PT_ABSTIME
	 *
	 * `T` must be `int32_t` for the following types:
	 * - PT_INT32
	 *
	 * `T` must be `int64_t` for the following types:
	 * - PT_INT64
	 * - PT_ERRNO
	 * - PT_FD
	 * - PT_PID
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 * @param op the operation we want to perform in the assertion.
	 */
	template<class T>
	void assert_numeric_param(int param_num, T param, enum assertion_operators op = EQUAL);

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

	/**
	 * @brief The ptrace `addr` param is a `PT_DYN`, so we need
	 * a dedicated helper to assert it.
	 *
	 * TODO: This is still a partial implementation, we assert
	 * only the case in which the param is empty.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 */
	void assert_ptrace_addr(int param_num);

	/**
	 * @brief The ptrace `data` param is a `PT_DYN`, so we need
	 * a dedicated helper to assert it.
	 *
	 * TODO: This is still a partial implementation, we assert
	 * only the case in which the param is empty.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 */
	void assert_ptrace_data(int param_num);

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
