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
#include "network_utils.h"
#include <arpa/inet.h>
#include <sys/un.h>
#include <scap.h>

#define CURRENT_PID -1
#define CURRENT_EVENT_TYPE -1

extern "C"
{
#include <ppm_events_public.h>
#include <feature_gates.h>
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

enum direction
{
	SOURCE = 0,
	DEST = 1,
};

/* Default snaplen that we use in the modern probe */
#define DEFAULT_SNAPLEN 80

/* Syscall return code assertions. */
#define SYSCALL_FAILURE 0
#define SYSCALL_SUCCESS 1

/* Event direction. */
#define EXIT_EVENT 0
#define ENTER_EVENT 1

/* NOTE: if we change the name of this executable
 * we have to change also this string!
 */
#define TEST_EXECUTABLE_NAME "drivers_test"

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
	static scap_t* s_scap_handle;

	static void set_scap_handle(scap_t* handle)
	{
		s_scap_handle = handle;
	}

	static void clear_ppm_sc_mask()
	{
		for (int i = 0; i < PPM_SC_MAX; i++)
		{
			scap_set_ppm_sc(s_scap_handle, i, false);
		}
	}

	/* Please note: only methods with `assert` in the name use Google assertions. */

	/////////////////////////////////
	// CONFIGURATION
	/////////////////////////////////

	/**
	 * @brief Construct a new event_test object for syscall events:
	 * - search in the `g_syscall_table` for the right event associated with the syscall-id.
	 *
	 * @param syscall_id syscall that we want to assert.
	 * @param event_direction it could be `ENTER_EVENT` or `EXIT_EVENT`.
	 */
	explicit event_test(int syscall_id, int event_direction);

	/**
	 * @brief Construct a new event test object for generic tracepoints events:
	 * - attach the right BPF program associated with this event type.
	 *
	 * @param event_type event that we want to assert.
	 */
	explicit event_test(ppm_event_type event_type);

	/**
	 * @brief Construct a new event_test object for syscall events:
	 * - mark all syscalls as interesting.
	 */
	explicit event_test();

	/**
	 * @brief Destroy the event_test object and clean the system state:
	 * - detach all BPF programs that are not syscall dispatchers.
	 * - mark all syscalls as uninteresting.
	 */
	~event_test();

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
	 * @brief Retrieve the event with the lowest timestamp in the ring buffer.
	 * Return the CPU from which we extracted the event. Return NULL
	 * in case of no events.
	 *
	 * @param cpu_id CPU from which we extracted the event.
	 */
	void get_event_from_ringbuffer(uint16_t* cpu_id);

	/**
	 * @brief Parse information from the event that we have extracted from the buffer:
	 * - Number of parameters.
	 * - Length and value of each parameter.
	 * - Total length of the event.
	 *
	 */
	void parse_event();

	/**
	 * @brief Check the current engine type
	 *
	 * @return true if the current engine is bpf
	 */
	bool is_bpf_engine()
	{
		return scap_check_current_engine(s_scap_handle, BPF_ENGINE);
	}

	/**
	 * @brief Check the current engine type
	 *
	 * @return true if the current engine is modern-bpf
	 */
	bool is_modern_bpf_engine()
	{
		return scap_check_current_engine(s_scap_handle, MODERN_BPF_ENGINE);
	}

	/**
	 * @brief Check the current engine type
	 *
	 * @return true if the current engine is kmod
	 */
	bool is_kmod_engine()
	{
		return scap_check_current_engine(s_scap_handle, KMOD_ENGINE);
	}

	/////////////////////////////////
	// NETWORK SCAFFOLDING
	/////////////////////////////////

	/**
	 * @brief Allow sockets to reuse the same port and address.
	 *
	 * @param socketfd socket file descriptor.
	 */
	void client_reuse_address_port(int32_t socketfd);
	void server_reuse_address_port(int32_t socketfd);

	/**
	 * @brief Fill a `sockaddr_in` struct. It uses default values defined
	 * in `network_utils.h`, if the user doesn't provide them.
	 *
	 * @param sockaddr `sockaddr_in` struct to fill.
	 * @param ipv4_port port as an integer value.
	 * @param ipv4_string ipv4 as a string.
	 */
	void client_fill_sockaddr_in(struct sockaddr_in* sockaddr, int32_t ipv4_port = IPV4_PORT_CLIENT, const char* ipv4_string = IPV4_CLIENT);
	void server_fill_sockaddr_in(struct sockaddr_in* sockaddr, int32_t ipv4_port = IPV4_PORT_SERVER, const char* ipv4_string = IPV4_SERVER);

	/**
	 * @brief Fill a `sockaddr_in6` struct. It uses default values defined
	 * in `network_utils.h`, if the user doesn't provide them.
	 *
	 * @param sockaddr `sockaddr_in6` struct to fill.
	 * @param ipv6_port port as an integer value.
	 * @param ipv6_string ipv6 as a string.
	 */
	void client_fill_sockaddr_in6(struct sockaddr_in6* sockaddr, int32_t ipv6_port = IPV6_PORT_CLIENT, const char* ipv6_string = IPV6_CLIENT);
	void server_fill_sockaddr_in6(struct sockaddr_in6* sockaddr, int32_t ipv6_port = IPV6_PORT_SERVER, const char* ipv6_string = IPV6_SERVER);

	/**
	 * @brief Fill a `sockaddr_un` struct. It uses default values defined
	 * in `network_utils.h`, if the user doesn't provide them.
	 *
	 * @param sockaddr `sockaddr_un` struct to fill.
	 * @param unix_path unix socket path.
	 */
	void client_fill_sockaddr_un(struct sockaddr_un* sockaddr, const char* unix_path = UNIX_CLIENT);
	void server_fill_sockaddr_un(struct sockaddr_un* sockaddr, const char* unix_path = UNIX_SERVER);

	/**
	 * @brief Connect a client to a server that is now ready to receive messages
	 * and accept new connections.
	 *
	 * @param client_socket client socket file descriptor.
	 * @param client_sockaddr client `sockaddr` struct to fill.
	 * @param server_socket server socket file descriptor.
	 * @param server_sockaddr server `sockaddr` struct to fill.
	 */
	void connect_ipv4_client_to_server(int32_t* client_socket, struct sockaddr_in* client_sockaddr, int32_t* server_socket, struct sockaddr_in* server_sockaddr);
	void connect_ipv6_client_to_server(int32_t* client_socket, struct sockaddr_in6* client_sockaddr, int32_t* server_socket, struct sockaddr_in6* server_sockaddr);
	void connect_unix_client_to_server(int32_t* client_socket, struct sockaddr_un* client_sockaddr, int32_t* server_socket, struct sockaddr_un* server_sockaddr);

	/////////////////////////////////
	// GENERIC EVENT ASSERTIONS
	/////////////////////////////////

	/**
	 * @brief Assert if our buffers contain an event:
	 *
	 * 1. generated by `pid_to_search`. If no `pid_to_search` is specified we search
	 * for an event generated by the process that calls this method. This is the meaning of
	 * the `CURRENT_PID` macro.
	 *
	 * 2. of type `event_to_search`. If no `event_to_search` is specified we search
	 * for the event type saved in the `event_test` object. This is the meaning of
	 * the `CURRENT_EVENT_TYPE` macro.
	 *
	 * Search until all buffers are empty. If we don't find any event
	 * with these requirements, we fail.
	 *
	 * @param pid_to_search pid that generated the event we are looking for.
	 * @param event_to_search event type we are looking for.
	 */
	void assert_event_presence(pid_t pid_to_search = CURRENT_PID, int event_to_search = CURRENT_EVENT_TYPE);

	/**
	 * @brief Assert if our buffers *don't* contain an event:
	 *
	 * 1. generated by `pid_to_search`. If no `pid_to_search` is specified we search
	 * for an event generated by the process that calls this method. This is the meaning of
	 * the `CURRENT_PID` macro.
	 *
	 * 2. of type `event_to_search`. If no `event_to_search` is specified we search
	 * for the event type saved in the `event_test` object. This is the meaning of
	 * the `CURRENT_EVENT_TYPE` macro.
	 *
	 * Search until all buffers are empty. If we find any event
	 * with these requirements, we fail.
	 *
	 * @param pid_to_search pid that generated the event we are looking for.
	 * @param event_to_search event type we are looking for.
	 */
	void assert_event_absence(pid_t pid_to_search = CURRENT_PID, int event_to_search = CURRENT_EVENT_TYPE);

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
	 * @brief Assert that the parameter is a `charbuf` array and
	 * compare element per element the array with the one passed as a parameter `param`.
	 *
	 * Use this method with the following types:
	 *	- PT_CHARBUFARRAY
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param param expected value.
	 */
	void assert_charbuf_array_param(int param_num, const char** param);

	/**
	 * @brief 'cgroup_string' is composed by 'cgroup_subsytem_name' + 'cgroup_path'.
	 * Here we can assert only the 'cgroup_subsytem_name' + the presence of the '/' in the path.
	 * So we don't need to pass any param we have a static vector of prefixes
	 * to assert (`cgroup_prefix_array`).
	 *
	 * @param param_num number of the parameter to assert into the event.
	 */
	void assert_cgroup_param(int param_num);

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
	 * @brief Assert the values extracted from an INET `sockaddr`:
	 * - socket family
	 * - ipv4
	 * - port
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param desired_family expected socket family.
	 * @param desired_ipv4 expected ipv4.
	 * @param desired_port expected port.
	 */
	void assert_addr_info_inet_param(int param_num, uint8_t desired_family, const char* desired_ipv4, const char* desired_port);

	/**
	 * @brief Assert the values extracted from an INET6 `sockaddr`:
	 * - socket family
	 * - ipv6
	 * - port
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param desired_family expected socket family.
	 * @param desired_ipv6 expected ipv6.
	 * @param desired_port expected port.
	 */
	void assert_addr_info_inet6_param(int param_num, uint8_t desired_family, const char* desired_ipv6, const char* desired_port);

	/**
	 * @brief Assert the values extracted from a UNIX `sockaddr`:
	 * - socket family
	 * - unix path
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param desired_family expected socket family.
	 * @param desired_path expected unix path.
	 */
	void assert_addr_info_unix_param(int param_num, uint8_t desired_family, const char* desired_path);

	/**
	 * @brief Assert the tuple extracted from a kernel INET socket:
	 * - socket family
	 * - src ipv4
	 * - dest ipv4
	 * - src port
	 * - dest port
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param desired_family expected socket family.
	 * @param desired_src_ipv4 expected source ipv4.
	 * @param desired_dest_ipv4 expected dest ipv4.
	 * @param desired_src_port expected source port.
	 * @param desired_dest_port expected dest port.
	 */
	void assert_tuple_inet_param(int param_num, uint8_t desired_family, const char* desired_src_ipv4,
				     const char* desired_dest_ipv4, const char* desired_src_port, const char* desired_dest_port);

	/**
	 * @brief Assert the tuple extracted from a kernel INET6 socket:
	 * - socket family
	 * - src ipv6
	 * - dest ipv6
	 * - src port
	 * - dest port
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param desired_family expected socket family.
	 * @param desired_src_ipv6 expected source ipv6.
	 * @param desired_dest_ipv6 expected dest ipv6.
	 * @param desired_src_port expected source port.
	 * @param desired_dest_port expected dest port.
	 */
	void assert_tuple_inet6_param(int param_num, uint8_t desired_family, const char* desired_src_ipv6, const char* desired_dest_ipv6,
				      const char* desired_src_port, const char* desired_dest_port);

	/**
	 * @brief Assert the tuple extracted from a kernel UNIX socket:
	 * - socket family.
	 * - dest OS pointer. (we cannot assert it!)
	 * - src OS pointer. (we cannot assert it!)
	 * - dest unix_path.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param desired_family expected socket family.
	 * @param desired_path expected dest unix_path.
	 */
	void assert_tuple_unix_param(int param_num, uint8_t desired_family, const char* desired_path);

	/**
	 * @brief The setsockopt `optval` is a `PT_DYN`, so we need
	 * a dedicated helper to assert it.
	 *
	 * @param param_num number of the parameter to assert into the event.
	 * @param sockopt scap code that indicates the type of option.
	 * @param option_value value that changes according to the option involved.
	 * @param option_len length of the value.
	 */
	void assert_setsockopt_val(int param_num, int sockopt, void* option_value, int option_len);

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
	std::vector<uint8_t> m_tp_set;		  /* Set of tracepoints that must be enabled for the specific test. */

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
	 * @brief Assert if the length of the current param is the expected one
	 *
	 * @param expected_size expected length of the param
	 */
	void assert_param_len(uint16_t expected_size);

	/**
	 * @brief Assert if the length of the current param is greater or equal
	 * than the expected one
	 *
	 * @param expected_size expected length of the param
	 */
	void assert_param_len_ge(uint16_t expected_size);

	/**
	 * @brief Assert the socket address family as part of a `sockaddr` or a `tuple`.
	 *
	 * @param desired_family expected socket family.
	 * @param starting_index index inside the param where we can find the socket familiy.
	 */
	void assert_address_family(uint8_t desired_family, int starting_index);

	/**
	 * @brief Assert an ipv4 address as part of a `sockaddr` or a `tuple`.
	 *
	 * Please note that the BPF instrumentation provides us with the ipv4 as number
	 * here we convert it to a string and we assert it.
	 *
	 * @param desired_ipv4 expected ipv4 address as a string.
	 * @param starting_index index inside the param where we can find the ipv4 address.
	 */
	void assert_ipv4_string(const char* desired_ipv4, int starting_index, enum direction dir = DEST);

	/**
	 * @brief Assert the port number as part of a `sockaddr` or a `tuple`.
	 *
	 * Please note that the BPF instrumentation provides us with the port as number
	 * here we convert it to a string and we assert it.
	 *
	 * @param desired_port expected port number as a string.
	 * @param starting_index index inside the param where we can find the port number.
	 */
	void assert_port_string(const char* desired_port, int starting_index, enum direction dir = DEST);

	/**
	 * @brief Assert an ipv6 address as part of a `sockaddr` or a `tuple`.
	 *
	 * Please note that the BPF instrumentation provides us with the ipv6 as number
	 * here we convert it to a string and we assert it.
	 *
	 * @param desired_ipv6 expected ipv6 address.
	 * @param starting_index index inside the param where we can find the ipv6 address.
	 */
	void assert_ipv6_string(const char* desired_ipv6, int starting_index, enum direction dir = DEST);

	/**
	 * @brief Assert an unix socket path as part of a `sockaddr` or a `tuple`.
	 *
	 * @param desired_path expected unix socket path.
	 * @param starting_index index inside the param where we can find the unix path.
	 */
	void assert_unix_path(const char* desired_path, int starting_index);

	/**
	 * @brief Assert if our buffers contain or not an event according to the
	 * `presence` bool.
	 * This method is used by `assert_event_presence` and `assert_event_absence`, if you
	 * need more info about the usage look at these methods.
	 *
	 * @param pid_to_search pid that generated the event we are looking for.
	 * @param event_to_search event type we are looking for.
	 * @param presence true if we want to assert the event presence.
	 */
	void assert_event_in_buffers(pid_t pid_to_search, int event_to_search, bool presence);
};

/////////////////////////////////
// RETRIEVE EVENT CLASS
/////////////////////////////////

/**
 * @brief Get a new event test object for generic tracepoints events:
 * - attach the right BPF program associated with this event type.
 *
 * @param event_type event that we want to assert.
 */
std::unique_ptr<event_test> get_generic_event_test(ppm_event_type event_type);

/**
 * @brief Get a new event_test object for syscall events:
 * - search in the `g_syscall_table` for the right event associated with the syscall-id.
 *
 * @param syscall_id syscall that we want to assert.
 * @param event_direction it could be `ENTER_EVENT` or `EXIT_EVENT`.
 */
std::unique_ptr<event_test> get_syscall_event_test(int syscall_id, int event_direction);

/**
 * @brief Get a new event_test object for syscall events:
 * - mark all syscalls as interesting.
 */
std::unique_ptr<event_test> get_syscall_event_test();
