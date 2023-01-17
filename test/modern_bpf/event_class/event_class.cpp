
#include "strlcpy.h"
#include "event_class.h"
#include <time.h>

#define MAX_CHARBUF_NUM 16
#define CGROUP_NUMBER 5
#define MAX_CGROUP_STRING_LEN 128
#define MAX_CGROUP_PREFIX_LEN 32

/* This array must follow the same order we use in BPF. */
const char* cgroup_prefix_array[CGROUP_NUMBER] = {
	"cpuset=/",
	"cpu=/",
	"cpuacct=/",
	"io=/",
	"memory=/",
};

/* Messages. */
#define VALUE_NOT_CORRECT ">>>>> value of the param is not correct. Param id = "
#define VALUE_NOT_ZERO ">>>>> value of the param must not be zero. Param id = "

extern const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];

/////////////////////////////////
// RETRIEVE EVENT CLASS
/////////////////////////////////

std::unique_ptr<event_test> get_generic_event_test(ppm_event_type event_type)
{
	return (std::unique_ptr<event_test>)new event_test(event_type);
}

std::unique_ptr<event_test> get_syscall_event_test(int syscall_id, int event_direction)
{
	return (std::unique_ptr<event_test>)new event_test(syscall_id, event_direction);
}

std::unique_ptr<event_test> get_syscall_event_test()
{
	return (std::unique_ptr<event_test>)new event_test();
}

/////////////////////////////////
// SYSCALL RESULT ASSERTIONS
/////////////////////////////////

void assert_syscall_state(int syscall_state, const char* syscall_name, long syscall_rc, enum assertion_operators op, long expected_rc)
{
	bool match = false;

	switch(op)
	{
	case EQUAL:
		match = syscall_rc == expected_rc;
		break;

	case NOT_EQUAL:
		match = syscall_rc != expected_rc;
		break;

	default:
		FAIL() << "Operation currently not supported!" << std::endl;
		return;
	}

	if(!match)
	{
		if(syscall_state == SYSCALL_SUCCESS)
		{
			FAIL() << ">>>>> The syscall '" << syscall_name << "' must be successful. Errno: " << errno << " err_message: " << strerror(errno) << std::endl;
		}
		else
		{
			FAIL() << ">>>>> The syscall '" << syscall_name << "' must fail." << std::endl;
		}
	}
}

/////////////////////////////////
// CONFIGURATION
/////////////////////////////////

event_test::~event_test()
{
	/*
	 * Cleaning phase.
	 */

	/*
	 * NOTE: we always expect disable_capture to be manually called,
	 * just like enable_capture is.
	 */

	/* 1 - clean all the ring_buffers until they are empty. */
	clear_ring_buffers();

	/* 2 - clean all interesting syscalls. */
	mark_all_64bit_syscalls_as_uninteresting();
}

/* This constructor must be used with generic tracepoints
 * that must attach a dedicated BPF program into the kernel.
 */
event_test::event_test(ppm_event_type event_type):
	m_tp_set(TP_VAL_MAX, 0)
{
	m_current_param = 0;
	m_event_type = event_type;

	switch(m_event_type)
	{
	case PPME_PROCEXIT_1_E:
		m_tp_set[SCHED_PROC_EXIT] = 1;
		break;
	case PPME_SCHEDSWITCH_6_E:
		m_tp_set[SCHED_SWITCH] = 1;
		break;
	case PPME_SYSCALL_EXECVE_19_X:
#ifdef CAPTURE_SCHED_PROC_EXEC
		m_tp_set[SCHED_PROC_EXEC] = 1;
#endif
		break;
	case PPME_SYSCALL_CLONE_20_X:
#ifdef CAPTURE_SCHED_PROC_FORK
		m_tp_set[SCHED_PROC_FORK] = 1;
#endif
		break;

	default:
		std::cout << " Unable to find the correct BPF program to attach" << std::endl;
		break;
	}
}

/* This constructor must be used with syscalls events */
event_test::event_test(int syscall_id, int event_direction):
	m_tp_set(TP_VAL_MAX, 0)
{
	if(event_direction == ENTER_EVENT)
	{
		m_tp_set[SYS_ENTER] = 1;
		m_event_type = g_syscall_table[syscall_id].enter_event_type;
	}
	else
	{
		m_tp_set[SYS_EXIT] = 1;
		m_event_type = g_syscall_table[syscall_id].exit_event_type;
	}

	m_current_param = 0;

	/* Set the current as the only interesting syscall. */
	mark_single_64bit_syscall_as_interesting(syscall_id);
}

/* This constructor must be used with syscalls events when you
 * want to enable all syscalls.
 */
event_test::event_test():
	m_tp_set(TP_VAL_MAX, 0)
{
	m_current_param = 0;

	/* Enable only syscall tracepoints */
	m_tp_set[SYS_ENTER] = 1;
	m_tp_set[SYS_EXIT] = 1;

	for(int sys_num = 0; sys_num < SYSCALL_TABLE_SIZE; sys_num++)
	{
		mark_single_64bit_syscall_as_interesting(sys_num);
	}
}

void event_test::mark_single_64bit_syscall_as_interesting(int interesting_syscall_id)
{
	pman_mark_single_64bit_syscall(interesting_syscall_id, true);
}

void event_test::mark_all_64bit_syscalls_as_uninteresting()
{
	pman_clean_all_64bit_interesting_syscalls();
}

void event_test::enable_capture()
{
	pman_enable_capture((bool*)m_tp_set.data());
	clear_ring_buffers();
}

void event_test::disable_capture()
{
	pman_disable_capture();
}

void event_test::clear_ring_buffers()
{
	uint16_t cpu_id = 0;
	while(get_event_from_ringbuffer(&cpu_id) != NULL)
	{
	};
}

bool event_test::are_all_ringbuffers_full(unsigned long threshold)
{
	return pman_are_all_ringbuffers_full(threshold);
}

struct ppm_evt_hdr* event_test::get_event_from_ringbuffer(uint16_t* cpu_id)
{
	m_event_header = NULL;
	uint16_t attempts = 0;

	/* Try 2 times just to be sure that all the buffers are empty. */
	while(attempts <= 1)
	{
		pman_consume_one_from_buffers((void**)&m_event_header, cpu_id);
		if(m_event_header != NULL)
		{
			return m_event_header;
		}
		attempts++;
	}
	return m_event_header;
}

void event_test::parse_event()
{
	uint8_t nparams = m_event_header->nparams;
	uint16_t* lens16 = (uint16_t*)((char*)m_event_header + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens16 + nparams * sizeof(uint16_t);
	uint32_t total_len = sizeof(struct ppm_evt_hdr) + nparams * sizeof(uint16_t);
	struct param par;

	/* Insert a dummy param just to use index starting from 1 insted of 0. */
	par.len = 0;
	par.valptr = NULL;
	m_event_params.push_back(par);

	for(int j = 0; j < nparams; j++)
	{
		par.valptr = valptr;
		par.len = lens16[j];
		valptr += lens16[j];
		m_event_params.push_back(par);
		total_len += lens16[j];
	}

	/* This event len is the overall len of the event (header + len_vector + data).
	 * Note: we compute this length according to the number of params written in the header by the bpf program.
	 */
	m_event_len = total_len;
}

/////////////////////////////////
// NETWORK SCAFFOLDING
/////////////////////////////////

void event_test::client_reuse_address_port(int32_t socketfd)
{
	/* Allow the socket to reuse the port and address. */
	int option_value = 1;
	assert_syscall_state(SYSCALL_SUCCESS, "setsockopt (client address)", syscall(__NR_setsockopt, socketfd, SOL_SOCKET, SO_REUSEADDR, &option_value, sizeof(option_value)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "setsockopt (client port)", syscall(__NR_setsockopt, socketfd, SOL_SOCKET, SO_REUSEPORT, &option_value, sizeof(option_value)), NOT_EQUAL, -1);
}

void event_test::server_reuse_address_port(int32_t socketfd)
{
	/* Allow the socket to reuse the port and address. */
	int option_value = 1;
	assert_syscall_state(SYSCALL_SUCCESS, "setsockopt (server address)", syscall(__NR_setsockopt, socketfd, SOL_SOCKET, SO_REUSEADDR, &option_value, sizeof(option_value)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "setsockopt (server port)", syscall(__NR_setsockopt, socketfd, SOL_SOCKET, SO_REUSEPORT, &option_value, sizeof(option_value)), NOT_EQUAL, -1);
}

void event_test::client_fill_sockaddr_in(struct sockaddr_in* sockaddr, int32_t ipv4_port, const char* ipv4_string)
{
	memset(sockaddr, 0, sizeof(*sockaddr));
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_port = htons(ipv4_port);
	assert_syscall_state(SYSCALL_SUCCESS, "inet_pton (client)", inet_pton(AF_INET, ipv4_string, &(sockaddr->sin_addr)), NOT_EQUAL, -1);
}

void event_test::server_fill_sockaddr_in(struct sockaddr_in* sockaddr, int32_t ipv4_port, const char* ipv4_string)
{
	memset(sockaddr, 0, sizeof(*sockaddr));
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_port = htons(ipv4_port);
	assert_syscall_state(SYSCALL_SUCCESS, "inet_pton (server)", inet_pton(AF_INET, ipv4_string, &(sockaddr->sin_addr)), NOT_EQUAL, -1);
}

void event_test::client_fill_sockaddr_in6(struct sockaddr_in6* sockaddr, int32_t ipv6_port, const char* ipv6_string)
{
	memset(sockaddr, 0, sizeof(*sockaddr));
	sockaddr->sin6_family = AF_INET6;
	sockaddr->sin6_port = htons(ipv6_port);
	assert_syscall_state(SYSCALL_SUCCESS, "inet_pton (client)", inet_pton(AF_INET6, ipv6_string, &(sockaddr->sin6_addr)), NOT_EQUAL, -1);
}

void event_test::server_fill_sockaddr_in6(struct sockaddr_in6* sockaddr, int32_t ipv6_port, const char* ipv6_string)
{
	memset(sockaddr, 0, sizeof(*sockaddr));
	sockaddr->sin6_family = AF_INET6;
	sockaddr->sin6_port = htons(ipv6_port);
	assert_syscall_state(SYSCALL_SUCCESS, "inet_pton (server)", inet_pton(AF_INET6, ipv6_string, &(sockaddr->sin6_addr)), NOT_EQUAL, -1);
}

void event_test::client_fill_sockaddr_un(struct sockaddr_un* sockaddr, const char* unix_path)
{
	memset(sockaddr, 0, sizeof(*sockaddr));
	sockaddr->sun_family = AF_UNIX;

	strlcpy(sockaddr->sun_path, unix_path, MAX_SUN_PATH);
}

void event_test::server_fill_sockaddr_un(struct sockaddr_un* sockaddr, const char* unix_path)
{
	memset(sockaddr, 0, sizeof(*sockaddr));
	sockaddr->sun_family = AF_UNIX;

	strlcpy(sockaddr->sun_path, unix_path, MAX_SUN_PATH);
}

void event_test::connect_ipv4_client_to_server(int32_t* client_socket, struct sockaddr_in* client_sockaddr, int32_t* server_socket, struct sockaddr_in* server_sockaddr)
{
	/* Create the server socket. */
	*server_socket = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", *server_socket, NOT_EQUAL, -1);
	server_reuse_address_port(*server_socket);

	memset(server_sockaddr, 0, sizeof(*server_sockaddr));
	server_fill_sockaddr_in(server_sockaddr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, *server_socket, (struct sockaddr*)server_sockaddr, sizeof(*server_sockaddr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, *server_socket, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	*client_socket = syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", *client_socket, NOT_EQUAL, -1);
	client_reuse_address_port(*client_socket);

	memset(client_sockaddr, 0, sizeof(*client_sockaddr));
	client_fill_sockaddr_in(client_sockaddr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, *client_socket, (struct sockaddr*)client_sockaddr, sizeof(*client_sockaddr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, *client_socket, (struct sockaddr*)server_sockaddr, sizeof(*server_sockaddr)), NOT_EQUAL, -1);
}

void event_test::connect_ipv6_client_to_server(int32_t* client_socket, struct sockaddr_in6* client_sockaddr, int32_t* server_socket, struct sockaddr_in6* server_sockaddr)
{
	/* Create the server socket. */
	*server_socket = syscall(__NR_socket, AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", *server_socket, NOT_EQUAL, -1);
	server_reuse_address_port(*server_socket);

	memset(server_sockaddr, 0, sizeof(*server_sockaddr));
	server_fill_sockaddr_in6(server_sockaddr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, *server_socket, (struct sockaddr*)server_sockaddr, sizeof(*server_sockaddr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, *server_socket, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	*client_socket = syscall(__NR_socket, AF_INET6, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", *client_socket, NOT_EQUAL, -1);
	client_reuse_address_port(*client_socket);

	memset(client_sockaddr, 0, sizeof(*client_sockaddr));
	client_fill_sockaddr_in6(client_sockaddr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, *client_socket, (struct sockaddr*)client_sockaddr, sizeof(*client_sockaddr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, *client_socket, (struct sockaddr*)server_sockaddr, sizeof(*server_sockaddr)), NOT_EQUAL, -1);
}

void event_test::connect_unix_client_to_server(int32_t* client_socket, struct sockaddr_un* client_sockaddr, int32_t* server_socket, struct sockaddr_un* server_sockaddr)
{
	/* Create the server socket. */
	*server_socket = syscall(__NR_socket, AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (server)", *server_socket, NOT_EQUAL, -1);

	memset(server_sockaddr, 0, sizeof(*server_sockaddr));
	server_fill_sockaddr_un(server_sockaddr);

	/* Now we bind the server socket with the server address. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (server)", syscall(__NR_bind, *server_socket, (struct sockaddr*)server_sockaddr, sizeof(*server_sockaddr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "listen (server)", syscall(__NR_listen, *server_socket, QUEUE_LENGTH), NOT_EQUAL, -1);

	/* The server now is ready, we need to create at least one connection from the client. */

	*client_socket = syscall(__NR_socket, AF_UNIX, SOCK_STREAM, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "socket (client)", *client_socket, NOT_EQUAL, -1);

	memset(client_sockaddr, 0, sizeof(*client_sockaddr));
	client_fill_sockaddr_un(client_sockaddr);

	/* We need to bind the client socket with an address otherwise we cannot assert against it. */
	assert_syscall_state(SYSCALL_SUCCESS, "bind (client)", syscall(__NR_bind, *client_socket, (struct sockaddr*)client_sockaddr, sizeof(*client_sockaddr)), NOT_EQUAL, -1);
	assert_syscall_state(SYSCALL_SUCCESS, "connect (client)", syscall(__NR_connect, *client_socket, (struct sockaddr*)server_sockaddr, sizeof(*server_sockaddr)), NOT_EQUAL, -1);
}

/////////////////////////////////
// GENERIC EVENT ASSERTIONS
/////////////////////////////////

void event_test::assert_event_presence(pid_t pid_to_search, int event_to_search)
{
	assert_event_in_buffers(pid_to_search, event_to_search, true);
}

void event_test::assert_event_absence(pid_t pid_to_search, int event_to_search)
{
	assert_event_in_buffers(pid_to_search, event_to_search, false);
}

void event_test::assert_header()
{
	int num_params_from_bpf_table = pman_get_event_params(m_event_type);

	/* the bpf event gets the correct number of parameters from the param table. */
	ASSERT_EQ(m_event_header->nparams, num_params_from_bpf_table) << "'nparams' in the header is not correct." << std::endl;
	/* the len specified in the header matches the real event len. */
	ASSERT_EQ(m_event_header->len, m_event_len) << "'event_len' in the header is not correct." << std::endl;
}

void event_test::assert_num_params_pushed(int total_params)
{
	int num_params_from_bpf_table = pman_get_event_params(m_event_type);
	ASSERT_EQ(total_params, num_params_from_bpf_table) << "for this event we have not pushed the right number of parameters." << std::endl;
}

/////////////////////////////////
// PARAM ASSERTIONS
/////////////////////////////////

void event_test::assert_empty_param(int param_num)
{
	assert_param_boundaries(param_num);
	/* The param length must be 0. */
	assert_param_len(0);
}

void event_test::assert_only_param_len(int param_num, uint16_t expected_size)
{
	assert_param_boundaries(param_num);
	assert_param_len(expected_size);
}

template<typename T>
void event_test::assert_numeric_param(int param_num, T param, enum assertion_operators op)
{
	assert_param_boundaries(param_num);
	assert_param_len(sizeof(T));

	switch(op)
	{
	case EQUAL:
		ASSERT_EQ(*(T*)(m_event_params[m_current_param].valptr), param) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		break;

	case NOT_EQUAL:
		ASSERT_NE(*(T*)(m_event_params[m_current_param].valptr), param) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		break;

	case GREATER_EQUAL:
		ASSERT_GE(*(T*)(m_event_params[m_current_param].valptr), param) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		break;

	case LESS_EQUAL:
		ASSERT_LE(*(T*)(m_event_params[m_current_param].valptr), param) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		break;

	default:
		FAIL() << "Operation currently not supported!";
		return;
	}
}

template void event_test::assert_numeric_param<uint8_t>(int, uint8_t, enum assertion_operators);
template void event_test::assert_numeric_param<uint16_t>(int, uint16_t, enum assertion_operators);
template void event_test::assert_numeric_param<uint32_t>(int, uint32_t, enum assertion_operators);
template void event_test::assert_numeric_param<uint64_t>(int, uint64_t, enum assertion_operators);
template void event_test::assert_numeric_param<int8_t>(int, int8_t, enum assertion_operators);
template void event_test::assert_numeric_param<int16_t>(int, int16_t, enum assertion_operators);
template void event_test::assert_numeric_param<int32_t>(int, int32_t, enum assertion_operators);
template void event_test::assert_numeric_param<int64_t>(int, int64_t, enum assertion_operators);

void event_test::assert_charbuf_param(int param_num, const char* param)
{
	assert_param_boundaries(param_num);
	/* 'strlen()' does not include the terminating null byte while bpf adds it. */
	assert_param_len(strlen(param) + 1);
	/* The following assertion compares two C strings, not std::string */
	ASSERT_STREQ(m_event_params[m_current_param].valptr, param) << VALUE_NOT_CORRECT << m_current_param << std::endl;
}

void event_test::assert_charbuf_array_param(int param_num, const char** param)
{
	assert_param_boundaries(param_num);
	uint16_t total_len = 0;

	for(int index = 0; index < MAX_CHARBUF_NUM; index++)
	{
		if(param[index] == NULL)
		{
			break;
		}
		/* We can use `STREQ` because every `charbuf` is `\0` terminated. */
		ASSERT_STREQ(m_event_params[m_current_param].valptr + total_len, param[index]) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		total_len += strlen(param[index]) + 1;
	}
	assert_param_len(total_len);
}

void event_test::assert_cgroup_param(int param_num)
{
	assert_param_boundaries(param_num);
	uint16_t total_len = 0;
	/* 'cgroup_string' is composed by 'cgroup_subsytem_name' + 'cgroup_path'.
	 * Here we can assert only the 'cgroup_subsytem_name' + the presence of the '/' in the path.
	 * We call 'cgroup_prefix' this substring we have to assert.
	 */
	char cgroup_string[MAX_CGROUP_STRING_LEN];
	char cgroup_prefix[MAX_CGROUP_PREFIX_LEN];
	int prefix_len = 0;

	for(int index = 0; index < CGROUP_NUMBER; index++)
	{
		strlcpy(cgroup_string, m_event_params[m_current_param].valptr + total_len, MAX_CGROUP_STRING_LEN);
		total_len += strlen(cgroup_string) + 1;

		prefix_len = strlen(cgroup_prefix_array[index]);
		strlcpy(cgroup_prefix, cgroup_string, prefix_len + 1);
		ASSERT_STREQ(cgroup_prefix, cgroup_prefix_array[index]) << VALUE_NOT_CORRECT << m_current_param;
	}
	assert_param_len(total_len);
}

void event_test::assert_bytebuf_param(int param_num, const char* param, int buf_dimension)
{
	assert_param_boundaries(param_num);
	assert_param_len(buf_dimension);
	/* We have to use `memcmp` because we could have bytebuf with string terminator `\0` inside. */
	ASSERT_EQ(memcmp(m_event_params[m_current_param].valptr, param, buf_dimension), 0) << VALUE_NOT_CORRECT << m_current_param << std::endl;
}

void event_test::assert_addr_info_inet_param(int param_num, uint8_t desired_family, const char* desired_ipv4, const char* desired_port)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Assert ipv4. */
	assert_ipv4_string(desired_ipv4, 1);

	/* Assert port. */
	assert_port_string(desired_port, 5);

	/* Assert (family + ipv4 + port) */
	assert_param_len(FAMILY_SIZE + IPV4_SIZE + PORT_SIZE);
}

void event_test::assert_addr_info_inet6_param(int param_num, uint8_t desired_family, const char* desired_ipv6, const char* desired_port)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Assert ipv6. */
	assert_ipv6_string(desired_ipv6, 1);

	/* Assert port. */
	assert_port_string(desired_port, 17);

	/* Assert (family + ipv6 + port) */
	assert_param_len(FAMILY_SIZE + IPV6_SIZE + PORT_SIZE);
}

void event_test::assert_addr_info_unix_param(int param_num, uint8_t desired_family, const char* desired_path)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Assert unix path. */
	assert_unix_path(desired_path, 1);

	/* Assert (family + unix_path + null terminator) */
	assert_param_len(FAMILY_SIZE + strlen(desired_path) + 1);
}

void event_test::assert_tuple_inet_param(int param_num, uint8_t desired_family, const char* desired_src_ipv4, const char* desired_dest_ipv4,
					 const char* desired_src_port, const char* desired_dest_port)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Assert src ipv4. */
	assert_ipv4_string(desired_src_ipv4, 1, SOURCE);

	/* Assert src port. */
	assert_port_string(desired_src_port, 5, SOURCE);

	/* Assert dest ipv4. */
	assert_ipv4_string(desired_dest_ipv4, 7, DEST);

	/* Assert dest port. */
	assert_port_string(desired_dest_port, 11, DEST);

	/* Assert (family + ipv4_src + port_src + ipv4_dest + port_dest) */
	assert_param_len(FAMILY_SIZE + IPV4_SIZE + PORT_SIZE + IPV4_SIZE + PORT_SIZE);
}

void event_test::assert_tuple_inet6_param(int param_num, uint8_t desired_family, const char* desired_src_ipv6, const char* desired_dest_ipv6,
					  const char* desired_src_port, const char* desired_dest_port)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Assert src ipv6. */
	assert_ipv6_string(desired_src_ipv6, 1, SOURCE);

	/* Assert src port. */
	assert_port_string(desired_src_port, 17, SOURCE);

	/* Assert dest ipv6. */
	assert_ipv6_string(desired_dest_ipv6, 19, DEST);

	/* Assert dest port. */
	assert_port_string(desired_dest_port, 35, DEST);

	/* Assert (family + ipv6_src + port_src + ipv6_dest + port_dest)*/
	assert_param_len(FAMILY_SIZE + IPV6_SIZE + PORT_SIZE + IPV6_SIZE + PORT_SIZE);
}

void event_test::assert_tuple_unix_param(int param_num, uint8_t desired_family, const char* desired_path)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Here we have the two pointers:
	 * - source OS pointer.
	 * - destination OS pointer.
	 * but we cannot make assertions on that.
	 */

	/* Assert unix path. */
	assert_unix_path(desired_path, 17);

	/* Assert (family + 2 (8-byte) pointers + unix_path + null_terminator) */
	assert_param_len(FAMILY_SIZE + 8 + 8 + strlen(desired_path) + 1);
}

void event_test::assert_setsockopt_val(int param_num, int sockopt, void* option_value, int option_len)
{
	/* 1 byte for the PPM type. */
	assert_param_boundaries(param_num);
	uint16_t expected_size = 1;
	ASSERT_EQ(*(uint8_t*)(m_event_params[m_current_param].valptr), sockopt) << VALUE_NOT_CORRECT << m_current_param << std::endl;

	switch(sockopt)
	{
	case PPM_SOCKOPT_IDX_ERRNO:
		ASSERT_EQ(*(int64_t*)(m_event_params[m_current_param].valptr + 1), *(int64_t*)option_value)
			<< VALUE_NOT_CORRECT << m_current_param << std::endl;
		expected_size += 8;
		break;

	case PPM_SOCKOPT_IDX_TIMEVAL:
		ASSERT_EQ(*(uint64_t*)(m_event_params[m_current_param].valptr + 1), *(uint64_t*)option_value) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		expected_size += 8;
		break;

	case PPM_SOCKOPT_IDX_UINT64:
		ASSERT_EQ(*(uint64_t*)(m_event_params[m_current_param].valptr + 1), *(uint64_t*)option_value) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		expected_size += 8;
		break;

	case PPM_SOCKOPT_IDX_UINT32:
		ASSERT_EQ(*(uint32_t*)(m_event_params[m_current_param].valptr + 1), *(uint32_t*)option_value) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		expected_size += 4;
		break;

	case PPM_SOCKOPT_IDX_UNKNOWN:
		/* if option_len is zero we should have just the `scap` code.*/
		if(option_len == 0)
		{
			assert_param_len(expected_size);
			break;
		}
		ASSERT_EQ(*(uint32_t*)(m_event_params[m_current_param].valptr + 1), *(uint32_t*)option_value) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		expected_size += 4;
		break;
	default:
		FAIL();
		break;
	}
	assert_param_len(expected_size);
}

void event_test::assert_ptrace_addr(int param_num)
{
	assert_param_boundaries(param_num);

	/* Right now we test only the failure case.
	 * - type: `PPM_PTRACE_IDX_UINT64`
	 * - val: `0`
	 */
	assert_param_len(sizeof(uint8_t) + sizeof(uint64_t));
	ASSERT_EQ(*(uint8_t*)(m_event_params[m_current_param].valptr), PPM_PTRACE_IDX_UINT64) << VALUE_NOT_CORRECT << m_current_param << std::endl;
	ASSERT_EQ(*(uint64_t*)(m_event_params[m_current_param].valptr + 1), 0) << VALUE_NOT_CORRECT << m_current_param << std::endl;
}

void event_test::assert_ptrace_data(int param_num)
{
	assert_param_boundaries(param_num);

	/* Right now we test only the failure case.
	 * - type: `PPM_PTRACE_IDX_UINT64`
	 * - val: `0`
	 */
	assert_param_len(sizeof(uint8_t) + sizeof(uint64_t));
	ASSERT_EQ(*(uint8_t*)(m_event_params[m_current_param].valptr), PPM_PTRACE_IDX_UINT64) << VALUE_NOT_CORRECT << m_current_param << std::endl;
	ASSERT_EQ(*(uint64_t*)(m_event_params[m_current_param].valptr + 1), 0) << VALUE_NOT_CORRECT << m_current_param << std::endl;
}

/////////////////////////////////
// INTERNAL ASSERTIONS
/////////////////////////////////

void event_test::assert_param_boundaries(int param_num)
{
	m_current_param = param_num;
	ASSERT_GE(m_current_param, 1) << ">>>>> The param id '" << m_current_param << "' is to low." << std::endl;
	ASSERT_LE(m_current_param, m_event_header->nparams) << ">>>>> The param id '" << m_current_param << "' is to big." << std::endl;
}

void event_test::assert_param_len(uint16_t expected_size)
{
	uint16_t size = m_event_params[m_current_param].len;
	ASSERT_EQ(size, expected_size) << ">>>>> length of the param is not correct. Param id = " << m_current_param << std::endl;
}

void event_test::assert_address_family(uint8_t desired_family, int starting_index)
{
	uint8_t family = (uint8_t)(m_event_params[m_current_param].valptr[starting_index]);
	ASSERT_EQ(family, desired_family) << VALUE_NOT_CORRECT << m_current_param << std::endl;
}

void event_test::assert_ipv4_string(const char* desired_ipv4, int starting_index, enum direction dir)
{
	char ipv4_string[ADDRESS_LENGTH];
	if(inet_ntop(AF_INET, (uint8_t*)(m_event_params[m_current_param].valptr + starting_index), ipv4_string, ADDRESS_LENGTH) == NULL)
	{
		FAIL() << "'inet_ntop' must not fail. Param id = " << m_current_param << std::endl;
	}

	if(dir == DEST)
	{
		ASSERT_STREQ(ipv4_string, desired_ipv4) << VALUE_NOT_CORRECT << m_current_param << " (dest ipv4)" << std::endl;
	}
	else
	{
		ASSERT_STREQ(ipv4_string, desired_ipv4) << VALUE_NOT_CORRECT << m_current_param << " (source ipv4)" << std::endl;
	}
}

void event_test::assert_port_string(const char* desired_port, int starting_index, enum direction dir)
{
	uint16_t port = *(uint16_t*)(m_event_params[m_current_param].valptr + starting_index);
	const char* port_string = std::to_string(port).c_str();

	if(dir == DEST)
	{
		ASSERT_STREQ(port_string, desired_port) << VALUE_NOT_CORRECT << m_current_param << "(dest port)" << std::endl;
	}
	else
	{
		ASSERT_STREQ(port_string, desired_port) << VALUE_NOT_CORRECT << m_current_param << "(source port)" << std::endl;
	}
}

void event_test::assert_ipv6_string(const char* desired_ipv6, int starting_index, enum direction dir)
{
	char ipv6_string[ADDRESS_LENGTH];
	if(inet_ntop(AF_INET6, (uint32_t*)(m_event_params[m_current_param].valptr + starting_index), ipv6_string, ADDRESS_LENGTH) == NULL)
	{
		FAIL() << "'inet_ntop' must not fail. Param id = " << m_current_param << std::endl;
	}

	if(dir == DEST)
	{
		ASSERT_STREQ(ipv6_string, desired_ipv6) << VALUE_NOT_CORRECT << m_current_param << "(dest ipv6)" << std::endl;
	}
	else
	{
		ASSERT_STREQ(ipv6_string, desired_ipv6) << VALUE_NOT_CORRECT << m_current_param << "(source ipv6)" << std::endl;
	}
}

void event_test::assert_unix_path(const char* desired_path, int starting_index)
{
	const char* unix_path = m_event_params[m_current_param].valptr + starting_index;
	ASSERT_STREQ(unix_path, desired_path) << VALUE_NOT_CORRECT << m_current_param;
}

void event_test::assert_event_in_buffers(pid_t pid_to_search, int event_to_search, bool presence)
{
	uint16_t cpu_id = 0;
	pid_t pid = 0;
	uint16_t evt_type = 0;

	if(pid_to_search == CURRENT_PID)
	{
		pid = ::getpid();
	}
	else
	{
		pid = pid_to_search;
	}

	if(event_to_search == CURRENT_EVENT_TYPE)
	{
		evt_type = m_event_type;
	}
	else
	{
		evt_type = event_to_search;
	}

	/* We need the while loop because in the buffers there could be different events
	 * with the type we are searching for. Even if we explicitly create only one event
	 * of this type, the system could create other events of the same type during the test!
	 */
	while(true)
	{
		get_event_from_ringbuffer(&cpu_id);
		if(m_event_header == NULL)
		{
			if(presence)
			{
				FAIL() << "There is no event '" << evt_type << "' in the buffers." << std::endl;
			}
			else
			{
				break;
			}
		}
		if(m_event_header->tid == (uint64_t)pid && m_event_header->type == evt_type)
		{
			if(presence)
			{
				break;
			}
			else
			{
				FAIL() << "There is an event '" << evt_type << "' in the buffers, but it shouldn't be there" << std::endl;
			}
		}
	}
}
