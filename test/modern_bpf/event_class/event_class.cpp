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

event_test::event_test(int syscall_id, int event_direction)
{
	if(event_direction == ENTER_EVENT)
	{
		m_event_type = g_syscall_table[syscall_id].enter_event_type;
	}
	else
	{
		m_event_type = g_syscall_table[syscall_id].exit_event_type;
	}

	m_current_param = 0;

	/*
	 * Cleaning phase.
	 */

	/* 1 - disable the capture of all events. */
	pman_disable_capture();

	/* 2 - clean all the ring_buffers until they are empty. */
	clear_ring_buffers();

	/* 3 - clean all interesting syscalls. */
	mark_all_64bit_syscalls_as_uninteresting();

	/* 4 - set the current as the only interesting syscall. */
	mark_single_64bit_syscall_as_interesting(syscall_id);

	/* 5 - detach all bpf programs attached to the kernel a part from syscall dispatchers. */
	/* Right now we don't have BPF programs to detach here ...*/
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
	pman_enable_capture();
}

void event_test::disable_capture()
{
	pman_disable_capture();
}

void event_test::clear_ring_buffers()
{
	int consume_ret = 1;
	uint16_t cpu_id = 0;
	void* event = NULL;
	while(consume_ret != -1)
	{
		consume_ret = pman_consume_one_from_buffers(&event, &cpu_id);
	}
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
// GENERIC EVENT ASSERTIONS
/////////////////////////////////

void event_test::assert_event_presence(pid_t desired_pid)
{
	pid_t pid = ::getpid();
	if(desired_pid != CURRENT_PID)
	{
		pid = desired_pid;
	}
	int consume_ret = 0;
	uint16_t cpu_id = 0;

	/* We need the while loop because in the buffers there could be different events
	 * with the type we are searching for. Even if we explicitly create only one event
	 * of this type, the system could create other events of the same type during the test!
	 */
	while(true)
	{
		consume_ret = pman_consume_one_from_buffers((void**)&m_event_header, &cpu_id);
		if(consume_ret == -1 || m_event_header == NULL)
		{
			FAIL() << "There is no event in the buffer." << std::endl;
		}
		if(m_event_header->tid == (uint64_t)pid && m_event_header->type == m_event_type)
		{
			break;
		}
	}
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
		/* 'strcpy()' takes also the '\0'. */
		strcpy(cgroup_string, m_event_params[m_current_param].valptr + total_len);
		/* 'strlen()' does not include the terminating null byte '\0'. */
		total_len += strlen(cgroup_string) + 1;
		prefix_len = strlen(cgroup_prefix_array[index]);
		strncpy(cgroup_prefix, cgroup_string, prefix_len);
		/* add the NULL terminator.
		 * Pay attention to buffer overflow if you change the `MAX_CGROUP_PREFIX_LEN`.
		 */
		cgroup_prefix[prefix_len] = '\0';
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

	/* Assert dest ipv4. */
	assert_ipv4_string(desired_dest_ipv4, 5, DEST);

	/* Assert src port. */
	assert_port_string(desired_src_port, 9, SOURCE);

	/* Assert dest port. */
	assert_port_string(desired_dest_port, 11, DEST);

	/* Assert (family + ipv4_src + ipv4_dest + port_src + port_dest) */
	assert_param_len(FAMILY_SIZE + IPV4_SIZE + IPV4_SIZE + PORT_SIZE + PORT_SIZE);
}

void event_test::assert_tuple_inet6_param(int param_num, uint8_t desired_family, const char* desired_src_ipv6, const char* desired_dest_ipv6,
					  const char* desired_src_port, const char* desired_dest_port)
{
	assert_param_boundaries(param_num);

	/* Assert family. */
	assert_address_family(desired_family, 0);

	/* Assert src ipv6. */
	assert_ipv6_string(desired_src_ipv6, 1, SOURCE);

	/* Assert dest ipv6. */
	assert_ipv6_string(desired_dest_ipv6, 17, DEST);

	/* Assert src port. */
	assert_port_string(desired_src_port, 33, SOURCE);

	/* Assert dest port. */
	assert_port_string(desired_dest_port, 35, DEST);

	/* Assert (family + ipv6_src + ipv6_dest + port_src + port_dest)*/
	assert_param_len(FAMILY_SIZE + IPV6_SIZE + IPV6_SIZE + PORT_SIZE + PORT_SIZE);
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
