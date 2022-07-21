#include "event_class.h"
#include <time.h>

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

	switch (op)
	{
	case EQUAL:
		match = syscall_rc == expected_rc;
		break;

	case NOT_EQUAL:
		match = syscall_rc != expected_rc;
		break;

	default:
		FAIL() << "Operation currently not supported!";
		return;
	}

	if(!match)
	{
		if(syscall_state==SYSCALL_SUCCESS)
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
	pman_mark_single_64bit_syscall_as_interesting(interesting_syscall_id);
}

void event_test::mark_all_64bit_syscalls_as_uninteresting()
{
	pman_mark_all_64bit_syscalls_as_uninteresting();
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

void event_test::assert_event_presence()
{
	uint64_t pid = ::getpid();
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
			FAIL() << "There is no event in the buffer.";
			exit(EXIT_SUCCESS);
		}
		if(m_event_header->tid == pid && m_event_header->type == m_event_type)
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

template <typename T>
void event_test::assert_numeric_param(int param_num, T param, enum assertion_operators op)
{
	assert_param_boundaries(param_num);
	assert_param_len(sizeof(T));

	switch (op)
	{
		case EQUAL:
		ASSERT_EQ(*(T*)(m_event_params[m_current_param].valptr), param) << VALUE_NOT_CORRECT << m_current_param << std::endl;
		break;

		case GREATER_EQUAL:
		ASSERT_GE(*(T*)(m_event_params[m_current_param].valptr), param) << VALUE_NOT_CORRECT << m_current_param << std::endl;

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

void event_test::assert_bytebuf_param(int param_num, const char* param, int buf_dimension)
{
	assert_param_boundaries(param_num);
	assert_param_len(buf_dimension);
	/* We have to use `memcmp` because we could have bytebuf with string terminator `\0` inside. */
	ASSERT_EQ(memcmp(m_event_params[m_current_param].valptr, param, buf_dimension), 0) << VALUE_NOT_CORRECT << m_current_param << std::endl;
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
