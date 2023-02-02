#include <scap.h>
#include <gtest/gtest.h>
#include <unordered_set>
#include <helpers/engines.h>
#include <libscap_test_var.h>

scap_t* open_bpf_engine(char* error_buf, int32_t* rc, unsigned long buffer_dim, const char* name, std::unordered_set<uint32_t> tp_set = {}, std::unordered_set<uint32_t> ppm_sc_set = {})
{
	struct scap_open_args oargs = {
		.engine_name = BPF_ENGINE,
		.mode = SCAP_MODE_LIVE,
	};

	/* If empty we fill with all tracepoints */
	if(tp_set.empty())
	{
		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			oargs.tp_of_interest.tp[i] = 1;
		}
	}
	else
	{
		for(auto tp : tp_set)
		{
			oargs.tp_of_interest.tp[tp] = 1;
		}
	}

	/* If empty we fill with all syscalls */
	if(ppm_sc_set.empty())
	{
		for(int i = 0; i < PPM_SC_MAX; i++)
		{
			oargs.ppm_sc_of_interest.ppm_sc[i] = 1;
		}
	}
	else
	{
		for(auto ppm_sc : ppm_sc_set)
		{
			oargs.ppm_sc_of_interest.ppm_sc[ppm_sc] = 1;
		}
	}

	struct scap_bpf_engine_params bpf_params = {
		.buffer_bytes_dim = buffer_dim,
		.bpf_probe = name,
	};
	oargs.engine_params = &bpf_params;

	return scap_open(&oargs, error_buf, rc);
}

TEST(bpf, open_engine)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;
	scap_close(h);
}

TEST(bpf, wrong_bpf_path)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, ".");
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the BPF path is wrong, we should fail: " << error_buffer << std::endl;
}

TEST(bpf, empty_bpf_path)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, "");
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the BPF path is wrong, we should fail: " << error_buffer << std::endl;
}

TEST(bpf, wrong_buffer_dim)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the buffer dimension is not a system page multiple, so we should fail: " << error_buffer << std::endl;
}

/* This check is not so reliable, better than nothing but to be sure we need to obtain the producer and consumer positions from the drivers */
TEST(bpf, events_not_overwritten)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(bpf, read_in_order)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}
