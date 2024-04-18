#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_engine_util.h>
#include <gtest/gtest.h>
#include <unordered_set>
#include <helpers/engines.h>
#include <libscap_test_var.h>

scap_t* open_bpf_engine(char* error_buf, int32_t* rc, unsigned long buffer_dim, const char* name, std::unordered_set<uint32_t> ppm_sc_set = {})
{
	struct scap_open_args oargs {};

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

	return scap_open(&oargs, &scap_bpf_engine, error_buf, rc);
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

TEST(bpf, scap_stats_check)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	scap_stats stats;

	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS);
	ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS);
	ASSERT_GT(stats.n_evts, 0);
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS);
	scap_close(h);
}

TEST(bpf, double_scap_stats_call)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	scap_stats stats;

	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS);

	ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS);
	ASSERT_GT(stats.n_evts, 0);

	/* Double call */
	ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS);
	ASSERT_GT(stats.n_evts, 0);

	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS);
	scap_close(h);
}

TEST(bpf, metrics_v2_check_results)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	uint32_t flags = METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS;
	uint32_t nstats;
	int32_t rc;
	const metrics_v2* stats_v2 = scap_get_stats_v2(h, flags, &nstats, &rc);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	ASSERT_GT(nstats, 0);

	/* These names should always be available */
	std::unordered_set<std::string> minimal_stats_name = {"n_evts"};
	if (scap_get_bpf_stats_enabled())
	{
		minimal_stats_name.insert({"sys_enter.run_cnt", "sys_enter.run_time_ns", "sys_exit.run_cnt", "sys_exit.run_time_ns", "signal_deliver.run_cnt", "signal_deliver.run_time_ns"});
	}
	
	uint32_t i = 0;
	for(const auto& stat_name : minimal_stats_name)
	{
		for(i = 0; i < nstats; i++)
		{
			if(stat_name.compare(stats_v2[i].name) == 0)
			{
				break;
			}
		}

		if(i == nstats)
		{
			FAIL() << "unable to find stat '" << stat_name << "' into the array";
		}
	}
	scap_close(h);
}

TEST(bpf, double_metrics_v2_call)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	uint32_t flags = METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS;
	uint32_t nstats;
	int32_t rc;
	
	scap_get_stats_v2(h, flags, &nstats, &rc);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	ASSERT_GT(nstats, 0);

	/* Double call */
	scap_get_stats_v2(h, flags, &nstats, &rc);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	ASSERT_GT(nstats, 0);

	scap_close(h);
}

TEST(bpf, metrics_v2_check_empty)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open bpf engine: " << error_buffer << std::endl;

	uint32_t flags = 0;
	uint32_t nstats;
	int32_t rc;
	ASSERT_TRUE(scap_get_stats_v2(h, flags, &nstats, &rc));
	ASSERT_EQ(nstats, 0);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	scap_close(h);
}
