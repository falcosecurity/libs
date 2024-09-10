#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_engine_util.h>
#include <gtest/gtest.h>
#include <unordered_set>
#include <helpers/engines.h>
#include <libscap_test_var.h>

scap_t* open_bpf_engine(char* error_buf,
                        int32_t* rc,
                        unsigned long buffer_dim,
                        const char* name,
                        std::unordered_set<uint32_t> ppm_sc_set = {}) {
	struct scap_open_args oargs {};

	/* If empty we fill with all syscalls */
	if(ppm_sc_set.empty()) {
		for(int i = 0; i < PPM_SC_MAX; i++) {
			oargs.ppm_sc_of_interest.ppm_sc[i] = 1;
		}
	} else {
		for(auto ppm_sc : ppm_sc_set) {
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

TEST(bpf, open_engine) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;
	scap_close(h);
}

TEST(bpf, wrong_bpf_path) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, ".");
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS)
	        << "the BPF path is wrong, we should fail: " << error_buffer << std::endl;
}

TEST(bpf, empty_bpf_path) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, "");
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS)
	        << "the BPF path is wrong, we should fail: " << error_buffer << std::endl;
}

TEST(bpf, wrong_buffer_dim) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS)
	        << "the buffer dimension is not a system page multiple, so we should fail: "
	        << error_buffer << std::endl;
}

/* This check is not so reliable, better than nothing but to be sure we need to obtain the producer
 * and consumer positions from the drivers */
TEST(bpf, events_not_overwritten) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(bpf, read_in_order) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}

TEST(bpf, scap_stats_check) {
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

	scap_stats stats;

	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS);
	ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS);
	ASSERT_GT(stats.n_evts, 0);
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS);
	scap_close(h);
}

TEST(bpf, double_scap_stats_call) {
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

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

TEST(bpf, metrics_v2_check_per_CPU_stats) {
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

	ssize_t num_possible_CPUs = num_possible_cpus();

	// Enabling `METRICS_V2_KERNEL_COUNTERS_PER_CPU` we also enable `METRICS_V2_KERNEL_COUNTERS`
	uint32_t flags = METRICS_V2_KERNEL_COUNTERS_PER_CPU;
	uint32_t nstats = 0;
	int32_t rc = 0;
	const metrics_v2* stats_v2 = scap_get_stats_v2(h, flags, &nstats, &rc);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	ASSERT_TRUE(stats_v2);
	ASSERT_GT(nstats, 0);

	uint32_t i = 0;
	ssize_t found = 0;
	char expected_name[METRIC_NAME_MAX] = "";
	snprintf(expected_name, METRIC_NAME_MAX, N_EVENTS_PER_CPU_PREFIX "%ld", found);
	bool check_general_kernel_counters_presence = false;

	while(i < nstats) {
		// We check if `METRICS_V2_KERNEL_COUNTERS` are enabled as well
		if(strncmp(stats_v2[i].name, N_EVENTS_PREFIX, sizeof(N_EVENTS_PREFIX)) == 0) {
			check_general_kernel_counters_presence = true;
			i++;
			continue;
		}

		// `sizeof(N_EVENTS_PER_CPU_PREFIX)-1` because we need to exclude the `\0`
		if(strncmp(stats_v2[i].name,
		           N_EVENTS_PER_CPU_PREFIX,
		           sizeof(N_EVENTS_PER_CPU_PREFIX) - 1) == 0) {
			i++;
			// The next metric should be the number of drops
			snprintf(expected_name, METRIC_NAME_MAX, N_DROPS_PER_CPU_PREFIX "%ld", found);
			if(strncmp(stats_v2[i].name,
			           N_DROPS_PER_CPU_PREFIX,
			           sizeof(N_DROPS_PER_CPU_PREFIX) - 1) == 0) {
				i++;
				found++;
			} else {
				FAIL() << "Missing CPU drops for CPU " << found;
			}
		} else {
			i++;
		}
	}

	ASSERT_TRUE(check_general_kernel_counters_presence)
	        << "per-CPU counter are enabled but general kernel counters are not";

	// This test could fail in case of rare race conditions in which the number of available CPUs
	// changes between the scap_open and the `num_possible_cpus` function. In CI we shouldn't have
	// hot plugs so probably we can live with this.
	ASSERT_EQ(num_possible_CPUs, found) << "We didn't find the stats for all the CPUs";
	scap_close(h);
}

TEST(bpf, metrics_v2_check_results) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

	uint32_t flags = METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS;
	uint32_t nstats;
	int32_t rc;
	const metrics_v2* stats_v2 = scap_get_stats_v2(h, flags, &nstats, &rc);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	ASSERT_GT(nstats, 0);

	/* These names should always be available */
	std::unordered_set<std::string> minimal_stats_name = {"n_evts"};
	if(scap_get_bpf_stats_enabled()) {
		minimal_stats_name.insert({"sys_enter.run_cnt",
		                           "sys_enter.run_time_ns",
		                           "sys_exit.run_cnt",
		                           "sys_exit.run_time_ns",
		                           "signal_deliver.run_cnt",
		                           "signal_deliver.run_time_ns"});
	}

	uint32_t i = 0;
	for(const auto& stat_name : minimal_stats_name) {
		for(i = 0; i < nstats; i++) {
			if(stat_name.compare(stats_v2[i].name) == 0) {
				break;
			}
		}

		if(i == nstats) {
			FAIL() << "unable to find stat '" << stat_name << "' into the array";
		}
	}

	// Check per-CPU stats are not enabled since we didn't provide the flag.
	for(i = 0; i < nstats; i++) {
		if(strncmp(stats_v2[i].name,
		           N_EVENTS_PER_CPU_PREFIX,
		           sizeof(N_EVENTS_PER_CPU_PREFIX) - 1) == 0) {
			FAIL() << "per-CPU counters are enabled but we didn't provide the flag!";
		}
	}

	scap_close(h);
}

TEST(bpf, double_metrics_v2_call) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

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

TEST(bpf, metrics_v2_check_empty) {
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_bpf_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_BPF_PROBE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS)
	        << "unable to open bpf engine: " << error_buffer << std::endl;

	uint32_t flags = 0;
	uint32_t nstats;
	int32_t rc;
	ASSERT_TRUE(scap_get_stats_v2(h, flags, &nstats, &rc));
	ASSERT_EQ(nstats, 0);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	scap_close(h);
}
