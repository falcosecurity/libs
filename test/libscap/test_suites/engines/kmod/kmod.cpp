#include <libscap/scap.h>
#include <libscap/scap_engines.h>
#include <gtest/gtest.h>
#include <unordered_set>
#include <helpers/engines.h>
#include <libscap_test_var.h>
#include <syscall.h>
#include <fcntl.h>

int remove_kmod(char* error_buf)
{
	if(syscall(__NR_delete_module, LIBSCAP_TEST_KERNEL_MODULE_NAME, O_NONBLOCK))
	{
		switch(errno)
		{
		case ENOENT:
			return EXIT_SUCCESS;

		/* If a module has a nonzero reference count with `O_NONBLOCK` flag
		 * the call returns immediately, with `EWOULDBLOCK` code. So in that
		 * case we wait until the module is detached.
		 */
		case EWOULDBLOCK:
			for(int i = 0; i < 4; i++)
			{
				int ret = syscall(__NR_delete_module, LIBSCAP_TEST_KERNEL_MODULE_NAME, O_NONBLOCK);
				if(ret == 0 || errno == ENOENT)
				{
					return EXIT_SUCCESS;
				}
				sleep(1);
			}
			snprintf(error_buf, SCAP_LASTERR_SIZE, "could not remove the kernel module");
			return EXIT_FAILURE;

		case EBUSY:
		case EFAULT:
		case EPERM:
			snprintf(error_buf, SCAP_LASTERR_SIZE, "Unable to remove kernel module. Errno message: %s, errno: %d\n", strerror(errno), errno);
			return EXIT_FAILURE;

		default:
			snprintf(error_buf, SCAP_LASTERR_SIZE, "Unexpected error code. Errno message: %s, errno: %d\n", strerror(errno), errno);
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int insert_kmod(const char* kmod_path, char* error_buf)
{
	/* Here we want to insert the module if we fail we need to abort the program. */
	int fd = open(kmod_path, O_RDONLY);
	if(fd < 0)
	{
		snprintf(error_buf, SCAP_LASTERR_SIZE, "Unable to open the kmod file. Errno message: %s, errno: %d\n", strerror(errno), errno);
		return EXIT_FAILURE;
	}

	if(syscall(__NR_finit_module, fd, "", 0))
	{
		snprintf(error_buf, SCAP_LASTERR_SIZE, "Unable to inject the kmod. Errno message: %s, errno: %d\n", strerror(errno), errno);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

scap_t* open_kmod_engine(char* error_buf, int32_t* rc, unsigned long buffer_dim, const char* kmod_path, std::unordered_set<uint32_t> ppm_sc_set = {})
{
	struct scap_open_args oargs {};

	/* Remove previously inserted kernel module */
	if(remove_kmod(error_buf) != EXIT_SUCCESS)
	{
		return NULL;
	}

	/* Insert again the kernel module */
	if(insert_kmod(kmod_path, error_buf) != EXIT_SUCCESS)
	{
		return NULL;
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

	struct scap_kmod_engine_params kmod_params = {
		.buffer_bytes_dim = buffer_dim,
	};
	oargs.engine_params = &kmod_params;

	return scap_open(&oargs, &scap_kmod_engine, error_buf, rc);
}

TEST(kmod, open_engine)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;
	scap_close(h);
}

TEST(kmod, wrong_buffer_dim)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the buffer dimension is not a system page multiple, so we should fail: " << error_buffer << std::endl;
}

/* This check is not so reliable, better than nothing but to be sure we need to obtain the producer and consumer positions from the drivers */
TEST(kmod, events_not_overwritten)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(kmod, read_in_order)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_kmod_engine(error_buffer, &ret, 1 * 1024 * 1024, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}

TEST(kmod, scap_stats_check)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

	scap_stats stats;

	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS);
	ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS);
	ASSERT_GT(stats.n_evts, 0);
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS);
	scap_close(h);
}

TEST(kmod, double_scap_stats_call)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

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

TEST(kmod, metrics_v2_check_results)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

	uint32_t flags = METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS;
	uint32_t nstats;
	int32_t rc;
	const metrics_v2* stats_v2 = scap_get_stats_v2(h, flags, &nstats, &rc);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	ASSERT_GT(nstats, 0);

	/* These names should always be available */
	std::unordered_set<std::string> minimal_stats_name = {"n_evts"};

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

TEST(kmod, double_metrics_v2_call)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

	uint32_t flags = METRICS_V2_KERNEL_COUNTERS;
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

TEST(kmod, metrics_v2_check_empty)
{
	char error_buffer[SCAP_LASTERR_SIZE] = {0};
	int ret = 0;
	scap_t* h = open_kmod_engine(error_buffer, &ret, 4 * 4096, LIBSCAP_TEST_KERNEL_MODULE_PATH);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open kmod engine: " << error_buffer << std::endl;

	uint32_t flags = 0;
	uint32_t nstats;
	int32_t rc;
	ASSERT_TRUE(scap_get_stats_v2(h, flags, &nstats, &rc));
	ASSERT_EQ(nstats, 0);
	ASSERT_EQ(rc, SCAP_SUCCESS);
	scap_close(h);
}
