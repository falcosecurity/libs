#include <gtest.h>

extern "C"
{
#include "test_fillers.h"
}

TEST(test_run_approach, basic)
{
	int err;
	__u32 retval;
	struct filler_data data;
	std::string filler_name = "bpf_sys_renameat2_x";
	err = do_test_single_filler(&retval, filler_name.c_str(), data);
	ASSERT_EQ(retval, 0);
	ASSERT_EQ(err, 0);
}
