#include <gtest/gtest.h>
#include <sinsp.h>

/* Check that an exception is thrown since the BPF path doesn't exist, moreover
 * check that the engine name is set to BPF.
 */
TEST(ScapEngine, check_BPF_engine_name)
{
	std::unique_ptr<sinsp> inspector(new sinsp());

	std::string bpf_path_name = "NOT EXISTING";
	std::string error_message = "can't open BPF probe '" + bpf_path_name + "': No such file or directory";
	EXPECT_THROW({
		try
		{
			inspector->open_bpf(bpf_path_name);
		}
		catch(const sinsp_exception& e)
		{
			/* We cannot assert the message since it changes according to how we are building the libraries (for example MINIMAL BUILD) */
			throw;
		}
	},sinsp_exception);

	ASSERT_EQ(inspector->check_current_engine(BPF_ENGINE), true);
	ASSERT_EQ(inspector->check_current_engine(KMOD_ENGINE), false);
}
