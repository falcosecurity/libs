#include "sinsp_suppress.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <algorithm>

struct test_case {
	std::string name;
	std::vector<std::string> suppressed_comms;
	std::vector<std::tuple<uint64_t /*tid*/, uint64_t /*parent_tid*/, std::string /*comm*/>>
	        entries;
	std::vector<uint64_t> expected_suppressed_tids;
};

class suppressed_comm_test : public ::testing::TestWithParam<test_case> {};

TEST_P(suppressed_comm_test, check_suppressed_comm) {
	auto test_case = GetParam();
	libsinsp::sinsp_suppress suppressor;

	for(const auto& comm : test_case.suppressed_comms) {
		// Suppress each comm in the test case
		suppressor.suppress_comm(comm);
	}

	// Initialize the suppressor, e.g. a simulate a proc scan
	suppressor.initialize();

	for(const auto& entry : test_case.entries) {
		// Handle each thread entry
		suppressor.check_suppressed_comm(std::get<0>(entry),
		                                 std::get<1>(entry),
		                                 std::get<2>(entry));
	}

	// Finalize the suppressor, e.g. to clean up or finalize the proc scan
	suppressor.finalize();

	// Check the number of suppressed tids
	EXPECT_EQ(suppressor.get_num_suppressed_tids(), test_case.expected_suppressed_tids.size());

	// Check if the expected suppressed tids are recognized
	for(const auto& expected_tid : test_case.expected_suppressed_tids) {
		EXPECT_TRUE(suppressor.is_suppressed_tid(expected_tid))
		        << "Expected tid " << expected_tid << " to be suppressed.";
	}
}

INSTANTIATE_TEST_CASE_P(suppressed_comm_tests,
                        suppressed_comm_test,
                        ::testing::ValuesIn(std::vector<test_case>{
                                {"single suppressed comm",
                                 {"suppress_me"},
                                 {
                                         {1, 0, "systemd"},
                                         {2, 1, "suppress_me"},
                                         {3, 1, "other_comm"},
                                 },
                                 {2}},
                                {"multiple suppressed comms",
                                 {"suppress_me", "ignore_me"},
                                 {
                                         {1, 0, "systemd"},
                                         {2, 1, "suppress_me"},
                                         {3, 1, "ignore_me"},
                                         {4, 1, "other_comm"},
                                 },
                                 {2, 3}},
                                {"hierarchical suppressed comms",
                                 {"suppress_me"},
                                 {
                                         {1, 0, "systemd"},
                                         {2, 1, "suppress_me"},
                                         {3, 2, "child_suppress"},
                                         {4, 1, "other_comm"},
                                 },
                                 {2, 3}},
                                {"out of order hierarchical suppressed comms",
                                 {"suppress_me"},
                                 {
                                         {1, 0, "systemd"},
                                         {3, 2, "other_comm"},  // child is scanned befor his parent
                                         {2, 1, "suppress_me"},
                                         {4, 1, "another_comm"},
                                         {3, 1, "another_comm"},
                                 },
                                 {3, 2}},
                                {"child of o child of a suppressed",
                                 {"suppress_me", "destroy_me"},
                                 {{1, 0, "systemd"},
                                  {100, 10, "a_child_to_suppress"},
                                  {200, 20, "another_child_to_suppress"},

                                  {1000, 100, "a_nephew_to_be_suppressed"},
                                  {2000, 200, "another_nephew_to_be_suppressed"},

                                  {10, 1, "suppress_me"},
                                  {20, 1, "destroy_me"},

                                  {1010, 1, "im_fine"}},
                                 {100, 200, 1000, 2000, 10, 20}},
                        }),
                        [](testing::TestParamInfo<test_case> info) {
	                        // replace space with underscore for test name
	                        std::string name = info.param.name;
	                        std::replace(name.begin(), name.end(), ' ', '_');
	                        return name;
                        });
