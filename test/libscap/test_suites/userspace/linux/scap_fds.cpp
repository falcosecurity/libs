#include <gtest/gtest.h>
#include <libscap/scap.h>

extern "C" {
int32_t test_time_wait_socket_at_buffer_end(void);
int32_t test_duplicate_socket_inodes(void);
}

TEST(scap_fds, buffer_overflow_test) {
	int32_t res = test_time_wait_socket_at_buffer_end();
	ASSERT_EQ(res, SCAP_SUCCESS)
	        << "Expected SCAP_SUCCESS when parsing TIME_WAIT socket at buffer end";
}

TEST(scap_fds, duplicate_socket_inodes) {
	ASSERT_EQ(test_duplicate_socket_inodes(), SCAP_SUCCESS)
	        << "Expected duplicate socket inodes to replace the existing table entry";
}
