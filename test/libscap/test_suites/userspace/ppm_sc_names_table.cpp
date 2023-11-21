#include <libscap/scap.h>
#include <gtest/gtest.h>

TEST(ppm_sc_names, scap_get_ppm_sc_name)
{
	/* First entry in the table */
	ASSERT_STREQ(scap_get_ppm_sc_name(PPM_SC_UNKNOWN), "unknown");

	/* A random entry in the middle of the table */
	ASSERT_STREQ(scap_get_ppm_sc_name(PPM_SC_UNAME), "uname");

	/* This entry should be an empty string */
	ASSERT_STREQ(scap_get_ppm_sc_name((ppm_sc_code)382), "");

	/* A random entry for a tracepoint */
	ASSERT_STREQ(scap_get_ppm_sc_name(PPM_SC_PAGE_FAULT_KERNEL), "page_fault_kernel");
	ASSERT_STREQ(scap_get_ppm_sc_name((ppm_sc_code)399), "page_fault_kernel");
}
