// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <libscap/scap.h>
#include <gtest/gtest.h>

extern const syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];

/* Each syscall_id should have its own PPM_SC, note that this should be true also for generic syscalls
 * only the event type is generic, the PPM_SC code is defined! This test is architecture dependent!
 */
TEST(syscall_table, check_1_1_match_between_ppm_sc_syscall_id)
{
	std::vector<int> ppm_sc_count(PPM_SC_MAX, 0);

	for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		ppm_sc_count[g_syscall_table[syscall_nr].ppm_sc]++;
	}

	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
        if(ppm_sc != PPM_SC_UNKNOWN)
        {
		    ASSERT_TRUE(ppm_sc_count[ppm_sc] <= 1) << "[fail] SYSCALL (" << scap_get_ppm_sc_name((ppm_sc_code)ppm_sc) << ") is found '" << ppm_sc_count[ppm_sc] << "' times" << std::endl;
        }
	}
}
