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
#include <sys/syscall.h>

extern const syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];

TEST(scap_ppm_sc, scap_get_modifies_state_ppm_sc)
{
	/* Failure case */
	ASSERT_EQ(scap_get_modifies_state_ppm_sc(NULL), SCAP_FAILURE);

	uint8_t ppm_sc_array[PPM_SC_MAX] = {0};
	ASSERT_EQ(scap_get_modifies_state_ppm_sc(ppm_sc_array), SCAP_SUCCESS);

	/* All UNEVER_DROP syscalls */
	for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if(g_syscall_table[syscall_nr].flags & UF_NEVER_DROP)
		{
			ASSERT_TRUE(ppm_sc_array[g_syscall_table[syscall_nr].ppm_sc]);
		}
	}

	/* Events that have EF_MODIFIES_STATE and are tracepoint or syscalls */
	for(int event_nr = 0; event_nr < PPM_EVENT_MAX; event_nr++)
	{
		if(((scap_get_event_info_table()[event_nr].flags & EF_MODIFIES_STATE) == 0) ||
		   ((scap_get_event_info_table()[event_nr].category & EC_SYSCALL) == 0 && (scap_get_event_info_table()[event_nr].category & EC_TRACEPOINT) == 0))
		{
			continue;
		}

		uint8_t ppm_sc_array_int[PPM_SC_MAX] = {0};
		uint8_t events_array_int[PPM_EVENT_MAX] = {0};
		events_array_int[event_nr] = 1;
		ASSERT_EQ(scap_get_ppm_sc_from_events(events_array_int, ppm_sc_array_int), SCAP_SUCCESS);
		for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
		{
			if(ppm_sc_array_int[ppm_sc])
			{
				ASSERT_TRUE(ppm_sc_array[ppm_sc]);
			}
		}
	}
}

/* This check tries to check the correspondence between the `g_events_to_sc_map` and the `syscall_table`
 * when the architecture allows it (in the syscall_table we have ifdefs)
 */
TEST(scap_ppm_sc, scap_get_events_from_ppm_sc)
{
	{
		/* Failure cases */
		uint8_t ppm_sc_array[PPM_SC_MAX] = {0};
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		ASSERT_EQ(scap_get_events_from_ppm_sc(NULL, events_array), SCAP_FAILURE);
		ASSERT_EQ(scap_get_events_from_ppm_sc(ppm_sc_array, NULL), SCAP_FAILURE);
		ASSERT_EQ(scap_get_events_from_ppm_sc(NULL, NULL), SCAP_FAILURE);

		/* Check memset */
		for(int i = 0; i < PPM_EVENT_MAX; i++)
		{
			events_array[i] = 1;
		}
		ASSERT_EQ(scap_get_events_from_ppm_sc(ppm_sc_array, events_array), SCAP_SUCCESS);
		for(int i = 0; i < PPM_EVENT_MAX; i++)
		{
			ASSERT_FALSE(events_array[i]);
		}
	}

	/* Best effort checks, we have ifdefs in the syscall_table.
	 * We need to skip PPM_SC_UNKNOWN since it is no more associated with any event with the new implementation.
	 */
	for(int ppm_sc = 1; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		uint8_t ppm_sc_array[PPM_SC_MAX] = {0};
		ppm_sc_array[ppm_sc] = 1;
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		ASSERT_EQ(scap_get_events_from_ppm_sc(ppm_sc_array, events_array), SCAP_SUCCESS);
		for(int sys_id = 0; sys_id < SYSCALL_TABLE_SIZE; sys_id++)
		{
			syscall_evt_pair pair = g_syscall_table[sys_id];
			if(pair.ppm_sc == ppm_sc)
			{
				ASSERT_TRUE(events_array[pair.enter_event_type]) << "ppm_sc: " << scap_get_ppm_sc_name((ppm_sc_code)pair.ppm_sc) << " (" << pair.ppm_sc << ") should be associated with event: " << pair.enter_event_type << std::endl;
				ASSERT_TRUE(events_array[pair.exit_event_type]) << "ppm_sc: " << scap_get_ppm_sc_name((ppm_sc_code)pair.ppm_sc) << " (" << pair.ppm_sc << ") should be associated with event: " << pair.exit_event_type << std::endl;
			}
		}
	}
}

/* This check tries to check the correspondence between the `g_events_to_sc_map` and the `syscall_table`
 * when the architecture allows it (in the syscall_table we have ifdefs)
 */
TEST(scap_ppm_sc, scap_get_ppm_sc_from_events)
{
	{
		/* Failure cases */
		uint8_t ppm_sc_array[PPM_SC_MAX] = {0};
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		ASSERT_EQ(scap_get_ppm_sc_from_events(NULL, ppm_sc_array), SCAP_FAILURE);
		ASSERT_EQ(scap_get_ppm_sc_from_events(events_array, NULL), SCAP_FAILURE);
		ASSERT_EQ(scap_get_ppm_sc_from_events(NULL, NULL), SCAP_FAILURE);

		/* Check memset */
		for(int i = 0; i < PPM_SC_MAX; i++)
		{
			ppm_sc_array[i] = 1;
		}
		ASSERT_EQ(scap_get_ppm_sc_from_events(events_array, ppm_sc_array), SCAP_SUCCESS);
		for(int i = 0; i < PPM_SC_MAX; i++)
		{
			ASSERT_FALSE(ppm_sc_array[i]);
		}
	}

	/* Best effort checks, we have ifdefs in the syscall_table.
	 */
	for(int evt_id = 1; evt_id < PPM_EVENT_MAX; evt_id++)
	{
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		events_array[evt_id] = 1;
		uint8_t ppm_sc_array[PPM_SC_MAX] = {0};
		ASSERT_EQ(scap_get_ppm_sc_from_events(events_array, ppm_sc_array), SCAP_SUCCESS);
		for(int sys_id = 0; sys_id < SYSCALL_TABLE_SIZE; sys_id++)
		{
			syscall_evt_pair pair = g_syscall_table[sys_id];
			if(pair.enter_event_type == evt_id || pair.exit_event_type == evt_id)
			{
				ASSERT_TRUE(ppm_sc_array[pair.ppm_sc]) << "event: " << scap_get_event_info_table()[evt_id].name << " (" << evt_id << ") should be associated with ppm_sc: " << pair.ppm_sc << std::endl;
			}
		}
	}
}

TEST(scap_ppm_sc, scap_ppm_sc_from_name)
{
	ASSERT_EQ(scap_ppm_sc_from_name(NULL), -1);
	ASSERT_EQ(scap_ppm_sc_from_name(""), -1);
	ASSERT_EQ(scap_ppm_sc_from_name(" "), -1);
	ASSERT_EQ(scap_ppm_sc_from_name("_"), -1);
	ASSERT_EQ(scap_ppm_sc_from_name("_______"), -1);
	ASSERT_EQ(scap_ppm_sc_from_name("ALARM"), -1);
	ASSERT_EQ(scap_ppm_sc_from_name(" alarm"), -1);
	ASSERT_EQ(scap_ppm_sc_from_name(" alarm "), -1);
	ASSERT_EQ(scap_ppm_sc_from_name("alarm "), -1);
	ASSERT_EQ(scap_ppm_sc_from_name("alarm"), PPM_SC_ALARM);
}

TEST(scap_ppm_sc, scap_native_id_to_ppm_sc)
{
	ASSERT_EQ(scap_native_id_to_ppm_sc(80000000), PPM_SC_UNKNOWN);
	ASSERT_EQ(scap_native_id_to_ppm_sc(-12), PPM_SC_UNKNOWN);
	ASSERT_EQ(scap_native_id_to_ppm_sc(SYSCALL_TABLE_SIZE), PPM_SC_UNKNOWN);
#ifdef __NR_read
	ASSERT_EQ(scap_native_id_to_ppm_sc(__NR_read), PPM_SC_READ);
#endif
#ifdef __NR_clone
	ASSERT_EQ(scap_native_id_to_ppm_sc(__NR_clone), PPM_SC_CLONE);
#endif
	ASSERT_EQ(scap_native_id_to_ppm_sc(511), PPM_SC_UNKNOWN);
}
