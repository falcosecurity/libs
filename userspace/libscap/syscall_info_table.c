/*
Copyright (C) 2021 The Falco Authors.

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

#include "../common/types.h"
#include "../../driver/ppm_events_public.h"
#include "scap.h"
#include "scap-int.h"
#include "strlcpy.h"
#include <ctype.h>

/*
 * SYSCALL INFO TABLE
 */
static struct ppm_syscall_desc g_syscall_info_table[PPM_SC_MAX];

static void load_syscall_info_table() {
	const char *sc_names[PPM_SC_MAX] = {
#define PPM_SC_X(name, value) [value] = #name,
		PPM_SC_FIELDS
#undef PPM_SC_X
	};

	int i;
	for (i = 0; i < PPM_SC_MAX; i++)
	{
		if (!sc_names[i])
		{
			continue;
		}

		strlcpy(g_syscall_info_table[i].name, sc_names[i], PPM_MAX_NAME_LEN);
		// tolower on name string
		char *p = g_syscall_info_table[i].name;
		for (; *p; ++p)
		{
			*p = tolower(*p);
		}

		g_syscall_info_table[i].category = EC_UNKNOWN;
	}
}

//
// Get the syscall info table
//
const struct ppm_syscall_desc* scap_get_syscall_info_table()
{
	// Lazy load syscall info table
	if (g_syscall_info_table[0].name[0] == 0) {
		load_syscall_info_table();
	}
	return g_syscall_info_table;
}
