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

#include <driver/ppm_events_public.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/strl.h>
#include <ctype.h>

/*
 * PPM_SC_NAMES
 * This table should be used only to obtain the name of the syscall when we have
 * generic events.
 */
/// TODO: the syscall bumper could generate directly a table like:
//
// static const char* g_ppm_sc_names[PPM_SC_MAX] = {
//   [PPM_SC], "name",
// };
//
// Without doing it at runtime, avoiding the lazy load! This approach
// would be clearer now that we have empty string names

static char g_ppm_sc_names[PPM_SC_MAX][PPM_MAX_NAME_LEN];

static void load_ppm_sc_table()
{
	const char *sc_names[PPM_SC_MAX] = {
#define PPM_SC_X(name, value) [value] = #name,
		PPM_SC_FIELDS
#undef PPM_SC_X
	};

	/* Use `tolower` to obtain lowe case names. */
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(!sc_names[i])
		{
			continue;
		}

		strlcpy(g_ppm_sc_names[i], sc_names[i], PPM_MAX_NAME_LEN);
		char *p = g_ppm_sc_names[i];
		for(; *p; ++p)
		{
			*p = tolower(*p);
		}
	}
}

/* Get the name of the sc_code */
const char *scap_get_ppm_sc_name(ppm_sc_code sc)
{
	/* We avoid the check for perf reasons */
	ASSERT(sc >= 0 && sc < PPM_SC_MAX);

	/* Lazy loading */
	if(g_ppm_sc_names[0][0] == '\0')
	{
		load_ppm_sc_table();
	}
	return g_ppm_sc_names[sc];
}
