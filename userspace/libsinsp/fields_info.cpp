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

//
// Various helper functions to render stuff on the screen
//
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <algorithm>

#include <sinsp.h>
#include "fields_info.h"

// Must match the value in the zsh tab completion
#define DESCRIPTION_TEXT_START 16


#define CONSOLE_LINE_LEN 79
#define PRINTF_WRAP_CPROC(x)  #x
#define PRINTF_WRAP(x) PRINTF_WRAP_CPROC(x)

void list_fields(bool verbose, bool markdown, bool names_only)
{
	uint32_t j, l, m;
	int32_t k;

	if(markdown && !names_only)
	{
		printf("# Filter Fields List\n\n");
	}

	vector<const filter_check_info*> fc_plugins;
	sinsp::get_filtercheck_fields_info(&fc_plugins);

	for(j = 0; j < fc_plugins.size(); j++)
	{
		const filter_check_info* fci = fc_plugins[j];

		if(fci->m_flags & filter_check_info::FL_HIDDEN)
		{
			continue;
		}

		if(!names_only)
		{
			if(markdown)
			{
				printf("## Filter Class: %s\n\n", fci->m_name.c_str());
			}
			else
			{
				printf("\n----------------------\n");
				printf("Field Class: %s\n\n", fci->m_name.c_str());
			}
		}

		for(k = 0; k < fci->m_nfields; k++)
		{
			const filtercheck_field_info* fld = &fci->m_fields[k];

			if(fld->m_flags & EPF_TABLE_ONLY)
			{
				continue;
			}

			if(names_only)
			{
				printf("%s\n", fld->m_name);
			}
			else if(markdown)
			{
				printf("**Name**: %s  \n", fld->m_name);
				printf("**Description**: %s  \n", fld->m_description);
				printf("**Type**: %s  \n\n", param_type_to_string(fld->m_type));
			}
			else
			{
				printf("%s", fld->m_name);
				uint32_t namelen = (uint32_t)strlen(fld->m_name);

				if(namelen >= DESCRIPTION_TEXT_START)
				{
					printf("\n");
					namelen = 0;
				}

				for(l = 0; l < DESCRIPTION_TEXT_START - namelen; l++)
				{
					printf(" ");
				}

				string desc(fld->m_description);

				if(fld->m_flags & EPF_FILTER_ONLY)
				{
					desc = "(FILTER ONLY) " + desc;
				}

				if(verbose)
				{
					desc += string(" Type:") + param_type_to_string(fld->m_type) + ".";
				}

				size_t desclen = desc.size();

				for(l = 0; l < desclen; l++)
				{
					if(l % (CONSOLE_LINE_LEN - DESCRIPTION_TEXT_START) == 0 && l != 0)
					{
						printf("\n");

						for(m = 0; m < DESCRIPTION_TEXT_START; m++)
						{
							printf(" ");
						}
					}

					printf("%c", desc[l]);
				}

				printf("\n");
			}
		}
	}
}

void list_events(sinsp* inspector)
{
	uint32_t j, k;
	string tstr;

	sinsp_evttables* einfo = inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;

	for(j = 0; j < PPM_EVENT_MAX; j++)
	{
		const struct ppm_event_info ei = etable[j];
		char dir = (PPME_IS_ENTER(j))? '>' : '<';

		if((ei.flags & EF_UNUSED) || (ei.flags & EF_OLD_VERSION) || (ei.category & EC_INTERNAL))
		{
			continue;
		}

		printf("%c %s(", dir, ei.name);

		for(k = 0; k < ei.nparams; k++)
		{
			if(k != 0)
			{
				printf(", ");
			}

			printf("%s %s", param_type_to_string(ei.params[k].type),
				ei.params[k].name);
		}

		printf(")\n");
	}
}