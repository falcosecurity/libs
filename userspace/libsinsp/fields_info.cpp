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
#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <algorithm>

#include <sinsp.h>
#include "fields_info.h"

static void list_fields_markdown(std::list<gen_event_filter_factory::filter_fieldclass_info> &fld_classes)
{
	for(auto &fld_class : fld_classes)
	{
		printf("\n## Field Class: %s\n\n", fld_class.name.c_str());
		printf("%s\n\n", fld_class.desc.c_str());
		printf("Name | Type | Description\n");
		printf(":----|:-----|:-----------\n");

		for(auto &fld_info : fld_class.fields)
		{
			// Skip fields with the EPF_TABLE_ONLY flag.
			if(fld_info.is_skippable())
			{
				continue;
			}

			printf("`%s` | %s | %s\n", fld_info.name.c_str(), fld_info.data_type.c_str(), fld_info.desc.c_str());
		}
	}
}

void list_fields(bool verbose, bool markdown)
{
	vector<const filter_check_info*> fc_plugins;
	std::list<gen_event_filter_factory::filter_fieldclass_info> fld_classes;

	sinsp::get_filtercheck_fields_info(fc_plugins);

	fld_classes = sinsp_filter_factory::check_infos_to_fieldclass_infos(fc_plugins);

	if(markdown)
	{
		list_fields_markdown(fld_classes);
	}
	else
	{
		for(auto &fld_class : fld_classes)
		{
			printf("%s\n", fld_class.as_string(verbose).c_str());
		}
	}
}

void list_events(sinsp* inspector, bool markdown)
{
	uint32_t j, k;
	string tstr;

	sinsp_evttables* einfo = inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;

	if(markdown)
	{
		printf("Falco | Dir | Event\n");
		printf(":-----|:----|:-----\n");
	}

	for(j = 0; j < PPM_EVENT_MAX; j++)
	{
		const struct ppm_event_info ei = etable[j];
		char dir = (PPME_IS_ENTER(j))? '>' : '<';

		if((ei.flags & EF_UNUSED) || (ei.flags & EF_OLD_VERSION) || (ei.category & EC_INTERNAL))
		{
			continue;
		}

		if(markdown)
		{
			if(sinsp::is_unused_event(j) || sinsp::is_old_version_event(j))
			{
				printf("No");
			}
			else
			{
				printf("Yes");
			}

			printf(" | %c | **%s**(", dir, ei.name);

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
		} else
		{
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
}
