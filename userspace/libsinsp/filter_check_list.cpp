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

#include <cstdint>

#include "sinsp.h"

#include "filter_check_list.h"
#include "filterchecks.h"

#include "strl.h"

using namespace std;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_list implementation
///////////////////////////////////////////////////////////////////////////////
filter_check_list::filter_check_list()
{
}

filter_check_list::~filter_check_list()
{
	for(auto *chk : m_check_list)
	{
		delete chk;
	}
}

void filter_check_list::add_filter_check(sinsp_filter_check* filter_check)
{
	// If a filtercheck already exists with this name and
	// shortdesc, don't add it--this can occur when plugins are
	// loaded and set up gen_event_filter_checks to handle plugin
	// events.

	for(auto *chk : m_check_list)
	{
		if(chk->m_info.m_name == filter_check->m_info.m_name &&
		   chk->m_info.m_shortdesc == filter_check->m_info.m_shortdesc)
		{
			delete filter_check;
			return;
		}
	}

	m_check_list.push_back(filter_check);
}

void filter_check_list::get_all_fields(std::vector<const filter_check_info*>& list)
{
	for(auto *chk : m_check_list)
	{
		list.push_back((const filter_check_info*)&(chk->m_info));
	}
}

/* Craft a new filter check from the field name */
sinsp_filter_check* filter_check_list::new_filter_check_from_fldname(const std::string& name,
								     sinsp* inspector,
								     bool do_exact_check)
{
	for(auto *chk : m_check_list)
	{
		chk->m_inspector = inspector;

		int32_t fldnamelen = chk->parse_field_name(name.c_str(), false, true);

		if(fldnamelen != -1)
		{
			if(do_exact_check)
			{
				if((int32_t)name.size() != fldnamelen)
				{
					break;
				}
			}

			sinsp_filter_check* newchk = chk->allocate_new();
			newchk->set_inspector(inspector);
			return newchk;
		}
	}

	//
	// If you are implementing a new filter check and this point is reached,
	// it's very likely that you've forgotten to add your filter to the list in
	// the constructor
	//
	return NULL;
}

sinsp_filter_check_list::sinsp_filter_check_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW FILTER CHECK CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	add_filter_check(new sinsp_filter_check_gen_event());
	add_filter_check(new sinsp_filter_check_event());
	add_filter_check(new sinsp_filter_check_thread());
	add_filter_check(new sinsp_filter_check_user());
	add_filter_check(new sinsp_filter_check_group());
	add_filter_check(new sinsp_filter_check_container());
	add_filter_check(new sinsp_filter_check_fd());
	add_filter_check(new sinsp_filter_check_fspath());
	add_filter_check(new sinsp_filter_check_syslog());
	add_filter_check(new sinsp_filter_check_utils());
	add_filter_check(new sinsp_filter_check_fdlist());
#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	add_filter_check(new sinsp_filter_check_k8s());
	add_filter_check(new sinsp_filter_check_mesos());
#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	add_filter_check(new sinsp_filter_check_tracer());
	add_filter_check(new sinsp_filter_check_evtin());
}

sinsp_filter_check_list::~sinsp_filter_check_list()
{
}
