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

#include <cstdint>

#include <libsinsp/sinsp.h>

#include <libsinsp/filter_check_list.h>
#include <libsinsp/filterchecks.h>

#include <libscap/strl.h>

using namespace std;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_list implementation
///////////////////////////////////////////////////////////////////////////////

void filter_check_list::add_filter_check(std::unique_ptr<sinsp_filter_check> filter_check)
{
	// If a filtercheck already exists with this name and
	// shortdesc, don't add it--this can occur when plugins are
	// loaded and set up sinsp_filter_checks to handle plugin
	// events.

	for(const auto& chk : m_check_list)
	{
		if(chk->get_fields()->m_name == filter_check->get_fields()->m_name &&
		   chk->get_fields()->m_shortdesc == filter_check->get_fields()->m_shortdesc)
		{
			return;
		}
	}

	m_check_list.push_back(std::move(filter_check));
}

void filter_check_list::get_all_fields(std::vector<const filter_check_info*>& list) const
{
	for(const auto& chk : m_check_list)
	{
		list.push_back(chk->get_fields());
	}
}

/* Craft a new filter check from the field name */
std::unique_ptr<sinsp_filter_check> filter_check_list::new_filter_check_from_fldname(const std::string& name,
								     sinsp* inspector,
								     bool do_exact_check) const
{
	for(const auto& chk : m_check_list)
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

			auto newchk = chk->allocate_new();
			newchk->set_inspector(inspector);
			return newchk;
		}
	}

	//
	// If you are implementing a new filter check and this point is reached,
	// it's very likely that you've forgotten to add your filter to the list in
	// the constructor
	//
	return nullptr;
}

sinsp_filter_check_list::sinsp_filter_check_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW FILTER CHECK CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	add_filter_check(std::make_unique<sinsp_filter_check_gen_event>());
	add_filter_check(std::make_unique<sinsp_filter_check_event>());
	add_filter_check(std::make_unique<sinsp_filter_check_thread>());
	add_filter_check(std::make_unique<sinsp_filter_check_user>());
	add_filter_check(std::make_unique<sinsp_filter_check_group>());
	add_filter_check(std::make_unique<sinsp_filter_check_container>());
	add_filter_check(std::make_unique<sinsp_filter_check_fd>());
	add_filter_check(std::make_unique<sinsp_filter_check_fspath>());
	add_filter_check(std::make_unique<sinsp_filter_check_syslog>());
	add_filter_check(std::make_unique<sinsp_filter_check_utils>());
	add_filter_check(std::make_unique<sinsp_filter_check_fdlist>());
	add_filter_check(std::make_unique<sinsp_filter_check_k8s>());
	add_filter_check(std::make_unique<sinsp_filter_check_mesos>());
	add_filter_check(std::make_unique<sinsp_filter_check_tracer>());
	add_filter_check(std::make_unique<sinsp_filter_check_evtin>());
}
