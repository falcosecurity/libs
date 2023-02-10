/*
Copyright (C) 2022 The Falco Authors.

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

#include <sinsp_events.h>

std::unordered_set<ppm_tp_code> libsinsp::events::enforce_sinsp_state_tp(std::unordered_set<ppm_tp_code> tp_of_interest)
{
	std::vector<uint32_t> minimum_tracepoints(TP_VAL_MAX, 0);

	/* Should never happen but just to be sure. */
	if(scap_get_modifies_state_tracepoints(minimum_tracepoints.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("'minimum_tracepoints' is an unexpected NULL vector!");
	}

	for(int tp = 0; tp < TP_VAL_MAX; tp++)
	{
		if(minimum_tracepoints[tp])
		{
			tp_of_interest.insert((ppm_tp_code)tp);
		}
	}
	return tp_of_interest;
}

std::unordered_set<ppm_tp_code> libsinsp::events::get_all_tp()
{
	std::unordered_set<ppm_tp_code> ppm_tp_set;

	for(uint32_t tp = 0; tp < TP_VAL_MAX; tp++)
	{
		ppm_tp_set.insert((ppm_tp_code)tp);
	}

	return ppm_tp_set;
}

std::unordered_set<std::string> libsinsp::events::get_tp_names(const std::unordered_set<ppm_tp_code>& tp_set)
{
	std::unordered_set<std::string> tp_names_set;
	for(const auto& it : tp_set)
	{
		std::string tp_name = tp_names[it];
		tp_names_set.insert(tp_name);
	}
	return tp_names_set;
}
