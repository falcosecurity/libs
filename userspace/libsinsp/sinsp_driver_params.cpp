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

#include "sinsp_driver_params.h"

sinsp_driver_params& sinsp_driver_params::set_ppm_sc_of_interest(const libsinsp::events::set<ppm_sc_code> &ppm_sc_of_interest_set)
{
	for (int i = 0; i < PPM_SC_MAX; i++)
	{
		/* If the set is empty, fallback to all interesting syscalls */
		if (ppm_sc_of_interest_set.empty())
		{
			ppm_sc_of_interest.ppm_sc[i] = true;
		}
		else
		{
			ppm_sc_of_interest.ppm_sc[i] = ppm_sc_of_interest_set.contains((ppm_sc_code)i);
		}
	}
	return *this;
}
