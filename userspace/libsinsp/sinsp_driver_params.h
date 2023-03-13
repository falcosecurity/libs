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

#pragma once

#include "scap_open.h"
#include "sinsp_public.h"
#include "events/sinsp_events_set.h"

struct SINSP_PUBLIC sinsp_driver_params : public scap_open_args
{
	sinsp_driver_params& set_ppm_sc_of_interest(const libsinsp::events::set<ppm_sc_code> &ppm_sc_of_interest_set);
	sinsp_driver_params& set_no_events(bool f)
	{
		no_events = f;
		return *this;
	}
};
