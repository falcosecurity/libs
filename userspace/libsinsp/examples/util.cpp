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

#include "util.h"
#include <libsinsp/sinsp.h>

//
// Get the string representation of a ppm_event_category
//
std::string get_event_category_name(ppm_event_category category)
{
    switch(category)
    {
        case EC_UNKNOWN: return "UNKNOWN";
        case EC_OTHER: return "OTHER";
        case EC_FILE: return "FILE";
        case EC_NET: return "NET";
        case EC_IPC: return "IPC";
        case EC_MEMORY: return "MEMORY";
        case EC_PROCESS: return "PROCESS";
        case EC_SLEEP: return "SLEEP";
        case EC_SYSTEM: return "SYSTEM";
        case EC_SIGNAL: return "SIGNAL";
        case EC_USER: return "USER";
        case EC_TIME: return "TIME";
        case EC_PROCESSING: return "PROCESSING";
        case EC_IO_READ: return "IO_READ";
        case EC_IO_WRITE: return "IO_WRITE";
        case EC_IO_OTHER: return "IO_OTHER";
        case EC_WAIT: return "WAIT";
        case EC_SCHEDULER: return "SCHEDULER";
        case EC_INTERNAL: return "INTERNAL";
        default: return "ERROR CONDITION";
    };
}

//
// Get the string representation of a ppm_event_type
//
std::string get_event_type_name(sinsp_evt *ev)
{
	uint16_t type = ev->get_type();
	if (type >= PPM_EVENT_MAX)
	{
		return "UNKNOWN " + std::to_string(type);
	}
	if (type != PPME_GENERIC_E && type != PPME_GENERIC_X)
	{
		return scap_get_event_info_table()[type].name;
	}

	uint16_t ppm_sc = ev->get_param(0)->as<uint16_t>();
	return scap_get_ppm_sc_name((ppm_sc_code)ppm_sc);
}
