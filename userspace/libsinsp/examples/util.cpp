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

#include "util.h"
#include <sinsp.h>

//
// Get the string representation of a ppm_event_category
//
std::string get_event_category_name(ppm_event_category category)
{
	if(category == EC_UNKNOWN)
	{
		return "UNKNOWN";
	}
	else if(category & EC_OTHER)
	{
		return "OTHER";
	}
	else if(category & EC_FILE)
	{
		return "FILE";
	}
	else if(category & EC_NET)
	{
		return "NET";
	}
	else if(category & EC_IPC)
	{
		return "IPC";
	}
	else if(category & EC_MEMORY)
	{
		return "MEMORY";
	}
	else if(category & EC_PROCESS)
	{
		return "PROCESS";
	}
	else if(category & EC_SLEEP)
	{
		return "SLEEP";
	}
	else if(category & EC_SYSTEM)
	{
		return "SYSTEM";
	}
	else if(category & EC_SIGNAL)
	{
		return "SIGNAL";
	}
	else if(category & EC_USER)
	{
		return "USER";
	}
	else if(category & EC_TIME)
	{
		return "TIME";
	}
	else if(category & EC_PROCESSING)
	{
		return "PROCESSING";
	}
	else if(category & EC_IO_READ)
	{
		return "IO_READ";
	}
	else if(category & EC_IO_WRITE)
	{
		return "IO_WRITE";
	}
	else if(category & EC_IO_OTHER)
	{
		return "IO_OTHER";
	}
	else if(category & EC_WAIT)
	{
		return "WAIT";
	}
	else if(category & EC_SCHEDULER)
	{
		return "SCHEDULER";
	}
	/* This is useful because there are events that have only the INTERNAL category
	 * Categories like `EC_SYSCALL`, `EC_TRACEPOINT, `EC_PLUGIN` are always used with another
	 * category.
	 */
	else if(category & EC_INTERNAL)
	{
		return "INTERNAL";
	}
	else
	{
		return "ERROR CONDITION";
	}
}

//
// Get the string representation of a ppm_event_type
//
std::string get_event_type_name(uint16_t type)
{
	if(type < PPM_EVENT_MAX && type != PPME_GENERIC_E && type != PPME_GENERIC_X)
	{
		return g_infotables.m_event_info[type].name;
	}
	return "UNKNOWN " + to_string(type);
}
