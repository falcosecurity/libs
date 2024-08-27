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

#include <helpers/scap_file_helpers.h>

namespace scap_file_test_helpers
{

sinsp_evt* capture_search_evt_by_num(sinsp* inspector, uint64_t evt_num)
{
	sinsp_evt* evt;
	int ret = SCAP_SUCCESS;
	while(ret != SCAP_EOF)
	{
		ret = inspector->next(&evt);
		if(ret == SCAP_SUCCESS && evt->get_num() == evt_num)
		{
			return evt;
		}
	}
	return NULL;
}

sinsp_evt* capture_search_evt_by_type_and_tid(sinsp* inspector, uint64_t type, int64_t tid)
{
	sinsp_evt* evt;
	int ret = SCAP_SUCCESS;
	while(ret != SCAP_EOF)
	{
		ret = inspector->next(&evt);
		if(ret == SCAP_SUCCESS && evt->get_type() == type && evt->get_tid() == tid)
		{
			return evt;
		}
	}
	return NULL;
}

} // namespace scap_file_test_helpers
