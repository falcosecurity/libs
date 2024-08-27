/*
Copyright (C) 2024 The Falco Authors.

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

#include <libscap/linux/scap_linux_platform.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/scap_machine_info.h>
#include <libscap/linux/scap_linux_int.h>

#include <stdlib.h>
#include <unistd.h>

static void scap_linux_hostinfo_free_platform(struct scap_platform* platform)
{
	free(platform);
}

int32_t scap_linux_hostinfo_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;

	if(scap_os_get_machine_info(&platform->m_machine_info, lasterr) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	scap_os_get_agent_info(&platform->m_agent_info);

	rc = scap_linux_create_iflist(platform);
	if(rc != SCAP_SUCCESS)
	{
		scap_linux_hostinfo_free_platform(platform);
		return rc;
	}

	return SCAP_SUCCESS;
}

static const struct scap_platform_vtable scap_linux_hostinfo_platform_vtable = {
	.init_platform = scap_linux_hostinfo_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.free_platform = scap_linux_hostinfo_free_platform,
};

struct scap_platform* scap_linux_hostinfo_alloc_platform()
{
	struct scap_linux_platform* platform = calloc(1, sizeof(*platform));

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_linux_hostinfo_platform_vtable;

	return generic;
}
