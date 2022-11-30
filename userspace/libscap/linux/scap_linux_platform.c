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

#include "scap_linux_platform.h"

#include "scap.h"
#include "scap-int.h"
#include "scap_linux_int.h"

#include <stdlib.h>

static int32_t scap_linux_close_platform(struct scap_platform* platform)
{
	return SCAP_SUCCESS;
}

static void scap_linux_free_platform(struct scap_platform* platform)
{
	free(platform);
}

int32_t scap_linux_early_init_platform(struct scap_platform* platform, char* lasterr, struct scap_open_args* oargs)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_lasterr = lasterr;

	return SCAP_SUCCESS;
}

int32_t scap_linux_init_platform(struct scap_platform* platform, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;

	rc = scap_linux_create_iflist(platform);
	if(rc != SCAP_SUCCESS)
	{
		scap_linux_free_platform(platform);
		return rc;
	}

	return SCAP_SUCCESS;
}

static const struct scap_platform_vtable scap_linux_platform = {
	.early_init_platform = scap_linux_early_init_platform,
	.init_platform = scap_linux_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.close_platform = scap_linux_close_platform,
	.free_platform = scap_linux_free_platform,
};

struct scap_platform* scap_linux_alloc_platform()
{
	struct scap_linux_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_linux_platform;

	return generic;
}
