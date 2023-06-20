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

#include "scap_platform_impl.h"
#include "scap_platform.h"

#include "scap.h"
#include "scap-int.h"

static int32_t scap_generic_init_platform(struct scap_platform* platform, char* lasterr, struct scap_open_args* oargs)
{
	return SCAP_SUCCESS;
}

static int32_t scap_generic_close_platform(struct scap_platform* platform)
{
	return SCAP_SUCCESS;
}

static void scap_generic_free_platform(struct scap_platform* platform)
{
	free(platform);
}

struct scap_platform_vtable scap_generic_platform_vtable = {
	.init_platform = NULL,
	.close_platform = NULL,
	.free_platform = scap_generic_free_platform,
};

struct scap_platform* scap_generic_alloc_platform()
{
	struct scap_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	platform->m_vtable = &scap_generic_platform_vtable;
	return platform;
}

int32_t scap_platform_init(struct scap_platform *platform, char *lasterr, struct scap_engine_handle engine,
			   struct scap_open_args *oargs)
{
	int32_t rc;

	if(!platform)
	{
		return SCAP_SUCCESS;
	}

	rc = scap_generic_init_platform(platform, lasterr, oargs);
	if(rc != SCAP_SUCCESS)
	{
		scap_platform_close(platform);
		return rc;
	}

	if(platform->m_vtable && platform->m_vtable->init_platform)
	{
		rc = platform->m_vtable->init_platform(platform, lasterr, engine, oargs);
		if(rc != SCAP_SUCCESS)
		{
			scap_platform_close(platform);
		}
		return rc;
	}
	else
	{
		return SCAP_SUCCESS;
	}
}

int32_t scap_platform_close(struct scap_platform* platform)
{
	int32_t rc;

	if(!platform)
	{
		return SCAP_SUCCESS;
	}

	rc = scap_generic_close_platform(platform);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	if(platform->m_vtable && platform->m_vtable->close_platform)
	{
		return platform->m_vtable->close_platform(platform);
	}
	else
	{
		return SCAP_SUCCESS;
	}
}

void scap_platform_free(struct scap_platform* platform)
{
	if(!platform)
	{
		return;
	}

	platform->m_vtable->free_platform(platform);
}
