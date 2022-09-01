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

#include <stdio.h>

#include "scap.h"
#include "scap-int.h"
#include "scap_engine_util.h"

#ifdef __linux__
#include "driver_config.h"
#endif

int32_t check_api_compatibility(scap_t *handle, char *error)
{
#ifdef PPM_API_CURRENT_VERSION_MAJOR
	if(!scap_is_api_compatible(handle->m_api_version, SCAP_MINIMUM_DRIVER_API_VERSION))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Driver supports API version %llu.%llu.%llu, but running version needs %llu.%llu.%llu",
			 PPM_API_VERSION_MAJOR(handle->m_api_version),
			 PPM_API_VERSION_MINOR(handle->m_api_version),
			 PPM_API_VERSION_PATCH(handle->m_api_version),
			 PPM_API_VERSION_MAJOR(SCAP_MINIMUM_DRIVER_API_VERSION),
			 PPM_API_VERSION_MINOR(SCAP_MINIMUM_DRIVER_API_VERSION),
			 PPM_API_VERSION_PATCH(SCAP_MINIMUM_DRIVER_API_VERSION));
		return SCAP_FAILURE;
	}

	if(!scap_is_api_compatible(handle->m_schema_version, SCAP_MINIMUM_DRIVER_SCHEMA_VERSION))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Driver supports schema version %llu.%llu.%llu, but running version needs %llu.%llu.%llu",
			 PPM_API_VERSION_MAJOR(handle->m_schema_version),
			 PPM_API_VERSION_MINOR(handle->m_schema_version),
			 PPM_API_VERSION_PATCH(handle->m_schema_version),
			 PPM_API_VERSION_MAJOR(SCAP_MINIMUM_DRIVER_SCHEMA_VERSION),
			 PPM_API_VERSION_MINOR(SCAP_MINIMUM_DRIVER_SCHEMA_VERSION),
			 PPM_API_VERSION_PATCH(SCAP_MINIMUM_DRIVER_SCHEMA_VERSION));
		return SCAP_FAILURE;
	}
#endif
	return SCAP_SUCCESS;
}
