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

#include <libscap/scap_api_version.h>
#include <libscap/scap.h>
#include <libscap/scap_engine_util.h>
#include <libscap/scap_vtable.h>
#include <libscap/strerror.h>


bool scap_apply_semver_check(uint32_t current_major, uint32_t current_minor, uint32_t current_patch,
			     uint32_t required_major, uint32_t required_minor, uint32_t required_patch)
{
	if(current_major != required_major)
	{
		return false;
	}

	if(current_minor < required_minor)
	{
		return false;
	}
	if(current_minor == required_minor && current_patch < required_patch)
	{
		return false;
	}

	return true;
}

bool scap_is_api_compatible(unsigned long driver_api_version, unsigned long required_api_version)
{
	unsigned long driver_major = PPM_API_VERSION_MAJOR(driver_api_version);
	unsigned long driver_minor = PPM_API_VERSION_MINOR(driver_api_version);
	unsigned long driver_patch = PPM_API_VERSION_PATCH(driver_api_version);
	unsigned long required_major = PPM_API_VERSION_MAJOR(required_api_version);
	unsigned long required_minor = PPM_API_VERSION_MINOR(required_api_version);
	unsigned long required_patch = PPM_API_VERSION_PATCH(required_api_version);

	return scap_apply_semver_check(driver_major, driver_minor, driver_patch, required_major, required_minor, required_patch);
}

static int32_t check_api_compatibility_impl(uint64_t current_version, uint64_t minimum_version, const char* label, char *error)
{
	if(!scap_is_api_compatible(current_version, minimum_version))
	{
		return scap_errprintf(error, 0, "Driver supports %s version %llu.%llu.%llu, but running version needs %llu.%llu.%llu",
				      label,
				      PPM_API_VERSION_MAJOR(current_version),
				      PPM_API_VERSION_MINOR(current_version),
				      PPM_API_VERSION_PATCH(current_version),
				      PPM_API_VERSION_MAJOR(minimum_version),
				      PPM_API_VERSION_MINOR(minimum_version),
				      PPM_API_VERSION_PATCH(minimum_version));
	}
	return SCAP_SUCCESS;
}

int32_t check_api_compatibility(const struct scap_vtable* vtable, struct scap_engine_handle engine, char *error)
{
	int rc;
	if(vtable && vtable->get_api_version)
	{
		uint64_t version = vtable->get_api_version(engine);
		rc = check_api_compatibility_impl(version, SCAP_MINIMUM_DRIVER_API_VERSION, "API", error);
		if(rc != SCAP_SUCCESS)
		{
			return rc;
		}
	}

	if(vtable && vtable->get_schema_version)
	{
		uint64_t version = vtable->get_schema_version(engine);
		rc = check_api_compatibility_impl(version, SCAP_MINIMUM_DRIVER_SCHEMA_VERSION, "schema", error);
		if(rc != SCAP_SUCCESS)
		{
			return rc;
		}
	}

	return SCAP_SUCCESS;
}

