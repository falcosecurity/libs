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

#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdio>
#include <inttypes.h>

/*!
	\brief Represents a version number
*/
class sinsp_version
{
public:
	inline sinsp_version() : m_valid(false) { }

	inline explicit sinsp_version(const std::string &version_str)
	{
		m_valid = sscanf(version_str.c_str(), "%" PRIu32 ".%" PRIu32 ".%" PRIu32,
			&m_version_major, &m_version_minor, &m_version_patch) == 3;
	}

	virtual ~sinsp_version() = default;

	inline std::string as_string() const
	{
		return std::to_string(m_version_major)
			+ "." + std::to_string(m_version_minor)
			+ "." + std::to_string(m_version_patch);
	}

	inline bool check(const sinsp_version &requested) const
	{
		if(this->m_version_major != requested.m_version_major)
		{
			// major numbers disagree
			return false;
		}

		if(this->m_version_minor < requested.m_version_minor)
		{
			// framework's minor version is < requested one
			return false;
		}

		if(this->m_version_minor == requested.m_version_minor
			&& this->m_version_patch < requested.m_version_patch)
		{
			// framework's patch level is < requested one
			return false;
		}
		return true;
	}

	bool m_valid;
	uint32_t m_version_major;
	uint32_t m_version_minor;
	uint32_t m_version_patch;
};
