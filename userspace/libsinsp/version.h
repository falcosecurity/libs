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
	inline sinsp_version() : sinsp_version("0.0.0") { }

	inline explicit sinsp_version(const std::string &version_str)
	{
		m_valid = sscanf(version_str.c_str(), "%" PRIu32 ".%" PRIu32 ".%" PRIu32,
			&m_version_major, &m_version_minor, &m_version_patch) == 3;
	}

	sinsp_version(sinsp_version&&) = default;
	sinsp_version& operator = (sinsp_version&&) = default;
	sinsp_version(const sinsp_version& s) = default;
	sinsp_version& operator = (const sinsp_version& s) = default;

	~sinsp_version() = default;

	inline std::string as_string() const
	{
		return std::to_string(m_version_major)
			+ "." + std::to_string(m_version_minor)
			+ "." + std::to_string(m_version_patch);
	}

	inline bool operator<(sinsp_version const& right) const
	{
		if(this->m_version_major > right.m_version_major)
		{
			return false;
		}

		if(this->m_version_major == right.m_version_major)
		{
			if(this->m_version_minor > right.m_version_minor)
			{
				return false;
			}

			if(this->m_version_minor == right.m_version_minor && this->m_version_patch >= right.m_version_patch)
			{
				return false;
			}
		}

		return true;
	}

	inline bool operator>(sinsp_version const& right) const
	{
		return (*this != right && !(*this < right));
	}

	inline bool operator==(sinsp_version const& right) const
	{
		if(this->m_version_major == right.m_version_major 
			&& this->m_version_minor == right.m_version_minor
			&& this->m_version_patch == right.m_version_patch)
		{
			return true;
		}

		return false;
	}

	inline bool operator!=(sinsp_version const& right) const
	{
		return !(*this == right);
	}

	inline bool operator>=(sinsp_version const& right) const
	{
		return ((*this == right) || (*this > right));
	}

	inline bool operator<=(sinsp_version const& right) const
	{
		return ((*this == right) || (*this < right));
	}

	inline bool compatible_with(const sinsp_version &requested) const
	{
		if(!m_valid || !requested.m_valid)
		{
			return false;
		}

		return (this->m_version_major == requested.m_version_major) && (*this >= requested);
	}

	inline bool is_valid() const
	{
		return m_valid;
	}

	inline uint32_t major() const
	{
		return m_version_major;
	}

	inline uint32_t minor() const
	{
		return m_version_minor;
	}

	inline uint32_t patch() const
	{
		return m_version_patch;
	}

private:
	bool m_valid;
	uint32_t m_version_major;
	uint32_t m_version_minor;
	uint32_t m_version_patch;
};
