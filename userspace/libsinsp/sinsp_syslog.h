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

#include <libsinsp/sinsp_exception.h>

#include <stdint.h>
#include <string>
#include <memory>

class sinsp_syslog_decoder
{
public:
	void parse_data(const char *data, uint32_t len);

	std::string get_info_line() const;
	std::string get_severity_str() const;
	std::string get_facility_str() const;

	inline void reset()
	{
		m_priority = s_invalid_priority;
	}

	bool is_data_valid() const
	{
		return m_priority != s_invalid_priority;
	}

	inline int32_t get_priority() const
	{
		return m_priority;
	}

	inline uint32_t get_facility() const
	{
		return m_facility;
	}

	inline uint32_t get_severity() const
	{
		return m_severity;
	}

	inline const std::string& get_msg() const
	{
		return m_msg;
	}

private:
	void decode_message(const char *data, uint32_t len, char* pristr, uint32_t pristrlen);

	int32_t m_priority{s_invalid_priority};
	uint32_t m_facility{0};
	uint32_t m_severity{0};
	std::string m_msg;
	std::string m_infostr;

	static constexpr const int32_t s_invalid_priority = -1;
};
