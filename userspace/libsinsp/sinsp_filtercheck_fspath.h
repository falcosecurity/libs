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

#include <libsinsp/sinsp_filtercheck.h>

class sinsp_filter_check_fspath : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NAME = 0,
		TYPE_NAMERAW = 1,
		TYPE_SOURCE = 2,
		TYPE_SOURCERAW = 3,
		TYPE_TARGET = 4,
		TYPE_TARGETRAW = 5,
	};

	sinsp_filter_check_fspath();
	virtual ~sinsp_filter_check_fspath() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;

protected:
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;

private:
	typedef std::map<uint16_t, std::shared_ptr<sinsp_filter_check>> filtercheck_map_t;

	std::shared_ptr<sinsp_filter_check> create_event_check(const char *name,
							       cmpop cop = CO_NONE,
							       const char *value = NULL);

	std::shared_ptr<sinsp_filter_check> create_fd_check(const char *name);

	void create_fspath_checks();
	void set_fspath_checks(std::shared_ptr<filtercheck_map_t> success_checks,
			       std::shared_ptr<filtercheck_map_t> path_checks,
			       std::shared_ptr<filtercheck_map_t> source_checks,
			       std::shared_ptr<filtercheck_map_t> target_checks);
	bool extract_fspath(sinsp_evt* evt,
			    OUT std::vector<extract_value_t>& values,
			    std::shared_ptr<filtercheck_map_t> map);
	std::string m_tstr;

	std::shared_ptr<filtercheck_map_t> m_success_checks;
	std::shared_ptr<filtercheck_map_t> m_path_checks;
	std::shared_ptr<filtercheck_map_t> m_source_checks;
	std::shared_ptr<filtercheck_map_t> m_target_checks;
};
