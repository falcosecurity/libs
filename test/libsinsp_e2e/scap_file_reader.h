// SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include <libsinsp/sinsp.h>

#include <functional>
#include <memory>
#include <string>

class scap_file_reader {
public:
	virtual ~scap_file_reader() { m_inspector = nullptr; }

	virtual std::shared_ptr<sinsp> setup_read_file() {
		if(!m_inspector) {
			m_inspector = std::make_shared<sinsp>();
			m_inspector->set_hostname_and_port_resolution_mode(true);
		}
		return m_inspector;
	}

	virtual void run_inspector(const char* filename,
	                           const std::string filter,
	                           std::function<void(sinsp_evt*)> evtcb) {
		m_inspector->open_savefile(filename);
		m_inspector->set_filter(filter.c_str());

		while(true) {
			int32_t res;
			sinsp_evt* evt;

			res = m_inspector->next(&evt);

			if(res == SCAP_TIMEOUT) {
				continue;
			} else if(res == SCAP_FILTERED_EVENT) {
				continue;
			} else if(res == SCAP_EOF) {
				break;
			} else if(res != SCAP_SUCCESS) {
				break;
			}

			evtcb(evt);
		}

		m_inspector->close();
	}

	virtual void read_file_filtered(const char* filename,
	                                const std::string filter,
	                                std::function<void(sinsp_evt*)> evtcb) {
		setup_read_file();
		run_inspector(filename, filter, evtcb);
	}

private:
	std::shared_ptr<sinsp> m_inspector;
};
