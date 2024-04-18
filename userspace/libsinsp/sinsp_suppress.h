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

#include <cstdint>
#include <string>
#include <unordered_set>

typedef struct ppm_evt_hdr scap_evt;

namespace libsinsp
{

class sinsp_suppress
{
public:
	sinsp_suppress() = default;

	void suppress_comm(const std::string& comm);

	void suppress_tid(uint64_t tid);

	void clear_suppress_comm();

	void clear_suppress_tid();

	bool check_suppressed_comm(uint64_t tid, const std::string& comm);

	int32_t process_event(scap_evt* e);

	bool is_suppressed_tid(uint64_t tid) const;

	uint64_t get_num_suppressed_events() const { return m_num_suppressed_events; }

	uint64_t get_num_suppressed_tids() const { return m_suppressed_tids.size(); }

protected:
	std::unordered_set<std::string> m_suppressed_comms;
	std::unordered_set<uint64_t> m_suppressed_tids;

	uint64_t m_num_suppressed_events = 0;
};

}
