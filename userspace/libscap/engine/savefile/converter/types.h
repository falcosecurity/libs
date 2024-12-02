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

#include <vector>
#include <cstdint>

enum conversion_instruction_flags {
	C_NO_INSTR = 0,        // This should be never called
	C_INSTR_FROM_OLD,      // Take the parameter from the old event
	C_INSTR_FROM_ENTER,    // Take the parameter from the enter event
	C_INSTR_FROM_DEFAULT,  // Generate the default parameter
};

// Conversion actions
enum conversion_action {
	C_ACTION_UNKNOWN = 0,
	C_ACTION_SKIP,
	C_ACTION_STORE,
	C_ACTION_ADD_PARAMS,
	C_ACTION_CHANGE_TYPE,
};

struct conversion_instruction {
	uint8_t flags = 0;
	uint8_t param_num = 0;
};

struct conversion_key {
	uint16_t event_code = 0;
	uint8_t param_num = 0;

	// Comparison operator for equality (needed by std::unordered_map)
	bool operator==(const conversion_key& other) const {
		return event_code == other.event_code && param_num == other.param_num;
	}
};

namespace std {
template<>
struct hash<conversion_key> {
	size_t operator()(const conversion_key& key) const {
		// Combine the hash of event_code and param_num
		return std::hash<uint16_t>()(key.event_code) ^ (std::hash<uint8_t>()(key.param_num) << 1);
	}
};
}  // namespace std

struct conversion_info {
	uint8_t m_action = 0;
	uint16_t m_desired_type = 0;  // Needed only when action is `C_ACTION_CHANGE_TYPE`
	std::vector<conversion_instruction> m_instrs = {};

	conversion_info& action(conversion_action a) {
		m_action = (uint8_t)a;
		return *this;
	};

	conversion_info& desired_type(uint16_t t) {
		m_desired_type = t;
		return *this;
	};

	conversion_info& instrs(std::vector<conversion_instruction> i) {
		m_instrs = i;
		return *this;
	};
};
