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
#include <converter/scap_evt_param_reader.h>

enum conversion_instruction_code {
	C_NO_INSTR = 0,         // This should be never called.
	C_INSTR_FROM_OLD,       // Take the parameter from the old event.
	C_INSTR_FROM_ENTER,     // Take the parameter from the enter event.
	C_INSTR_FROM_DEFAULT,   // Generate the default parameter.
	C_INSTR_FROM_EMPTY,     // Generate the empty parameter.
	C_INSTR_FROM_CALLBACK,  // Generate the parameter using a callback leveraging old event info.
};

// TODO(ekoops): remove CIF_FALLBACK_TO_EMPTY and fallback to empty by default once sinsp is able to
//   handle empty parameters for all the EF_CONVERTER_MANAGED entries in the converter table.
enum conversion_instruction_flags {
	CIF_NO_FLAGS = 0,
	CIF_FALLBACK_TO_EMPTY,  // C_INSTR_FROM_ENTER-only flag: fallback to the empty value instead of
	                        // the default one if for some reason the converter is not able to
	                        // obtain the parameter.
};

// Conversion actions
enum conversion_action {
	C_ACTION_UNKNOWN = 0,
	C_ACTION_PASS,
	C_ACTION_STORE,
	C_ACTION_STORE_AND_PASS,
	C_ACTION_ADD_PARAMS,
	C_ACTION_CHANGE_TYPE,
};

// Type denoting the signature of the callback required by the `C_INSTR_FROM_CALLBACK` instruction.
// `min_param_len` and `max_param_len` are provided to help the user reasoning about what is the
// allowed sizes range for the returned buffer.
typedef std::vector<char> (*conversion_instruction_callback)(const scap_evt_param_reader& reader,
                                                             size_t min_param_len,
                                                             size_t max_param_len);

struct conversion_instruction {
	conversion_instruction_code code = C_NO_INSTR;
	uint8_t param_num = 0;
	conversion_instruction_flags flags = CIF_NO_FLAGS;
	conversion_instruction_callback callback = nullptr;  // Only used by C_INSTR_FROM_CALLBACK.
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
