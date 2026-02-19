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
#include <plugin/plugin_types.h>

#include <string>

namespace libsinsp {
namespace state {
class base_table;

template<typename T>
static constexpr ss_plugin_state_type type_id_of();

template<>
inline constexpr ss_plugin_state_type type_id_of<bool>() {
	return SS_PLUGIN_ST_BOOL;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<int8_t>() {
	return SS_PLUGIN_ST_INT8;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<int16_t>() {
	return SS_PLUGIN_ST_INT16;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<int32_t>() {
	return SS_PLUGIN_ST_INT32;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<int64_t>() {
	return SS_PLUGIN_ST_INT64;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<uint8_t>() {
	return SS_PLUGIN_ST_UINT8;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<uint16_t>() {
	return SS_PLUGIN_ST_UINT16;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<uint32_t>() {
	return SS_PLUGIN_ST_UINT32;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<uint64_t>() {
	return SS_PLUGIN_ST_UINT64;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<std::string>() {
	return SS_PLUGIN_ST_STRING;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<base_table*>() {
	return SS_PLUGIN_ST_TABLE;
}
template<>
inline constexpr ss_plugin_state_type type_id_of<const base_table*>() {
	return SS_PLUGIN_ST_TABLE;
}

/**
 * @brief Returns the name of the type.
 */
static inline const char* type_name(ss_plugin_state_type type_id) {
	switch(type_id) {
	case SS_PLUGIN_ST_INT8:
		return "int8";
	case SS_PLUGIN_ST_INT16:
		return "int16";
	case SS_PLUGIN_ST_INT32:
		return "int32";
	case SS_PLUGIN_ST_INT64:
		return "int64";
	case SS_PLUGIN_ST_UINT8:
		return "uint8";
	case SS_PLUGIN_ST_UINT16:
		return "uint16";
	case SS_PLUGIN_ST_UINT32:
		return "uint32";
	case SS_PLUGIN_ST_UINT64:
		return "uint64";
	case SS_PLUGIN_ST_STRING:
		return "string";
	case SS_PLUGIN_ST_TABLE:
		return "table";
	case SS_PLUGIN_ST_BOOL:
		return "bool";
	default:
		throw sinsp_exception("state::type_name invoked for unsupported type_id: " +
		                      std::to_string(type_id));
	}
}

template<typename T>
const char* type_name() {
	return type_name(type_id_of<T>());
}

};  // namespace state
};  // namespace libsinsp
