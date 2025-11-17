// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <libsinsp/state/type_info.h>
#include <plugin/plugin_types.h>

namespace libsinsp::state {
class borrowed_state_data {
public:
	borrowed_state_data() noexcept = default;

	explicit borrowed_state_data(const ss_plugin_state_data& data) noexcept { m_data = data; }

	template<ss_plugin_state_type StateType, typename ValueType>
	static borrowed_state_data from(const ValueType& value) noexcept {
		using decayed_t = decltype(decay(value));
		borrowed_state_data sd;
		sd.borrow_from<StateType, decayed_t>(static_cast<const decayed_t&>(value));
		return sd;
	}

	template<ss_plugin_state_type StateType, typename ValueType>
	void borrow_from(const ValueType& value) {
		using decayed_t = decltype(decay(value));
		borrow_from<StateType, decayed_t>(static_cast<const decayed_t&>(value));
	}

	template<ss_plugin_state_type StateType, typename ValueType>
	void borrow_to(ValueType& out) const;

	// Yes, we copy and borrow using the exact same implementation by default.
	// The only time we notice a difference would be with raw C strings
	// (deep copying would involve a strdup, while borrowing would just copy the pointer).
	// However, this introduces an asymmetry where state_data_wrapper is responsible
	// for allocating memory, but not freeing it. So delete that specialization
	// explicitly. This prevents us from using `const char*` for storing string fields
	// in tables, forcing the use of `std::string` (or `owned_state_data`) instead.
	//
	// A special case is "borrowing" a const char* into a std::string,
	// which always involves a copy.
	template<ss_plugin_state_type StateType, typename ValueType>
	void copy_to(ValueType& out) const {
		borrow_to<StateType, ValueType>(out);
	}

	[[nodiscard]] const ss_plugin_state_data& data() const noexcept { return m_data; }

private:
	template<typename T, size_t N>
	static const T* decay(const T (&arr)[N]) noexcept {
		return static_cast<const T*>(arr);
	}

	template<typename T>
	static std::decay_t<T> decay(const T& val) noexcept {
		return val;
	}

	ss_plugin_state_data m_data{};
};

#define STATE_DATA_IMPL(_TYPE, _MEMBER)                                                            \
	template<>                                                                                     \
	inline void borrowed_state_data::borrow_from<type_id_of<_TYPE>(), _TYPE>(const _TYPE& value) { \
		m_data._MEMBER = value;                                                                    \
	}                                                                                              \
	template<>                                                                                     \
	inline void borrowed_state_data::borrow_to<type_id_of<_TYPE>(), _TYPE>(_TYPE & out) const {    \
		out = m_data._MEMBER;                                                                      \
	}

STATE_DATA_IMPL(bool, b);
STATE_DATA_IMPL(int8_t, s8);
STATE_DATA_IMPL(int16_t, s16);
STATE_DATA_IMPL(int32_t, s32);
STATE_DATA_IMPL(int64_t, s64);
STATE_DATA_IMPL(uint8_t, u8);
STATE_DATA_IMPL(uint16_t, u16);
STATE_DATA_IMPL(uint32_t, u32);
STATE_DATA_IMPL(uint64_t, u64);

#undef STATE_DATA_IMPL

template<>
inline void borrowed_state_data::borrow_from<SS_PLUGIN_ST_STRING, const char*>(
        const char* const& value) {
	m_data.str = value;
}

template<>
inline void borrowed_state_data::borrow_from<SS_PLUGIN_ST_STRING, std::string>(
        const std::string& value) {
	m_data.str = value.c_str();
}

template<>
inline void borrowed_state_data::borrow_from<SS_PLUGIN_ST_TABLE, base_table*>(
        base_table* const& value) {
	m_data.table = value;
}

template<>
inline void borrowed_state_data::borrow_from<SS_PLUGIN_ST_TABLE>(base_table const* const& value) {
	m_data.table = const_cast<base_table*>(value);
}

template<>
inline void borrowed_state_data::borrow_to<SS_PLUGIN_ST_STRING, std::string>(
        std::string& out) const {
	if(m_data.str == nullptr) {
		out = "";
	} else {
		out = m_data.str;
	}
}

template<>
void borrowed_state_data::copy_to<SS_PLUGIN_ST_STRING, const char*>(const char*& out) const =
        delete;

template<>
inline void borrowed_state_data::borrow_to<SS_PLUGIN_ST_TABLE, base_table*>(
        base_table*& out) const {
	out = static_cast<base_table*>(m_data.table);
}

}  // namespace libsinsp::state
