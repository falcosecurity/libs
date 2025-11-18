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

/**
 * @brief Generic and agnostic information about a type, similar to
 * std::type_info but following a restricted and controlled enumeration of
 * the supported types for the state component of libsinsp. Enumerating
 * the types also allows for more peformant runtime checks. Moreover, this class
 * also provides construction and destruction utilities for each supported
 * types for convenience.
 */
class typeinfo {
public:
	/**
	 * @brief Returns a type info for the type T.
	 */
	template<typename T>
	static typeinfo of();

	static constexpr typeinfo from(ss_plugin_state_type state_type);

	inline typeinfo() = delete;
	inline ~typeinfo() = default;
	inline typeinfo(typeinfo&&) = default;
	inline typeinfo& operator=(typeinfo&&) = default;
	inline typeinfo(const typeinfo& s) = default;
	inline typeinfo& operator=(const typeinfo& s) = default;

	friend inline bool operator==(const typeinfo& a, const typeinfo& b) {
		return a.type_id() == b.type_id();
	};

	friend inline bool operator!=(const typeinfo& a, const typeinfo& b) {
		return a.type_id() != b.type_id();
	};

	/**
	 * @brief Returns the name of the type.
	 */
	inline const char* name() const { return m_name; }

	/**
	 * @brief Returns the numeric representation of the type.
	 */
	inline constexpr ss_plugin_state_type type_id() const { return m_type_id; }

	/**
	 * @brief Returns the byte size of variables of the given type.
	 */
	inline size_t size() const { return m_size; }

	/**
	 * @brief Constructs and initializes the given type in the passed-in
	 * memory location, which is expected to be larger or equal than size().
	 */
	inline void construct(void* p) const noexcept {
		if(p && m_construct)
			m_construct(p);
	}

	/**
	 * @brief Destructs and deinitializes the given type in the passed-in
	 * memory location, which is expected to be larger or equal than size().
	 */
	inline void destroy(void* p) const noexcept {
		if(p && m_destroy)
			m_destroy(p);
	}

private:
	inline typeinfo(const char* n,
	                ss_plugin_state_type k,
	                size_t s,
	                void (*c)(void*),
	                void (*d)(void*)):
	        m_name(n),
	        m_type_id(k),
	        m_size(s),
	        m_construct(c),
	        m_destroy(d) {}

	template<typename T, typename _Alloc = std::allocator<T>>
	static inline void _construct(void* p) {
		_Alloc a;
		std::allocator_traits<_Alloc>::construct(a, reinterpret_cast<T*>(p));
	}

	template<typename T, typename _Alloc = std::allocator<T>>
	static inline void _destroy(void* p) {
		_Alloc a;
		std::allocator_traits<_Alloc>::destroy(a, reinterpret_cast<T*>(p));
	}

	template<typename T>
	static inline typeinfo _build(const char* n, ss_plugin_state_type k) {
		return typeinfo(n, k, sizeof(T), _construct<T>, _destroy<T>);
	}

	const char* m_name;
	ss_plugin_state_type m_type_id;
	size_t m_size;
	void (*m_construct)(void*);
	void (*m_destroy)(void*);
};

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

// below is the manually-controlled list of all the supported types
template<>
inline typeinfo typeinfo::of<bool>() {
	return _build<bool>("bool", SS_PLUGIN_ST_BOOL);
}
template<>
inline typeinfo typeinfo::of<int8_t>() {
	return _build<int8_t>("int8", SS_PLUGIN_ST_INT8);
}
template<>
inline typeinfo typeinfo::of<int16_t>() {
	return _build<int16_t>("int16", SS_PLUGIN_ST_INT16);
}
template<>
inline typeinfo typeinfo::of<int32_t>() {
	return _build<int32_t>("int32", SS_PLUGIN_ST_INT32);
}
template<>
inline typeinfo typeinfo::of<int64_t>() {
	return _build<int64_t>("int64", SS_PLUGIN_ST_INT64);
}
template<>
inline typeinfo typeinfo::of<uint8_t>() {
	return _build<uint8_t>("uint8", SS_PLUGIN_ST_UINT8);
}
template<>
inline typeinfo typeinfo::of<uint16_t>() {
	return _build<uint16_t>("uint16", SS_PLUGIN_ST_UINT16);
}
template<>
inline typeinfo typeinfo::of<uint32_t>() {
	return _build<uint32_t>("uint32", SS_PLUGIN_ST_UINT32);
}
template<>
inline typeinfo typeinfo::of<uint64_t>() {
	return _build<uint64_t>("uint64", SS_PLUGIN_ST_UINT64);
}
template<>
inline typeinfo typeinfo::of<std::string>() {
	return _build<std::string>("string", SS_PLUGIN_ST_STRING);
}
template<>
inline typeinfo typeinfo::of<libsinsp::state::base_table*>() {
	return _build<libsinsp::state::base_table*>("table", SS_PLUGIN_ST_TABLE);
}
template<>
inline typeinfo typeinfo::of<const libsinsp::state::base_table*>() {
	return _build<const libsinsp::state::base_table*>("table", SS_PLUGIN_ST_TABLE);
}

inline constexpr typeinfo typeinfo::from(ss_plugin_state_type state_type) {
	switch(state_type) {
	case SS_PLUGIN_ST_INT8:
		return typeinfo::of<int8_t>();
	case SS_PLUGIN_ST_INT16:
		return typeinfo::of<int16_t>();
	case SS_PLUGIN_ST_INT32:
		return typeinfo::of<int32_t>();
	case SS_PLUGIN_ST_INT64:
		return typeinfo::of<int64_t>();
	case SS_PLUGIN_ST_UINT8:
		return typeinfo::of<uint8_t>();
	case SS_PLUGIN_ST_UINT16:
		return typeinfo::of<uint16_t>();
	case SS_PLUGIN_ST_UINT32:
		return typeinfo::of<uint32_t>();
	case SS_PLUGIN_ST_UINT64:
		return typeinfo::of<uint64_t>();
	case SS_PLUGIN_ST_STRING:
		return typeinfo::of<std::string>();
	case SS_PLUGIN_ST_TABLE:
		return typeinfo::of<libsinsp::state::base_table*>();
	case SS_PLUGIN_ST_BOOL:
		return typeinfo::of<bool>();
	default:
		throw sinsp_exception("state::typeinfo::of invoked for unsupported state_type: " +
		                      std::to_string(state_type));
	}
}

};  // namespace state
};  // namespace libsinsp
