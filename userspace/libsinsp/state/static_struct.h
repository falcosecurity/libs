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

#include <libsinsp/state/table_entry.h>
#include <libsinsp/state/type_info.h>

#include <string>
#include <unordered_map>

namespace libsinsp {
namespace state {

class static_field_accessor;

/**
 * @brief Info about a given field in a static struct.
 */
class static_field_info {
public:
	friend inline bool operator==(const static_field_info& a, const static_field_info& b) {
		return a.type_id() == b.type_id() && a.name() == b.name() && a.readonly() == b.readonly() &&
		       a.m_offset == b.m_offset;
	};

	friend inline bool operator!=(const static_field_info& a, const static_field_info& b) {
		return !(a == b);
	};

	/**
	 * @brief Returns true if the field info is valid.
	 */
	inline bool valid() const { return m_offset != (size_t)-1; }

	/**
	 * @brief Returns true if the field is read only.
	 */
	inline bool readonly() const { return m_readonly; }

	/**
	 * @brief Returns the name of the field.
	 */
	inline const std::string& name() const { return m_name; }

	/**
	 * @brief Returns the type info of the field.
	 */
	inline ss_plugin_state_type type_id() const { return m_type_id; }

	/**
	 * @brief Returns the offset of the field within the struct.
	 */
	inline size_t offset() const { return m_offset; }

	/**
	 * @brief Returns a strongly-typed accessor for the given field,
	 * that can be used to reading and writing the field's value in
	 * all instances of structs where it is defined.
	 */
	inline accessor::ptr new_accessor() const;

	inline static_field_info(const std::string& n, size_t o, ss_plugin_state_type t, bool r):
	        m_readonly(r),
	        m_offset(o),
	        m_name(n),
	        m_type_id(t) {}

private:
	bool m_readonly;
	size_t m_offset;
	std::string m_name;
	ss_plugin_state_type m_type_id;
};

/**
 * @brief An accessor for accessing a field of a static struct.
 * @tparam T Type of the field.
 */
class static_field_accessor : public accessor {
public:
	/**
	 * @brief Returns the info about the field to which this accessor is tied.
	 */
	[[nodiscard]] const static_field_info& info() const { return m_info; }

	explicit static_field_accessor(static_field_info info):
	        accessor(info.type_id()),
	        m_info(std::move(info)) {};

private:
	static_field_info m_info;
};

/**
 * @brief A group of field infos, describing all the ones available
 * in a static struct.
 */
using static_field_infos = std::unordered_map<std::string, static_field_info>;

/**
 * @brief Returns a strongly-typed accessor for the given field,
 * that can be used to reading and writing the field's value in
 * all instances of structs where it is defined.
 */
inline accessor::ptr static_field_info::new_accessor() const {
	if(!valid()) {
		throw sinsp_exception("can't create static struct field accessor for invalid field");
	}
	return accessor::ptr(std::make_unique<static_field_accessor>(*this));
}

};  // namespace state
};  // namespace libsinsp

// This `offsetof` custom definition prevents the compiler from complaining about "offsetof"-ing on
// non-standard-layout types (e.g.: `warning: ‘offsetof’ within non-standard-layout type ‘X’ is
// conditionally-supported)`.
#define OFFSETOF_STATIC_FIELD(type, member) reinterpret_cast<size_t>(&static_cast<type*>(0)->member)

// DEFINE_STATIC_FIELD macro is a wrapper around static_struct::define_static_field helping to
// extract the field type and field offset.
#define DEFINE_STATIC_FIELD(field_infos, container_type, container_field, name) \
	libsinsp::state::define_static_field<                                       \
	        decltype(static_cast<container_type*>(0)->container_field)>(        \
	        field_infos,                                                        \
	        OFFSETOF_STATIC_FIELD(container_type, container_field),             \
	        name);

// DEFINE_STATIC_FIELD_READONLY macro is a wrapper around static_struct::define_static_field helping
// to extract the field type and field offset. The defined field is set to guarantee read-only
// access.
#define DEFINE_STATIC_FIELD_READONLY(field_infos, container_type, container_field, name) \
	libsinsp::state::define_static_field<                                                \
	        decltype(static_cast<container_type*>(0)->container_field)>(                 \
	        field_infos,                                                                 \
	        OFFSETOF_STATIC_FIELD(container_type, container_field),                      \
	        name,                                                                        \
	        true);
