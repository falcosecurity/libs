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

/**
 * @brief Info about a given field in a static struct.
 */
class static_field_info {
public:
	friend inline bool operator==(const static_field_info& a, const static_field_info& b) {
		return a.type_id() == b.type_id() && a.name() == b.name() && a.readonly() == b.readonly();
	};

	friend inline bool operator!=(const static_field_info& a, const static_field_info& b) {
		return !(a == b);
	};

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
	 * @brief Returns the reader function for this field.
	 */
	inline accessor::reader_fn reader() const { return m_reader; }

	/**
	 * @brief Returns the writer function for this field.
	 */
	inline accessor::writer_fn writer() const { return m_writer; }

	/**
	 * @brief Returns a strongly-typed accessor for the given field,
	 * that can be used to reading and writing the field's value in
	 * all instances of structs where it is defined.
	 */
	inline accessor::ptr new_accessor() const;

	inline static_field_info(const std::string& n,
	                         ss_plugin_state_type t,
	                         bool r,
	                         accessor::reader_fn reader,
	                         accessor::writer_fn writer):
	        m_readonly(r),
	        m_name(n),
	        m_type_id(t),
	        m_reader(reader),
	        m_writer(writer) {}

private:
	bool m_readonly;
	std::string m_name;
	ss_plugin_state_type m_type_id;
	accessor::reader_fn m_reader;
	accessor::writer_fn m_writer;
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
	return accessor::ptr(std::make_unique<accessor>(type_id(), reader(), writer(), 0));
}

};  // namespace state
};  // namespace libsinsp

#define READER_LAMBDA(container_type, container_field, state_type)                             \
	[](const void* in, size_t) -> libsinsp::state::borrowed_state_data {                       \
		auto* c = static_cast<const container_type*>(in);                                      \
		return libsinsp::state::borrowed_state_data::                                          \
		        from<libsinsp::state::type_id_of<state_type>(), decltype(c->container_field)>( \
		                c->container_field);                                                   \
	}

#define WRITER_LAMBDA(container_type, container_field, field_type)                                \
	[](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {                   \
		auto* c = static_cast<container_type*>(in);                                               \
		in_data.copy_to<libsinsp::state::type_id_of<field_type>(), decltype(c->container_field)>( \
		        c->container_field);                                                              \
	}

#define READONLY_WRITER_LAMBDA(name)                                                  \
	[](void*, size_t, const libsinsp::state::borrowed_state_data&) {                  \
		throw sinsp_exception("attempt to write to read-only static struct field: " + \
		                      std::string(name));                                     \
	}

// DEFINE_STATIC_FIELD macro is a wrapper around static_struct::define_static_field helping to
// extract the field type and field offset.
#define DEFINE_STATIC_FIELD(field_infos, container_type, container_field, name)           \
	libsinsp::state::define_static_field<                                                 \
	        decltype(static_cast<container_type*>(0)->container_field)>(                  \
	        field_infos,                                                                  \
	        name,                                                                         \
	        READER_LAMBDA(container_type, container_field, decltype(c->container_field)), \
	        WRITER_LAMBDA(container_type, container_field, decltype(c->container_field)));

// DEFINE_STATIC_FIELD_READONLY macro is a wrapper around static_struct::define_static_field helping
// to extract the field type and field offset. The defined field is set to guarantee read-only
// access.
#define DEFINE_STATIC_FIELD_READONLY(field_infos, container_type, container_field, name)  \
	libsinsp::state::define_static_field<                                                 \
	        decltype(static_cast<container_type*>(0)->container_field)>(                  \
	        field_infos,                                                                  \
	        name,                                                                         \
	        READER_LAMBDA(container_type, container_field, decltype(c->container_field)), \
	        READONLY_WRITER_LAMBDA(name),                                                 \
	        true);
