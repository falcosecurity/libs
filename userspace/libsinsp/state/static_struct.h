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

#include <libsinsp/state/borrowed_state_data.h>
#include <libsinsp/state/table_entry.h>
#include <libsinsp/state/type_info.h>

#include <string>
#include <unordered_map>

namespace libsinsp {
namespace state {

/**
 * @brief A base class for classes and structs that allow dynamic programming
 * by making part (or all) of their fields discoverable and accessible at runtime.
 * The structure of the class is predetermined at compile-time and its fields
 * are placed at a given offset within the class memory area.
 */
class static_struct : virtual public table_entry {
public:
	/**
	 * @brief Info about a given field in a static struct.
	 */
	class field_info {
	public:
		friend inline bool operator==(const field_info& a, const field_info& b) {
			return a.info() == b.info() && a.name() == b.name() && a.m_reader == b.m_reader &&
			       a.m_writer == b.m_writer;
		};

		friend inline bool operator!=(const field_info& a, const field_info& b) {
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
		inline ss_plugin_state_type info() const { return m_type_id; }

		/**
		 * @brief Returns a strongly-typed accessor for the given field,
		 * that can be used to reading and writing the field's value in
		 * all instances of structs where it is defined.
		 */
		inline accessor::ptr new_accessor() const {
			return accessor::ptr(std::make_unique<field_accessor>(*this));
		}

	private:
		inline field_info(const std::string& n,
		                  ss_plugin_state_type t,
		                  bool r,
		                  accessor::reader_fn reader,
		                  accessor::writer_fn writer):
		        m_readonly(r),
		        m_name(n),
		        m_type_id(t),
		        m_reader(reader),
		        m_writer(writer) {}

		bool m_readonly;
		std::string m_name;
		ss_plugin_state_type m_type_id;
		accessor::reader_fn m_reader;
		accessor::writer_fn m_writer;

		friend class static_struct;
	};

	/**
	 * @brief An strongly-typed accessor for accessing a field of a static struct.
	 * @tparam T Type of the field.
	 */
	class field_accessor : public accessor {
	public:
		/**
		 * @brief Returns the info about the field to which this accessor is tied.
		 */
		[[nodiscard]] const field_info& info() const { return m_info; }

		explicit field_accessor(field_info info):
		        accessor(info.m_type_id, info.m_reader, info.m_writer, 0),
		        m_info(std::move(info)) {};

	private:
		field_info m_info;

		friend class static_struct;
	};

	/**
	 * @brief A group of field infos, describing all the ones available
	 * in a static struct.
	 */
	using field_infos = std::unordered_map<std::string, field_info>;

protected:
	/**
	 * @brief Defines the information about a field defined in the class or struct.
	 * An exception is thrown if two fields are defined with the same name.
	 *
	 * @tparam T Type of the field.
	 * @param fields Fields group to which to add the new field.
	 * @param name Display name of the field.
	 */
	static const field_info& define_static_field(field_infos& fields,
	                                             const std::string& name,
	                                             ss_plugin_state_type type,
	                                             accessor::reader_fn reader,
	                                             accessor::writer_fn writer,
	                                             const bool readonly = false) {
		const auto& it = fields.find(name);
		if(it != fields.end()) {
			throw sinsp_exception("multiple definitions of static field in struct: " + name);
		}

		fields.insert({name, field_info(name, type, readonly, reader, writer)});
		return fields.at(name);
	}
};

class static_table_fields : virtual public table_fields {
public:
	explicit static_table_fields(const static_struct::field_infos* const m_static_fields):
	        m_static_fields(m_static_fields) {}

	using table_fields::list_fields;
	void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) const override;

	using table_fields::get_field;
	accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) override;

	using table_fields::add_field;
	accessor::ptr add_field(const char* name, ss_plugin_state_type type_id) override;

private:
	const static_struct::field_infos* const m_static_fields;
};

};  // namespace state
};  // namespace libsinsp

#define READER_LAMBDA(container_type, container_field, state_type)                       \
	[](const void* in, size_t) -> libsinsp::state::borrowed_state_data {                 \
		auto* c = static_cast<const container_type*>(in);                                \
		return libsinsp::state::borrowed_state_data::from<state_type,                    \
		                                                  decltype(c->container_field)>( \
		        c->container_field);                                                     \
	}

#define WRITER_LAMBDA(container_type, container_field, field_type)                     \
	[](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {        \
		auto* c = static_cast<container_type*>(in);                                    \
		in_data.copy_to<field_type, decltype(c->container_field)>(c->container_field); \
	}

#define READONLY_WRITER_LAMBDA(name)                                                  \
	[](void*, size_t, const libsinsp::state::borrowed_state_data&) {                  \
		throw sinsp_exception("attempt to write to read-only static struct field: " + \
		                      std::string(name));                                     \
	}

// DEFINE_STATIC_FIELD macro is a wrapper around static_struct::define_static_field helping to
// extract the field type.
#define DEFINE_STATIC_TYPED_FIELD(field_infos, container_type, container_field, name, state_type) \
	define_static_field(field_infos,                                                              \
	                    name,                                                                     \
	                    state_type,                                                               \
	                    READER_LAMBDA(container_type, container_field, state_type),               \
	                    WRITER_LAMBDA(container_type, container_field, state_type));

#define DEFINE_STATIC_FIELD(field_infos, container_type, container_field, name) \
	DEFINE_STATIC_TYPED_FIELD(                                                  \
	        field_infos,                                                        \
	        container_type,                                                     \
	        container_field,                                                    \
	        name,                                                               \
	        libsinsp::state::type_id_of<                                        \
	                decltype(static_cast<container_type*>(0)->container_field)>());

#define DEFINE_STATIC_TYPED_FIELD_READONLY(field_infos,                             \
                                           container_type,                          \
                                           container_field,                         \
                                           name,                                    \
                                           state_type)                              \
	define_static_field(field_infos,                                                \
	                    name,                                                       \
	                    state_type,                                                 \
	                    READER_LAMBDA(container_type, container_field, state_type), \
	                    READONLY_WRITER_LAMBDA(name),                               \
	                    true);

// DEFINE_STATIC_FIELD_READONLY macro is a wrapper around static_struct::define_static_field helping
// to extract the field type and field offset. The defined field is set to guarantee read-only
// access.
#define DEFINE_STATIC_FIELD_READONLY(field_infos, container_type, container_field, name) \
	DEFINE_STATIC_TYPED_FIELD_READONLY(                                                  \
	        field_infos,                                                                 \
	        container_type,                                                              \
	        container_field,                                                             \
	        name,                                                                        \
	        libsinsp::state::type_id_of<                                                 \
	                decltype(static_cast<container_type*>(0)->container_field)>());
