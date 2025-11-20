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

#include <string>
#include <unordered_map>

namespace libsinsp {
namespace state {

/**
 * @brief A group of field infos, describing all the ones available
 * in a static struct.
 */
using static_field_infos = std::unordered_map<std::string, accessor>;

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
	libsinsp::state::define_static_field(                                                         \
	        field_infos,                                                                          \
	        name,                                                                                 \
	        state_type,                                                                           \
	        READER_LAMBDA(container_type, container_field, state_type),                           \
	        WRITER_LAMBDA(container_type, container_field, state_type));

#define DEFINE_STATIC_FIELD(field_infos, container_type, container_field, name) \
	DEFINE_STATIC_TYPED_FIELD(                                                  \
	        field_infos,                                                        \
	        container_type,                                                     \
	        container_field,                                                    \
	        name,                                                               \
	        libsinsp::state::type_id_of<                                        \
	                decltype(static_cast<container_type*>(0)->container_field)>());

#define DEFINE_STATIC_TYPED_FIELD_READONLY(field_infos,                 \
                                           container_type,              \
                                           container_field,             \
                                           name,                        \
                                           state_type)                  \
	libsinsp::state::define_static_field(                               \
	        field_infos,                                                \
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
