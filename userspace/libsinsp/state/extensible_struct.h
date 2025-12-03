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

#include <libsinsp/state/dynamic_struct.h>
#include <libsinsp/state/static_struct.h>

namespace libsinsp::state {
template<typename TDerived>
class extensible_struct : public static_struct, public dynamic_struct<TDerived> {
public:
	explicit extensible_struct(
	        const std::shared_ptr<typename dynamic_struct<TDerived>::field_infos>& dynamic_fields):
	        static_struct(),
	        dynamic_struct<TDerived>(dynamic_fields) {}

protected:
	[[nodiscard]] borrowed_state_data raw_read_field(const accessor& a) const override {
		if(dynamic_cast<const static_struct::field_accessor*>(&a)) {
			return static_struct::raw_read_field(a);
		} else {
			return dynamic_struct<TDerived>::raw_read_field(a);
		}
	}

	void raw_write_field(const accessor& a, const borrowed_state_data& in) override {
		if(dynamic_cast<const static_struct::field_accessor*>(&a)) {
			static_struct::raw_write_field(a, in);
		} else {
			dynamic_struct<TDerived>::raw_write_field(a, in);
		}
	}
};

template<typename TDerived>
class extensible_table_fields : public libsinsp::state::static_table_fields,
                                public libsinsp::state::dynamic_table_fields<TDerived> {
public:
	explicit extensible_table_fields(
	        const static_struct::field_infos* const m_static_fields,
	        const std::shared_ptr<typename dynamic_struct<TDerived>::field_infos>& dynamic_fields =
	                nullptr):
	        static_table_fields(m_static_fields),
	        dynamic_table_fields<TDerived>(dynamic_fields) {}

	void fields(std::vector<ss_plugin_table_fieldinfo>& out) const override {
		static_table_fields::fields(out);
		dynamic_table_fields<TDerived>::fields(out);
	}

	accessor::ptr field(const char* name, ss_plugin_state_type type_id) override {
		auto fixed_field = static_table_fields::field(name, type_id);
		auto dynamic_field = dynamic_table_fields<TDerived>::field(name, type_id);

		if(fixed_field != nullptr && dynamic_field != nullptr) {
			// todo(jasondellaluce): plugins are not aware of the difference
			// between static and dynamic fields. Do we want to enforce
			// this limitation in the sinsp tables implementation as well?
			throw sinsp_exception("field is defined as both static and dynamic: " +
			                      std::string(name));
		}

		if(fixed_field != nullptr) {
			return fixed_field;
		}

		return dynamic_field;
	}

	accessor::ptr new_field(const char* name, ss_plugin_state_type type_id) override {
		if(static_table_fields::field(name, type_id) != nullptr) {
			throw sinsp_exception("can't add dynamic field already defined as static: " +
			                      std::string(name));
		}

		return dynamic_table_fields<TDerived>::new_field(name, type_id);
	}
};

}  // namespace libsinsp::state
