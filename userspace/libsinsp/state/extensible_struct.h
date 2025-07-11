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
class extensible_struct : public static_struct, public dynamic_struct {
public:
	explicit extensible_struct(const std::shared_ptr<dynamic_struct::field_infos>& dynamic_fields):
	        static_struct(),
	        dynamic_struct(dynamic_fields) {}

protected:
	struct reader {
		const extensible_struct* self;
		const accessor* acc;

		template<typename T>
		const void* operator()() const {
			if(auto static_acc = dynamic_cast<const static_struct::field_accessor<T>*>(acc)) {
				return self->static_struct::raw_read_field(*static_acc);
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_struct::field_accessor<T>*>(acc)) {
				return self->dynamic_struct::raw_read_field(*acc);
			}

#ifdef _MSC_VER
			_assume(0);
#else
			__builtin_unreachable();
#endif
		}
	};
	[[nodiscard]] const void* raw_read_field(const accessor& a) const override {
		return dispatch_lambda(a.type_info().type_id(), reader{this, &a});
	}

	struct writer {
		extensible_struct* self;
		const accessor* acc;
		const void* in;

		template<typename T>
		void operator()() const {
			if(auto static_acc = dynamic_cast<const static_struct::field_accessor<T>*>(acc)) {
				self->static_struct::raw_write_field(*static_acc, in);
				return;
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_struct::field_accessor<T>*>(acc)) {
				self->dynamic_struct::raw_write_field(*acc, in);
				return;
			}

#ifdef _MSC_VER
			_assume(0);
#else
			__builtin_unreachable();
#endif
		}
	};

	void raw_write_field(const accessor& a, const void* in) override {
		return dispatch_lambda(a.type_info().type_id(), writer{this, &a, in});
	}
};

class extensible_table_fields : public libsinsp::state::static_table_fields,
                                public libsinsp::state::dynamic_table_fields {
public:
	explicit extensible_table_fields(
	        const static_struct::field_infos* const m_static_fields,
	        const std::shared_ptr<dynamic_struct::field_infos>& dynamic_fields = nullptr):
	        static_table_fields(m_static_fields),
	        dynamic_table_fields(dynamic_fields) {}

	void fields(std::vector<ss_plugin_table_fieldinfo>& out) const override {
		static_table_fields::fields(out);
		dynamic_table_fields::fields(out);
	}

	std::unique_ptr<accessor> field(const char* name, const typeinfo& type_info) override {
		auto fixed_field = static_table_fields::field(name, type_info);
		auto dynamic_field = dynamic_table_fields::field(name, type_info);

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

	std::unique_ptr<accessor> new_field(const char* name, const typeinfo& type_info) override {
		if(static_table_fields::field(name, type_info) != nullptr) {
			throw sinsp_exception("can't add dynamic field already defined as static: " +
			                      std::string(name));
		}

		return dynamic_table_fields::new_field(name, type_info);
	}
};

}  // namespace libsinsp::state
