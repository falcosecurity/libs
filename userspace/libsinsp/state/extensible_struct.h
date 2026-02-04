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
			if(auto static_acc = dynamic_cast<const static_field_accessor<T>*>(acc)) {
				return self->static_struct::raw_read_field(*static_acc);
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_struct::field_accessor<T>*>(acc)) {
				self->_check_defsptr(dynamic_acc->info(), false);
				return self->_access_dynamic_field_for_read(dynamic_acc->info().index());
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
			if(auto static_acc = dynamic_cast<const static_field_accessor<T>*>(acc)) {
				self->static_struct::raw_write_field(*static_acc, in);
				return;
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_struct::field_accessor<T>*>(acc)) {
				self->_check_defsptr(dynamic_acc->info(), true);
				auto ptr = static_cast<T*>(
				        self->_access_dynamic_field_for_write(dynamic_acc->info().index()));
				auto val = static_cast<const T*>(in);
				*ptr = *val;
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
}  // namespace libsinsp::state
