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
	[[nodiscard]] const void* raw_read_field(const accessor& a) const override {
		auto reader = [&]<typename T>() {
			if(auto static_acc = dynamic_cast<const static_struct::field_accessor<T>*>(&a)) {
				return static_struct::raw_read_field(a);
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_struct::field_accessor<T>*>(&a)) {
				return dynamic_struct::raw_read_field(a);
			}

			__builtin_unreachable();
		};
		return dispatch_lambda(a.type_info().type_id(), reader);
	}

	void raw_write_field(const accessor& a, const void* in) override {
		auto writer = [&]<typename T>() {
			if(auto static_acc = dynamic_cast<const static_struct::field_accessor<T>*>(&a)) {
				static_struct::raw_write_field(*static_acc, in);
				return;
			}

			if(auto dynamic_acc = dynamic_cast<const dynamic_struct::field_accessor<T>*>(&a)) {
				dynamic_struct::raw_write_field(a, in);
				return;
			}

			__builtin_unreachable();
		};
		return dispatch_lambda(a.type_info().type_id(), writer);
	}
};
}  // namespace libsinsp::state
