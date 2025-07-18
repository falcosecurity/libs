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

namespace libsinsp::state {

class accessor {
public:
	explicit accessor(const typeinfo& type_info): m_type_info(type_info) {}
	virtual ~accessor() = default;

	[[nodiscard]] typeinfo type_info() const { return m_type_info; }

private:
	typeinfo m_type_info;
};

template<typename T>
class typed_accessor : public accessor {
public:
	typed_accessor(): accessor(typeinfo::of<T>()) {}
};

/**
 * @brief Base class for entries of a state table.
 */
class table_entry {
public:
	virtual ~table_entry() = default;

	template<typename T>
	T read_field(const typed_accessor<T>& a) const {
		auto out = static_cast<const T*>(this->raw_read_field(a));
		if(out == nullptr) {
			return {};
		}
		return *out;
	}

	template<typename T, typename Val = T>
	void read_field(const typed_accessor<T>& a, Val& out) const {
		out = this->read_field(a);
	}

	template<typename T, typename Val = T>
	void write_field(const typed_accessor<T>& a, const Val& in) {
		// TODO: we could use a direct assignment of const char* to strings
		//       but we'd have to handle it deep down in each individual
		//       implementation of raw_write_field
		T in_val = in;
		this->raw_write_field(a, &in_val);
	}

protected:
	[[nodiscard]] virtual const void* raw_read_field(const accessor& a) const = 0;
	virtual void raw_write_field(const accessor& a, const void* in) = 0;
};

template<>
inline void table_entry::read_field(const typed_accessor<std::string>& a, const char*& out) const {
	auto out_ptr = static_cast<const std::string*>(this->raw_read_field(a));
	if(out_ptr) {
		out = out_ptr->c_str();
	} else {
		out = "";
	}
}

template<typename F, typename... Args>
auto dispatch_lambda(ss_plugin_state_type st, F&& f, Args&&... args) {
	switch(st) {
	case SS_PLUGIN_ST_INT8:
		return std::forward<F>(f).template operator()<int8_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_INT16:
		return std::forward<F>(f).template operator()<int16_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_INT32:
		return std::forward<F>(f).template operator()<int32_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_INT64:
		return std::forward<F>(f).template operator()<int64_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_UINT8:
		return std::forward<F>(f).template operator()<uint8_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_UINT16:
		return std::forward<F>(f).template operator()<uint16_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_UINT32:
		return std::forward<F>(f).template operator()<uint32_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_UINT64:
		return std::forward<F>(f).template operator()<uint64_t>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_STRING:
		return std::forward<F>(f).template operator()<std::string>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_TABLE:
		return std::forward<F>(f).template operator()<base_table*>(std::forward<Args>(args)...);
	case SS_PLUGIN_ST_BOOL:
		return std::forward<F>(f).template operator()<bool>(std::forward<Args>(args)...);
	default:
#ifdef _MSC_VER
		_assume(0);
#else
		__builtin_unreachable();
#endif
	}
}

}  // namespace libsinsp::state
