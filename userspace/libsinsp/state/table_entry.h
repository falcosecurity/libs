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
#include <memory>

namespace libsinsp::state {

class accessor {
public:
	template<typename T>
	class typed_ref {
	public:
		explicit typed_ref(const accessor& ref): m_ref(ref) {}

		operator const accessor&() const { return m_ref; }

	private:
		const accessor& m_ref;
	};

	template<typename T>
	class typed_ptr {
	public:
		typed_ptr(): m_ptr(nullptr) {}
		explicit typed_ptr(std::unique_ptr<const accessor> m_ptr): m_ptr(std::move(m_ptr)) {}
		bool operator==(const typed_ptr<T>& other) const { return m_ptr == other.m_ptr; }
		bool operator==(std::nullptr_t) const { return m_ptr == nullptr; }
		bool operator!=(const typed_ptr<T>& other) const { return m_ptr != other.m_ptr; }
		bool operator!=(std::nullptr_t) const { return m_ptr != nullptr; }

		typed_ref<T> as_ref() const { return m_ptr->as<T>(); }
		std::unique_ptr<const accessor> release() { return std::move(m_ptr); }

	private:
		std::unique_ptr<const accessor> m_ptr;
	};

	class ptr {
	public:
		explicit ptr(std::unique_ptr<const accessor> m_ptr): m_ptr(std::move(m_ptr)) {}
		template<typename T>
		explicit ptr(typed_ptr<T> typed): m_ptr(typed.release()) {}
		bool operator==(const ptr& other) const { return m_ptr == other.m_ptr; }
		bool operator==(std::nullptr_t) const { return m_ptr == nullptr; }
		bool operator!=(const ptr& other) const { return m_ptr != other.m_ptr; }
		bool operator!=(std::nullptr_t) const { return m_ptr != nullptr; }

		template<typename T>
		[[nodiscard]] typed_ptr<T> into() {
			if(m_ptr) {
				m_ptr->assert_type<T>();
			}
			return typed_ptr<T>(std::move(m_ptr));
		}

		template<typename T>
		[[nodiscard]] typed_ref<T> as() const {
			return m_ptr->as<T>();
		}

		[[nodiscard]] const accessor* raw_ptr() const { return m_ptr.get(); }

	private:
		std::unique_ptr<const accessor> m_ptr;
	};

	explicit accessor(const typeinfo& type_info): m_type_info(type_info) {}
	virtual ~accessor() = default;

	[[nodiscard]] typeinfo type_info() const { return m_type_info; }

	template<typename T>
	void assert_type() const {
		if(typeinfo::of<T>() != m_type_info) {
			throw sinsp_exception(std::string("type mismatch in accessor: expected ") +
			                      typeinfo::of<T>().name() + ", got " + m_type_info.name());
		}
	}

	template<typename T>
	[[nodiscard]] typed_ref<T> as() const {
		assert_type<T>();
		return typed_ref<T>(*this);
	}

	static ptr null() { return ptr(std::unique_ptr<const accessor>(nullptr)); }

protected:
	typeinfo m_type_info;
};

/**
 * @brief Base class for entries of a state table.
 */
class table_entry {
public:
	virtual ~table_entry() = default;

	template<typename T>
	T read_field(const accessor::typed_ref<T>& a) const {
		auto out = static_cast<const T*>(this->raw_read_field(a));
		if(out == nullptr) {
			return {};
		}
		return *out;
	}

	template<typename T, typename Val = T>
	void read_field(const accessor::typed_ref<T>& a, Val& out) const {
		out = this->read_field(a);
	}

	template<typename T>
	T read_field(const accessor::typed_ptr<T>& a) const {
		return this->read_field(a.as_ref());
	}

	template<typename T, typename Val = T>
	void read_field(const accessor::typed_ptr<T>& a, Val& out) const {
		this->read_field(a.as_ref(), out);
	}

	template<typename T, typename Val = T>
	void write_field(const accessor::typed_ref<T>& a, const Val& in) {
		// TODO: we could use a direct assignment of const char* to strings
		//       but we'd have to handle it deep down in each individual
		//       implementation of raw_write_field
		T in_val = in;
		this->raw_write_field(a, &in_val);
	}

	template<typename T, typename Val = T>
	void write_field(const accessor::typed_ptr<T>& a, const Val& in) {
		write_field(a.as_ref(), in);
	}

protected:
	[[nodiscard]] virtual const void* raw_read_field(const accessor& a) const = 0;
	virtual void raw_write_field(const accessor& a, const void* in) = 0;
};

template<>
inline void table_entry::read_field(const accessor::typed_ref<std::string>& a,
                                    const char*& out) const {
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
