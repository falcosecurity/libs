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
#include <libsinsp/state/borrowed_state_data.h>
#include <libsinsp/state/type_info.h>

#include <memory>
#include <vector>

namespace libsinsp::state {

class accessor {
public:
	using reader_fn = borrowed_state_data (*)(const void*, size_t);
	using writer_fn = void (*)(void*, size_t, const borrowed_state_data&);

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

	private:
		std::unique_ptr<const accessor> m_ptr;
	};

	class ptr {
	public:
		explicit ptr(std::unique_ptr<const accessor> m_ptr): m_ptr(std::move(m_ptr)) {}
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

	explicit accessor(ss_plugin_state_type type_id,
	                  reader_fn reader,
	                  writer_fn writer,
	                  size_t index):
	        m_type_id(type_id),
	        m_reader(reader),
	        m_writer(writer),
	        m_index(index) {}
	virtual ~accessor() = default;

	[[nodiscard]] ss_plugin_state_type type_info() const { return m_type_id; }

	template<typename T>
	void assert_type() const {
		if(type_id_of<T>() != m_type_id) {
			std::string name = type_name(m_type_id);
			throw sinsp_exception(std::string("type mismatch in accessor: expected ") +
			                      type_name<T>() + ", got " + name);
		}
	}

	template<typename T>
	[[nodiscard]] typed_ref<T> as() const {
		assert_type<T>();
		return typed_ref<T>(*this);
	}

	static ptr null() { return ptr(std::unique_ptr<const accessor>(nullptr)); }

	[[nodiscard]] reader_fn reader() const { return m_reader; }
	[[nodiscard]] writer_fn writer() const { return m_writer; }
	[[nodiscard]] size_t index() const { return m_index; }

protected:
	ss_plugin_state_type m_type_id;
	reader_fn m_reader;
	writer_fn m_writer;
	size_t m_index;
};

/**
 * @brief Base class for entries of a state table.
 */
class table_entry {
public:
	virtual ~table_entry() = default;

	template<typename T>
	T read_field(const accessor::typed_ref<T>& a) const {
		T val{};
		this->raw_read_field(a).template borrow_to<libsinsp::state::type_id_of<T>(), T>(val);
		return val;
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

	void read_field(const accessor::typed_ref<std::string>& a, const char*& out) const {
		const auto val = this->raw_read_field(a);
		if(val.data().str == nullptr) {
			out = "";
		} else {
			out = val.data().str;
		}
	}

	template<typename T, typename Val = T>
	void write_field(const accessor::typed_ref<T>& a, const Val& in) {
		borrowed_state_data in_val =
		        borrowed_state_data::from<libsinsp::state::type_id_of<T>(), Val>(in);
		this->raw_write_field(a, in_val);
	}

	template<typename T, typename Val = T>
	void write_field(const accessor::typed_ptr<T>& a, const Val& in) {
		write_field(a.as_ref(), in);
	}

	[[nodiscard]] borrowed_state_data raw_read_field(const accessor& a) const {
		return a.reader()(this, a.index());
	}

	void raw_write_field(const accessor& a, const borrowed_state_data& in) {
		a.writer()(this, a.index(), in);
	}
};

class table_fields {
public:
	virtual ~table_fields() = default;

	virtual void list_fields(std::vector<ss_plugin_table_fieldinfo>& out) const = 0;

	template<typename T>
	accessor::typed_ptr<T> get_field(const char* name) {
		return get_field(name, type_id_of<T>()).template into<T>();
	}

	virtual accessor::ptr get_field(const char* name, ss_plugin_state_type type_id) = 0;

	template<typename T>
	accessor::typed_ptr<T> add_field(const char* name) {
		return add_field(name, type_id_of<T>()).template into<T>();
	}

	virtual accessor::ptr add_field(const char* name, ss_plugin_state_type type_id) = 0;
};

}  // namespace libsinsp::state
