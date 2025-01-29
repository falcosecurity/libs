/*
Copyright (C) 2024 The Falco Authors.

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

#include <libsinsp/state/table.h>
#include <libsinsp/plugin.h>

#define __CATCH_ERR_MSG(_ERR, _F)           \
	{                                       \
		try {                               \
			_F;                             \
		} catch(const std::exception& _e) { \
			_ERR = _e.what();               \
		} catch(...) {                      \
			_ERR = "unknown error";         \
		}                                   \
	}

#define __PLUGIN_STATETYPE_SWITCH(_kt)                                              \
	{                                                                               \
		switch(_kt) {                                                               \
		case ss_plugin_state_type::SS_PLUGIN_ST_INT8:                               \
			_X(int8_t, s8);                                                         \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_INT16:                              \
			_X(int16_t, s16);                                                       \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_INT32:                              \
			_X(int32_t, s32);                                                       \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_INT64:                              \
			_X(int64_t, s64);                                                       \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_UINT8:                              \
			_X(uint8_t, u8);                                                        \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_UINT16:                             \
			_X(uint16_t, u16);                                                      \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_UINT32:                             \
			_X(uint32_t, u32);                                                      \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_UINT64:                             \
			_X(uint64_t, u64);                                                      \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_STRING:                             \
			_X(std::string, str);                                                   \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_BOOL:                               \
			_X(bool, b);                                                            \
			break;                                                                  \
		case ss_plugin_state_type::SS_PLUGIN_ST_TABLE:                              \
			_X(libsinsp::state::base_table*, table);                                \
			break;                                                                  \
		default:                                                                    \
			throw sinsp_exception("can't convert plugin state type to typeinfo: " + \
			                      std::to_string(_kt));                             \
		}                                                                           \
	}

template<typename From, typename To>
static inline void convert_types(const From& from, To& to) {
	to = from;
}

// special cases for strings
template<>
inline void convert_types(const std::string& from, const char*& to) {
	to = from.c_str();
}

template<>
inline void convert_types(libsinsp::state::base_table* const& from, ss_plugin_table_t*& to) {
	to = static_cast<ss_plugin_table_t*>(from);
}

template<>
inline void convert_types(ss_plugin_table_t* const& from, libsinsp::state::base_table*& to) {
	to = static_cast<libsinsp::state::base_table*>(from);
}

template<typename KeyType>
void extract_key(const ss_plugin_state_data& key, KeyType& out) {
	throw sinsp_exception("unsupported key type");
}

template<>
void extract_key<uint64_t>(const ss_plugin_state_data& key, uint64_t& out) {
	out = key.u64;
}

template<>
void extract_key<int64_t>(const ss_plugin_state_data& key, int64_t& out) {
	out = key.u64;
}

//
// sinsp_field_accessor_wrapper implementation
//
libsinsp::state::sinsp_field_accessor_wrapper::~sinsp_field_accessor_wrapper() {
	if(!accessor) {
		return;
	}
#define _X(_type, _dtype)                                                                          \
	{                                                                                              \
		if(dynamic) {                                                                              \
			delete static_cast<libsinsp::state::dynamic_struct::field_accessor<_type>*>(accessor); \
		} else {                                                                                   \
			delete static_cast<libsinsp::state::static_struct::field_accessor<_type>*>(accessor);  \
		}                                                                                          \
		break;                                                                                     \
	}
	std::string tmp;
	__CATCH_ERR_MSG(tmp, { __PLUGIN_STATETYPE_SWITCH(data_type); });
#undef _X
}

libsinsp::state::sinsp_field_accessor_wrapper::sinsp_field_accessor_wrapper(
        libsinsp::state::sinsp_field_accessor_wrapper&& s) {
	this->accessor = s.accessor;
	this->dynamic = s.dynamic;
	this->data_type = s.data_type;
	this->subtable_key_type = s.subtable_key_type;
	s.accessor = nullptr;
}

libsinsp::state::sinsp_field_accessor_wrapper&
libsinsp::state::sinsp_field_accessor_wrapper::operator=(
        libsinsp::state::sinsp_field_accessor_wrapper&& s) {
	this->accessor = s.accessor;
	this->dynamic = s.dynamic;
	this->data_type = s.data_type;
	this->subtable_key_type = s.subtable_key_type;
	s.accessor = nullptr;
	return *this;
}

//
// table_accessor implementation
//
template<typename T>
void libsinsp::state::table_accessor::set(sinsp_table_owner* p, libsinsp::state::table<T>* t) {
	if(!t) {
		throw sinsp_exception("null table assigned to sinsp table wrapper");
	}
	if(!p) {
		throw sinsp_exception("null plugin assigned to sinsp table wrapper");
	}

	m_table = t;
	m_owner_plugin = p;

	input.name = m_table->name();
	input.table = this;
	input.key_type = m_table->key_info().type_id();
}

template void libsinsp::state::table_accessor::set<int8_t>(sinsp_table_owner* p,
                                                           libsinsp::state::table<int8_t>* t);
template void libsinsp::state::table_accessor::set<int16_t>(sinsp_table_owner* p,
                                                            libsinsp::state::table<int16_t>* t);
template void libsinsp::state::table_accessor::set<int32_t>(sinsp_table_owner* p,
                                                            libsinsp::state::table<int32_t>* t);
template void libsinsp::state::table_accessor::set<int64_t>(sinsp_table_owner* p,
                                                            libsinsp::state::table<int64_t>* t);
template void libsinsp::state::table_accessor::set<uint8_t>(sinsp_table_owner* p,
                                                            libsinsp::state::table<uint8_t>* t);
template void libsinsp::state::table_accessor::set<uint16_t>(sinsp_table_owner* p,
                                                             libsinsp::state::table<uint16_t>* t);
template void libsinsp::state::table_accessor::set<uint32_t>(sinsp_table_owner* p,
                                                             libsinsp::state::table<uint32_t>* t);
template void libsinsp::state::table_accessor::set<uint64_t>(sinsp_table_owner* p,
                                                             libsinsp::state::table<uint64_t>* t);
template void libsinsp::state::table_accessor::set<std::string>(
        sinsp_table_owner* p,
        libsinsp::state::table<std::string>* t);
template void libsinsp::state::table_accessor::set<bool>(sinsp_table_owner* p,
                                                         libsinsp::state::table<bool>* t);
// Do not instantiate the template for libsinsp::state::base_table* since a table cannot be used
// as a key for another table

void libsinsp::state::table_accessor::unset() {
	m_owner_plugin = nullptr;
	m_table = nullptr;

	input.name = nullptr;
	input.table = nullptr;
	input.key_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;
}

bool libsinsp::state::table_accessor::is_set() const {
	return m_table != nullptr;
}

const ss_plugin_table_fieldinfo* libsinsp::state::table_accessor::list_fields(ss_plugin_table_t* _t,
                                                                              uint32_t* nfields) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->list_fields(t->m_owner_plugin, nfields);
}

ss_plugin_table_field_t* libsinsp::state::table_accessor::get_field(
        ss_plugin_table_t* _t,
        const char* name,
        ss_plugin_state_type data_type) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->get_field(t->m_owner_plugin, name, data_type);
}

ss_plugin_table_field_t* libsinsp::state::table_accessor::add_field(
        ss_plugin_table_t* _t,
        const char* name,
        ss_plugin_state_type data_type) {
	auto t = static_cast<table_accessor*>(_t);

	if(data_type == ss_plugin_state_type::SS_PLUGIN_ST_TABLE) {
		t->m_owner_plugin->m_last_owner_err =
		        "can't add dynamic field of type table: " + std::string(name);
		return NULL;
	}

	return t->m_table->add_field(t->m_owner_plugin, name, data_type);
}

const char* libsinsp::state::table_accessor::get_name(ss_plugin_table_t* _t) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->name();
}

uint64_t libsinsp::state::table_accessor::get_size(ss_plugin_table_t* _t) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->get_size(t->m_owner_plugin);
}

ss_plugin_table_entry_t* libsinsp::state::table_accessor::get_entry(
        ss_plugin_table_t* _t,
        const ss_plugin_state_data* key) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->get_entry(t->m_owner_plugin, key);
}

void libsinsp::state::table_accessor::release_table_entry(ss_plugin_table_t* _t,
                                                          ss_plugin_table_entry_t* _e) {
	auto t = static_cast<table_accessor*>(_t);
	t->m_table->release_table_entry(t->m_owner_plugin, _e);
}

ss_plugin_bool libsinsp::state::table_accessor::iterate_entries(
        ss_plugin_table_t* _t,
        ss_plugin_table_iterator_func_t it,
        ss_plugin_table_iterator_state_t* s) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->iterate_entries(t->m_owner_plugin, it, s);
}

ss_plugin_rc libsinsp::state::table_accessor::clear(ss_plugin_table_t* _t) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->clear_entries(t->m_owner_plugin);
}

ss_plugin_rc libsinsp::state::table_accessor::erase_entry(ss_plugin_table_t* _t,
                                                          const ss_plugin_state_data* key) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->erase_entry(t->m_owner_plugin, key);
}

ss_plugin_table_entry_t* libsinsp::state::table_accessor::create_table_entry(
        ss_plugin_table_t* _t) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->create_table_entry(t->m_owner_plugin);
}

void libsinsp::state::table_accessor::destroy_table_entry(ss_plugin_table_t* _t,
                                                          ss_plugin_table_entry_t* _e) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->destroy_table_entry(t->m_owner_plugin, _e);
}

ss_plugin_table_entry_t* libsinsp::state::table_accessor::add_entry(ss_plugin_table_t* _t,
                                                                    const ss_plugin_state_data* key,
                                                                    ss_plugin_table_entry_t* _e) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->add_entry(t->m_owner_plugin, key, _e);
}

ss_plugin_rc libsinsp::state::table_accessor::read_entry_field(ss_plugin_table_t* _t,
                                                               ss_plugin_table_entry_t* _e,
                                                               const ss_plugin_table_field_t* f,
                                                               ss_plugin_state_data* out) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->read_entry_field(t->m_owner_plugin, _e, f, out);
}

ss_plugin_rc libsinsp::state::table_accessor::write_entry_field(ss_plugin_table_t* _t,
                                                                ss_plugin_table_entry_t* _e,
                                                                const ss_plugin_table_field_t* f,
                                                                const ss_plugin_state_data* in) {
	auto t = static_cast<table_accessor*>(_t);
	return t->m_table->write_entry_field(t->m_owner_plugin, _e, f, in);
}

//
// sinsp_table_input implementation
//
libsinsp::state::table_accessor::table_accessor() {
	// populate vtables
	reader_vtable.get_table_name = libsinsp::state::table_accessor::get_name;
	reader_vtable.get_table_size = libsinsp::state::table_accessor::get_size;
	reader_vtable.get_table_entry = libsinsp::state::table_accessor::get_entry;
	reader_vtable.read_entry_field = libsinsp::state::table_accessor::read_entry_field;
	reader_vtable.release_table_entry = libsinsp::state::table_accessor::release_table_entry;
	reader_vtable.iterate_entries = libsinsp::state::table_accessor::iterate_entries;
	writer_vtable.clear_table = libsinsp::state::table_accessor::clear;
	writer_vtable.erase_table_entry = libsinsp::state::table_accessor::erase_entry;
	writer_vtable.create_table_entry = libsinsp::state::table_accessor::create_table_entry;
	writer_vtable.destroy_table_entry = libsinsp::state::table_accessor::destroy_table_entry;
	writer_vtable.add_table_entry = libsinsp::state::table_accessor::add_entry;
	writer_vtable.write_entry_field = libsinsp::state::table_accessor::write_entry_field;
	fields_vtable.list_table_fields = libsinsp::state::table_accessor::list_fields;
	fields_vtable.add_table_field = libsinsp::state::table_accessor::add_field;
	fields_vtable.get_table_field = libsinsp::state::table_accessor::get_field;

	// fill-up input's legacy vtables for backward compatibility
	input.reader.get_table_name = reader_vtable.get_table_name;
	input.reader.get_table_size = reader_vtable.get_table_size;
	input.reader.get_table_entry = reader_vtable.get_table_entry;
	input.reader.read_entry_field = reader_vtable.read_entry_field;
	input.writer.clear_table = writer_vtable.clear_table;
	input.writer.erase_table_entry = writer_vtable.erase_table_entry;
	input.writer.create_table_entry = writer_vtable.create_table_entry;
	input.writer.destroy_table_entry = writer_vtable.destroy_table_entry;
	input.writer.add_table_entry = writer_vtable.add_table_entry;
	input.writer.write_entry_field = writer_vtable.write_entry_field;
	input.fields.list_table_fields = fields_vtable.list_table_fields;
	input.fields.add_table_field = fields_vtable.add_table_field;
	input.fields.get_table_field = fields_vtable.get_table_field;

	// bind input's vtables
	input.fields_ext = &fields_vtable;
	input.reader_ext = &reader_vtable;
	input.writer_ext = &writer_vtable;

	// fill-up with some default values
	input.table = nullptr;
	input.name = nullptr;
	input.key_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;
}

template<typename KeyType>
const ss_plugin_table_fieldinfo* libsinsp::state::built_in_table<KeyType>::list_fields(
        sinsp_table_owner* owner,
        uint32_t* nfields) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		this->m_field_list.clear();
		for(auto& info : *this->static_fields()) {
			ss_plugin_table_fieldinfo i;
			i.name = info.second.name().c_str();
			i.field_type = info.second.info().type_id();
			i.read_only = info.second.readonly();
			this->m_field_list.push_back(i);
		}
		for(auto& info : this->dynamic_fields()->fields()) {
			ss_plugin_table_fieldinfo i;
			i.name = info.second.name().c_str();
			i.field_type = info.second.info().type_id();
			i.read_only = false;
			this->m_field_list.push_back(i);
		}
		*nfields = this->m_field_list.size();
		return this->m_field_list.data();
	});
	return NULL;
}

template<typename KeyType>
ss_plugin_table_field_t* libsinsp::state::built_in_table<KeyType>::get_field(
        sinsp_table_owner* owner,
        const char* name,
        ss_plugin_state_type data_type) {
	libsinsp::state::static_struct::field_infos::const_iterator fixed_it;
	std::unordered_map<std::string, libsinsp::state::dynamic_struct::field_info>::const_iterator
	        dyn_it;
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		auto it = this->m_field_accessors.find(name);
		if(it != this->m_field_accessors.end()) {
			return static_cast<ss_plugin_table_field_t*>(it->second);
		}

		fixed_it = this->static_fields()->find(name);
		dyn_it = this->dynamic_fields()->fields().find(name);
		if(fixed_it != this->static_fields()->end() &&
		   dyn_it != this->dynamic_fields()->fields().end()) {
			// todo(jasondellaluce): plugins are not aware of the difference
			// between static and dynamic fields. Do we want to enforce
			// this limitation in the sinsp tables implementation as well?
			throw sinsp_exception("field is defined as both static and dynamic: " +
			                      std::string(name));
		}
	});

#define _X(_type, _dtype)                                                                   \
	{                                                                                       \
		auto acc = fixed_it->second.new_accessor<_type>();                                  \
		libsinsp::state::sinsp_field_accessor_wrapper acc_wrap;                             \
		acc_wrap.dynamic = false;                                                           \
		acc_wrap.data_type = data_type;                                                     \
		acc_wrap.accessor = new libsinsp::state::static_struct::field_accessor<_type>(acc); \
		owner->m_accessed_table_fields.push_back(std::move(acc_wrap));                      \
		this->m_field_accessors[name] = &owner->m_accessed_table_fields.back();             \
		return this->m_field_accessors[name];                                               \
	}
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		if(fixed_it != this->static_fields()->end()) {
			if(data_type != fixed_it->second.info().type_id()) {
				throw sinsp_exception("incompatible data types for static field: " +
				                      std::string(name));
			}
			__PLUGIN_STATETYPE_SWITCH(data_type);
		}
	});
#undef _X

#define _X(_type, _dtype)                                                                    \
	{                                                                                        \
		auto acc = dyn_it->second.new_accessor<_type>();                                     \
		libsinsp::state::sinsp_field_accessor_wrapper acc_wrap;                              \
		acc_wrap.dynamic = true;                                                             \
		acc_wrap.data_type = data_type;                                                      \
		acc_wrap.accessor = new libsinsp::state::dynamic_struct::field_accessor<_type>(acc); \
		owner->m_accessed_table_fields.push_back(std::move(acc_wrap));                       \
		this->m_field_accessors[name] = &owner->m_accessed_table_fields.back();              \
		return this->m_field_accessors[name];                                                \
	}
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		if(dyn_it != this->dynamic_fields()->fields().end()) {
			if(data_type != dyn_it->second.info().type_id()) {
				throw sinsp_exception("incompatible data types for dynamic field: " +
				                      std::string(name));
			}
			__PLUGIN_STATETYPE_SWITCH(data_type);
		}
		throw sinsp_exception("undefined field '" + std::string(name) + "' in table '" +
		                      std::string(this->name()) + "'");
	});
#undef _X

	return NULL;
}

template<typename KeyType>
ss_plugin_table_field_t* libsinsp::state::built_in_table<KeyType>::add_field(
        sinsp_table_owner* owner,
        const char* name,
        ss_plugin_state_type data_type) {
	if(this->static_fields()->find(name) != this->static_fields()->end()) {
		owner->m_last_owner_err =
		        "can't add dynamic field already defined as static: " + std::string(name);
		return NULL;
	}

#define _X(_type, _dtype)                                        \
	{                                                            \
		this->dynamic_fields()->template add_field<_type>(name); \
		break;                                                   \
	}
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		__PLUGIN_STATETYPE_SWITCH(data_type);
		return get_field(owner, name, data_type);
	});
#undef _X
	return NULL;
}

template<typename KeyType>
uint64_t libsinsp::state::built_in_table<KeyType>::get_size(sinsp_table_owner* owner) {
	return this->entries_count();
}

template<typename KeyType>
ss_plugin_table_entry_t* libsinsp::state::built_in_table<KeyType>::get_entry(
        sinsp_table_owner* owner,
        const ss_plugin_state_data* key) {
	// note: the C++ API returns a shared pointer, but in plugins we only
	// use raw pointers without increasing/decreasing/owning the refcount.
	// How can we do better than this?
	// todo(jasondellaluce): should we actually make plugins own some memory,
	// to guarantee that the shared_ptr returned is properly refcounted?
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		KeyType kk;
		extract_key(*key, kk);
		auto ret = this->get_entry(kk);
		if(ret != nullptr) {
			auto owned_ptr = owner->find_unset_accessed_table_entry();
			*owned_ptr = ret;
			return static_cast<ss_plugin_table_entry_t*>(owned_ptr);
		}
		throw sinsp_exception("get_entry found no element at given key");
		return NULL;
	});
	return NULL;
}

template<typename KeyType>
void libsinsp::state::built_in_table<KeyType>::release_table_entry(sinsp_table_owner* owner,
                                                                   ss_plugin_table_entry_t* _e) {
	static_cast<std::shared_ptr<libsinsp::state::table_entry>*>(_e)->reset();
}

template<typename KeyType>
ss_plugin_bool libsinsp::state::built_in_table<KeyType>::iterate_entries(
        sinsp_table_owner* owner,
        ss_plugin_table_iterator_func_t it,
        ss_plugin_table_iterator_state_t* s) {
	std::shared_ptr<libsinsp::state::table_entry> owned_ptr;
	std::function<bool(libsinsp::state::table_entry&)> iter = [&owned_ptr, &it, &s](auto& e) {
		owned_ptr.reset(&e, [](libsinsp::state::table_entry* p) {});
		return it(s, static_cast<ss_plugin_table_entry_t*>(&owned_ptr)) != 0;
	};

	__CATCH_ERR_MSG(owner->m_last_owner_err, { return this->foreach_entry(iter); });

	return false;
}

template<typename KeyType>
ss_plugin_rc libsinsp::state::built_in_table<KeyType>::clear_entries(sinsp_table_owner* owner) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		this->clear_entries();
		return SS_PLUGIN_SUCCESS;
	});
	return SS_PLUGIN_FAILURE;
}

template<typename KeyType>
ss_plugin_rc libsinsp::state::built_in_table<KeyType>::erase_entry(
        sinsp_table_owner* owner,
        const ss_plugin_state_data* key) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		KeyType kk;
		extract_key(*key, kk);
		if(this->erase_entry(kk)) {
			return SS_PLUGIN_SUCCESS;
		}
		owner->m_last_owner_err = "table entry not found";
		return SS_PLUGIN_FAILURE;
	});
	return SS_PLUGIN_FAILURE;
}

template<typename KeyType>
ss_plugin_table_entry_t* libsinsp::state::built_in_table<KeyType>::create_table_entry(
        sinsp_table_owner* owner) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		auto ret = this->new_entry().release();
		auto owned_ptr = owner->find_unset_accessed_table_entry();
		owned_ptr->reset(ret, [](libsinsp::state::table_entry* p) { /* do nothing */ });
		return static_cast<ss_plugin_table_entry_t*>(owned_ptr);
	});
	return NULL;
}

template<typename KeyType>
void libsinsp::state::built_in_table<KeyType>::destroy_table_entry(sinsp_table_owner* owner,
                                                                   ss_plugin_table_entry_t* _e) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		auto e = static_cast<std::shared_ptr<libsinsp::state::table_entry>*>(_e);
		auto ptr = std::unique_ptr<libsinsp::state::table_entry>(e->get());
		e->reset();
	});
}

template<typename KeyType>
ss_plugin_table_entry_t* libsinsp::state::built_in_table<KeyType>::add_entry(
        sinsp_table_owner* owner,
        const ss_plugin_state_data* key,
        ss_plugin_table_entry_t* _e) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		KeyType kk;
		extract_key(*key, kk);
		auto e = static_cast<std::shared_ptr<libsinsp::state::table_entry>*>(_e);
		auto ptr = std::unique_ptr<libsinsp::state::table_entry>(e->get());
		e->reset();
		auto owned_ptr = owner->find_unset_accessed_table_entry();
		*owned_ptr = this->add_entry(kk, std::move(ptr));
		return static_cast<ss_plugin_table_entry_t*>(owned_ptr);
	});
	return NULL;
}

template<typename KeyType>
ss_plugin_rc libsinsp::state::built_in_table<KeyType>::read_entry_field(
        sinsp_table_owner* owner,
        ss_plugin_table_entry_t* _e,
        const ss_plugin_table_field_t* f,
        ss_plugin_state_data* out) {
	auto a = static_cast<const libsinsp::state::sinsp_field_accessor_wrapper*>(f);
	auto e = static_cast<std::shared_ptr<libsinsp::state::table_entry>*>(_e);
	auto res = SS_PLUGIN_FAILURE;

#define _X(_type, _dtype)                                                                   \
	{                                                                                       \
		if(a->dynamic) {                                                                    \
			auto aa = static_cast<libsinsp::state::dynamic_struct::field_accessor<_type>*>( \
			        a->accessor);                                                           \
			e->get()->get_dynamic_field<_type>(*aa, out->_dtype);                           \
		} else {                                                                            \
			auto aa = static_cast<libsinsp::state::static_struct::field_accessor<_type>*>(  \
			        a->accessor);                                                           \
			e->get()->get_static_field<_type>(*aa, out->_dtype);                            \
		}                                                                                   \
		res = SS_PLUGIN_SUCCESS;                                                            \
		break;                                                                              \
	}
	__CATCH_ERR_MSG(owner->m_last_owner_err, { __PLUGIN_STATETYPE_SWITCH(a->data_type); });
#undef _X

#define _X(_type, _dtype)                                                    \
	{                                                                        \
		auto st = static_cast<libsinsp::state::table<_type>*>(subtable_ptr); \
		auto& slot = owner->find_unset_ephemeral_table();                    \
		slot.set<_type>(owner, st);                                          \
		out->table = &slot.input;                                            \
	};
	if(a->data_type == ss_plugin_state_type::SS_PLUGIN_ST_TABLE) {
		auto* subtable_ptr = out->table;
		if(!subtable_ptr) {
			t->m_owner_plugin->m_last_owner_err.clear();
			return SS_PLUGIN_FAILURE;
		}
		__CATCH_ERR_MSG(owner->m_last_owner_err,
		                { __PLUGIN_STATETYPE_SWITCH(a->subtable_key_type); });
	}
#undef _X

	return res;
}

template<typename KeyType>
ss_plugin_rc libsinsp::state::built_in_table<KeyType>::write_entry_field(
        sinsp_table_owner* owner,
        ss_plugin_table_entry_t* _e,
        const ss_plugin_table_field_t* f,
        const ss_plugin_state_data* in) {
	auto a = static_cast<const libsinsp::state::sinsp_field_accessor_wrapper*>(f);
	auto e = static_cast<std::shared_ptr<libsinsp::state::table_entry>*>(_e);

	// todo(jasondellaluce): drop this check once we start supporting this
	if(a->data_type == ss_plugin_state_type::SS_PLUGIN_ST_TABLE) {
		owner->m_last_owner_err = "writing to table fields is currently not supported";
		return SS_PLUGIN_FAILURE;
	}

#define _X(_type, _dtype)                                                                   \
	{                                                                                       \
		if(a->dynamic) {                                                                    \
			auto aa = static_cast<libsinsp::state::dynamic_struct::field_accessor<_type>*>( \
			        a->accessor);                                                           \
			_type val;                                                                      \
			convert_types(in->_dtype, val);                                                 \
			e->get()->set_dynamic_field<_type>(*aa, val);                                   \
		} else {                                                                            \
			auto aa = static_cast<libsinsp::state::static_struct::field_accessor<_type>*>(  \
			        a->accessor);                                                           \
			_type val;                                                                      \
			convert_types(in->_dtype, val);                                                 \
			e->get()->set_static_field<_type>(*aa, val);                                    \
		}                                                                                   \
		return SS_PLUGIN_SUCCESS;                                                           \
	}
	__CATCH_ERR_MSG(owner->m_last_owner_err, { __PLUGIN_STATETYPE_SWITCH(a->data_type); });
#undef _X
	return SS_PLUGIN_FAILURE;
}

template class libsinsp::state::built_in_table<int64_t>;
template class libsinsp::state::built_in_table<uint64_t>;
