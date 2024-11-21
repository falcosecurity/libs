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

#include "table.h"
#include "plugin.h"

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

static inline ss_plugin_state_type typeinfo_to_state_type(const libsinsp::state::typeinfo& i) {
	switch(i.index()) {
	case libsinsp::state::typeinfo::index_t::TI_INT8:
		return ss_plugin_state_type::SS_PLUGIN_ST_INT8;
	case libsinsp::state::typeinfo::index_t::TI_INT16:
		return ss_plugin_state_type::SS_PLUGIN_ST_INT16;
	case libsinsp::state::typeinfo::index_t::TI_INT32:
		return ss_plugin_state_type::SS_PLUGIN_ST_INT32;
	case libsinsp::state::typeinfo::index_t::TI_INT64:
		return ss_plugin_state_type::SS_PLUGIN_ST_INT64;
	case libsinsp::state::typeinfo::index_t::TI_UINT8:
		return ss_plugin_state_type::SS_PLUGIN_ST_UINT8;
	case libsinsp::state::typeinfo::index_t::TI_UINT16:
		return ss_plugin_state_type::SS_PLUGIN_ST_UINT16;
	case libsinsp::state::typeinfo::index_t::TI_UINT32:
		return ss_plugin_state_type::SS_PLUGIN_ST_UINT32;
	case libsinsp::state::typeinfo::index_t::TI_UINT64:
		return ss_plugin_state_type::SS_PLUGIN_ST_UINT64;
	case libsinsp::state::typeinfo::index_t::TI_STRING:
		return ss_plugin_state_type::SS_PLUGIN_ST_STRING;
	case libsinsp::state::typeinfo::index_t::TI_BOOL:
		return ss_plugin_state_type::SS_PLUGIN_ST_BOOL;
	case libsinsp::state::typeinfo::index_t::TI_TABLE:
		return ss_plugin_state_type::SS_PLUGIN_ST_TABLE;
	default:
		throw sinsp_exception("can't convert typeinfo to plugin state type: " +
		                      std::to_string(i.index()));
	}
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

template<typename KeyType>
const ss_plugin_table_fieldinfo* libsinsp::state::built_in_table<KeyType>::list_fields(
        sinsp_plugin* owner,
        uint32_t* nfields) {
	__CATCH_ERR_MSG(owner->m_last_owner_err, {
		this->m_field_list.clear();
		for(auto& info : *this->static_fields()) {
			ss_plugin_table_fieldinfo i;
			i.name = info.second.name().c_str();
			i.field_type = typeinfo_to_state_type(info.second.info());
			i.read_only = info.second.readonly();
			this->m_field_list.push_back(i);
		}
		for(auto& info : this->dynamic_fields()->fields()) {
			ss_plugin_table_fieldinfo i;
			i.name = info.second.name().c_str();
			i.field_type = typeinfo_to_state_type(info.second.info());
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
        sinsp_plugin* owner,
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
			if(data_type != typeinfo_to_state_type(fixed_it->second.info())) {
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
			if(data_type != typeinfo_to_state_type(dyn_it->second.info())) {
				throw sinsp_exception("incompatible data types for dynamic field: " +
				                      std::string(name));
			}
			__PLUGIN_STATETYPE_SWITCH(data_type);
		}
		throw sinsp_exception("undefined field '" + std::string(name) + "' in table '" +
		                      this->m_name + "'");
	});
#undef _X

	return NULL;
}

template<typename KeyType>
ss_plugin_table_field_t* libsinsp::state::built_in_table<KeyType>::add_field(
        sinsp_plugin* owner,
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
const char* libsinsp::state::built_in_table<KeyType>::get_name(sinsp_plugin* owner) {
	return this->m_name.c_str();
}

template<typename KeyType>
uint64_t libsinsp::state::built_in_table<KeyType>::get_size(sinsp_plugin* owner) {
	return this->entries_count();
}

template<typename KeyType>
ss_plugin_table_entry_t* libsinsp::state::built_in_table<KeyType>::get_entry(
        sinsp_plugin* owner,
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
void libsinsp::state::built_in_table<KeyType>::release_table_entry(sinsp_plugin* owner,
                                                                   ss_plugin_table_entry_t* _e) {
	static_cast<std::shared_ptr<libsinsp::state::table_entry>*>(_e)->reset();
}

template<typename KeyType>
ss_plugin_bool libsinsp::state::built_in_table<KeyType>::iterate_entries(
        sinsp_plugin* owner,
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

template class libsinsp::state::built_in_table<int64_t>;
template class libsinsp::state::built_in_table<uint64_t>;
