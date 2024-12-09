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

template class libsinsp::state::built_in_table<int64_t>;
template class libsinsp::state::built_in_table<uint64_t>;
