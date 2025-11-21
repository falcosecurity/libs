// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

static void noop_release_table_entry(ss_plugin_table_t*, ss_plugin_table_entry_t*) {}

static ss_plugin_bool noop_iterate_entries(ss_plugin_table_t*,
                                           ss_plugin_table_iterator_func_t,
                                           ss_plugin_table_iterator_state_t*) {
	return 0;
}

struct owned_table_input_deleter {
	void operator()(ss_plugin_table_input* in) {
		delete in->reader_ext;
		delete in->writer_ext;
		delete in->fields_ext;
		delete in;
	}
};

using owned_table_input_t = std::shared_ptr<ss_plugin_table_input>;

// note(jasondellaluce): here we assume that the api version has major number v3
// todo(jasondellaluce): update the repairing logic and safety checks
// when switching to a v4 minor/major plugin API version
static inline owned_table_input_t copy_and_check_table_input(const sinsp_plugin* p,
                                                             const ss_plugin_table_input* in) {
	std::string errprefix = "failure in adding state table defined by plugin '" + p->name() + "': ";
	if(!in) {
		throw sinsp_exception(errprefix + "input is null");
	}
	if(!in->name) {
		throw sinsp_exception(errprefix + "name is null");
	}

	owned_table_input_t res(new ss_plugin_table_input(), owned_table_input_deleter());
	res->name = in->name;
	res->key_type = in->key_type;
	res->table = in->table;
	res->reader = in->reader;
	res->writer = in->writer;
	res->fields = in->fields;

	// note: before minor v1, we didn't have the "extended" vtables for state tables,
	// so we need to recreate them from the information we had available before,
	// plus adding "no-op" implementations of all the functions not available before v1
	res->reader_ext = new ss_plugin_table_reader_vtable_ext();
	res->writer_ext = new ss_plugin_table_writer_vtable_ext();
	res->fields_ext = new ss_plugin_table_fields_vtable_ext();
	if(p->required_api_version().minor() < 1) {
		res->reader_ext->get_table_name = res->reader.get_table_name;
		res->reader_ext->get_table_size = res->reader.get_table_size;
		res->reader_ext->get_table_entry = res->reader.get_table_entry;
		res->reader_ext->read_entry_field = res->reader.read_entry_field;
		res->reader_ext->release_table_entry = noop_release_table_entry;
		res->reader_ext->iterate_entries = noop_iterate_entries;

		res->writer_ext->clear_table = res->writer.clear_table;
		res->writer_ext->erase_table_entry = res->writer.erase_table_entry;
		res->writer_ext->create_table_entry = res->writer.create_table_entry;
		res->writer_ext->destroy_table_entry = res->writer.destroy_table_entry;
		res->writer_ext->add_table_entry = res->writer.add_table_entry;
		res->writer_ext->write_entry_field = res->writer.write_entry_field;

		res->fields_ext->list_table_fields = res->fields.list_table_fields;
		res->fields_ext->get_table_field = res->fields.get_table_field;
		res->fields_ext->add_table_field = res->fields.add_table_field;
	} else {
		if(!in->reader_ext || !in->writer_ext || !in->fields_ext) {
			throw sinsp_exception(errprefix + "extended vtables must all be defined");
		}

		res->reader_ext->get_table_name = in->reader_ext->get_table_name;
		res->reader_ext->get_table_size = in->reader_ext->get_table_size;
		res->reader_ext->get_table_entry = in->reader_ext->get_table_entry;
		res->reader_ext->read_entry_field = in->reader_ext->read_entry_field;
		res->reader_ext->release_table_entry = in->reader_ext->release_table_entry;
		res->reader_ext->iterate_entries = in->reader_ext->iterate_entries;

		res->writer_ext->clear_table = in->writer_ext->clear_table;
		res->writer_ext->erase_table_entry = in->writer_ext->erase_table_entry;
		res->writer_ext->create_table_entry = in->writer_ext->create_table_entry;
		res->writer_ext->destroy_table_entry = in->writer_ext->destroy_table_entry;
		res->writer_ext->add_table_entry = in->writer_ext->add_table_entry;
		res->writer_ext->write_entry_field = in->writer_ext->write_entry_field;

		res->fields_ext->list_table_fields = in->fields_ext->list_table_fields;
		res->fields_ext->get_table_field = in->fields_ext->get_table_field;
		res->fields_ext->add_table_field = in->fields_ext->add_table_field;
	}

	if((!res->reader_ext->get_table_name ||
	    res->reader_ext->get_table_name != res->reader.get_table_name) ||
	   (!res->reader_ext->get_table_size ||
	    res->reader_ext->get_table_size != res->reader.get_table_size) ||
	   (!res->reader_ext->get_table_entry ||
	    res->reader_ext->get_table_entry != res->reader.get_table_entry) ||
	   (!res->reader_ext->read_entry_field ||
	    res->reader_ext->read_entry_field != res->reader.read_entry_field) ||
	   !res->reader_ext->release_table_entry || !res->reader_ext->iterate_entries) {
		throw sinsp_exception(errprefix + "broken or inconsistent reader vtables");
	}

	if((!res->writer_ext->clear_table || res->writer_ext->clear_table != res->writer.clear_table) ||
	   (!res->writer_ext->erase_table_entry ||
	    res->writer_ext->erase_table_entry != res->writer.erase_table_entry) ||
	   (!res->writer_ext->create_table_entry ||
	    res->writer_ext->create_table_entry != res->writer.create_table_entry) ||
	   (!res->writer_ext->destroy_table_entry ||
	    res->writer_ext->destroy_table_entry != res->writer.destroy_table_entry) ||
	   (!res->writer_ext->add_table_entry ||
	    res->writer_ext->add_table_entry != res->writer.add_table_entry) ||
	   (!res->writer_ext->write_entry_field ||
	    res->writer_ext->write_entry_field != res->writer.write_entry_field)) {
		throw sinsp_exception(errprefix + "broken or inconsistent writer vtables");
	}

	if((!res->fields_ext->list_table_fields ||
	    res->fields_ext->list_table_fields != res->fields.list_table_fields) ||
	   (!res->fields_ext->get_table_field ||
	    res->fields_ext->get_table_field != res->fields.get_table_field) ||
	   (!res->fields_ext->add_table_field ||
	    res->fields_ext->add_table_field != res->fields.add_table_field)) {
		throw sinsp_exception(errprefix + "broken or inconsistent fields vtables");
	}

	return res;
}

static inline std::string table_input_error_prefix(const libsinsp::state::sinsp_table_owner* o,
                                                   ss_plugin_table_input* i) {
	auto plugin = dynamic_cast<const sinsp_plugin*>(o);
	if(plugin) {
		return "error in state table '" + std::string(i->name) + "' defined by plugin '" +
		       plugin->name() + "': ";

	} else {
		return "error in state table '" + std::string(i->name) + "': ";
	}
}

// wraps instances of ss_plugin_table_input and makes them comply
// to the libsinsp::state::table state tables definition.
template<typename KeyType>
struct plugin_table_wrapper : public libsinsp::state::table<KeyType> {
	plugin_table_wrapper(sinsp_plugin* o, const ss_plugin_table_input* i):
	        libsinsp::state::table<KeyType>(),
	        m_owner(o),
	        m_input(copy_and_check_table_input(o, i)) {
		auto t = libsinsp::state::type_id_of<KeyType>();
		if(m_input->key_type != t) {
			throw sinsp_exception(
			        table_input_error_prefix(m_owner, m_input.get()) +
			        "invalid key type: " + std::string(libsinsp::state::type_name(t)));
		}
	}

	virtual ~plugin_table_wrapper() = default;
	plugin_table_wrapper(plugin_table_wrapper&&) = default;
	plugin_table_wrapper& operator=(plugin_table_wrapper&&) = default;
	plugin_table_wrapper(const plugin_table_wrapper& s) = delete;
	plugin_table_wrapper& operator=(const plugin_table_wrapper& s) = delete;

	sinsp_plugin* m_owner;
	owned_table_input_t m_input;

	const char* name() const override { return m_input->name; }

	const ss_plugin_table_fieldinfo* list_fields(libsinsp::state::sinsp_table_owner* owner,
	                                             uint32_t* nfields) override;

	ss_plugin_table_field_t* get_field(libsinsp::state::sinsp_table_owner* owner,
	                                   const char* name,
	                                   ss_plugin_state_type data_type) override;

	ss_plugin_table_field_t* add_field(libsinsp::state::sinsp_table_owner* owner,
	                                   const char* name,
	                                   ss_plugin_state_type data_type) override;

	uint64_t get_size(libsinsp::state::sinsp_table_owner* owner) override;

	ss_plugin_table_entry_t* get_entry(libsinsp::state::sinsp_table_owner* owner,
	                                   const ss_plugin_state_data* key) override;

	void release_table_entry(libsinsp::state::sinsp_table_owner* owner,
	                         ss_plugin_table_entry_t* _e) override;

	ss_plugin_bool iterate_entries(libsinsp::state::sinsp_table_owner* owner,
	                               ss_plugin_table_iterator_func_t it,
	                               ss_plugin_table_iterator_state_t* s) override;

	ss_plugin_rc clear_entries(libsinsp::state::sinsp_table_owner* owner) override;

	ss_plugin_rc erase_entry(libsinsp::state::sinsp_table_owner* owner,
	                         const ss_plugin_state_data* key) override;

	ss_plugin_table_entry_t* create_table_entry(libsinsp::state::sinsp_table_owner* owner) override;

	void destroy_table_entry(libsinsp::state::sinsp_table_owner* owner,
	                         ss_plugin_table_entry_t* _e) override;

	ss_plugin_table_entry_t* add_entry(libsinsp::state::sinsp_table_owner* owner,
	                                   const ss_plugin_state_data* key,
	                                   ss_plugin_table_entry_t* _e) override;

	ss_plugin_rc read_entry_field(libsinsp::state::sinsp_table_owner* owner,
	                              ss_plugin_table_entry_t* _e,
	                              const ss_plugin_table_field_t* f,
	                              ss_plugin_state_data* out) override;

	ss_plugin_rc write_entry_field(libsinsp::state::sinsp_table_owner* owner,
	                               ss_plugin_table_entry_t* _e,
	                               const ss_plugin_table_field_t* f,
	                               const ss_plugin_state_data* in) override;
};

template<typename KeyType>
const ss_plugin_table_fieldinfo* plugin_table_wrapper<KeyType>::list_fields(
        libsinsp::state::sinsp_table_owner* owner,
        uint32_t* nfields) {
	auto ret = m_input->fields_ext->list_table_fields(m_input->table, nfields);
	if(ret == NULL) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_table_field_t* plugin_table_wrapper<KeyType>::get_field(
        libsinsp::state::sinsp_table_owner* owner,
        const char* name,
        ss_plugin_state_type data_type) {
	auto ret = m_input->fields_ext->get_table_field(m_input->table, name, data_type);
	if(ret == NULL) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_table_field_t* plugin_table_wrapper<KeyType>::add_field(
        libsinsp::state::sinsp_table_owner* owner,
        const char* name,
        ss_plugin_state_type data_type) {
	auto ret = m_input->fields_ext->add_table_field(m_input->table, name, data_type);
	if(ret == NULL) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
uint64_t plugin_table_wrapper<KeyType>::get_size(libsinsp::state::sinsp_table_owner* owner) {
	auto ret = m_input->reader_ext->get_table_size(m_input->table);
	if(ret == ((uint64_t)-1)) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_table_entry_t* plugin_table_wrapper<KeyType>::get_entry(
        libsinsp::state::sinsp_table_owner* owner,
        const ss_plugin_state_data* key) {
	auto ret = m_input->reader_ext->get_table_entry(m_input->table, key);
	if(ret == NULL) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
void plugin_table_wrapper<KeyType>::release_table_entry(libsinsp::state::sinsp_table_owner* owner,
                                                        ss_plugin_table_entry_t* _e) {
	m_input->reader_ext->release_table_entry(m_input->table, _e);
}

template<typename KeyType>
ss_plugin_bool plugin_table_wrapper<KeyType>::iterate_entries(
        libsinsp::state::sinsp_table_owner* owner,
        ss_plugin_table_iterator_func_t it,
        ss_plugin_table_iterator_state_t* s) {
	return m_input->reader_ext->iterate_entries(m_input->table, it, s);
}

template<typename KeyType>
ss_plugin_rc plugin_table_wrapper<KeyType>::clear_entries(
        libsinsp::state::sinsp_table_owner* owner) {
	auto ret = m_input->writer_ext->clear_table(m_input->table);
	if(ret == SS_PLUGIN_FAILURE) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_rc plugin_table_wrapper<KeyType>::erase_entry(libsinsp::state::sinsp_table_owner* owner,
                                                        const ss_plugin_state_data* key) {
	auto ret = m_input->writer_ext->erase_table_entry(m_input->table, key);
	if(ret == SS_PLUGIN_FAILURE) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_table_entry_t* plugin_table_wrapper<KeyType>::create_table_entry(
        libsinsp::state::sinsp_table_owner* owner) {
	auto ret = m_input->writer_ext->create_table_entry(m_input->table);
	if(ret == NULL) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
void plugin_table_wrapper<KeyType>::destroy_table_entry(libsinsp::state::sinsp_table_owner* owner,
                                                        ss_plugin_table_entry_t* _e) {
	m_input->writer_ext->destroy_table_entry(m_input->table, _e);
}

template<typename KeyType>
ss_plugin_table_entry_t* plugin_table_wrapper<KeyType>::add_entry(
        libsinsp::state::sinsp_table_owner* owner,
        const ss_plugin_state_data* key,
        ss_plugin_table_entry_t* _e) {
	auto ret = m_input->writer_ext->add_table_entry(m_input->table, key, _e);
	if(ret == NULL) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_rc plugin_table_wrapper<KeyType>::read_entry_field(
        libsinsp::state::sinsp_table_owner* owner,
        ss_plugin_table_entry_t* _e,
        const ss_plugin_table_field_t* f,
        ss_plugin_state_data* out) {
	auto ret = m_input->reader_ext->read_entry_field(m_input->table, _e, f, out);
	if(ret == SS_PLUGIN_FAILURE) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

template<typename KeyType>
ss_plugin_rc plugin_table_wrapper<KeyType>::write_entry_field(
        libsinsp::state::sinsp_table_owner* owner,
        ss_plugin_table_entry_t* _e,
        const ss_plugin_table_field_t* f,
        const ss_plugin_state_data* in) {
	auto ret = m_input->writer_ext->write_entry_field(m_input->table, _e, f, in);
	if(ret == SS_PLUGIN_FAILURE) {
		owner->m_last_owner_err = m_owner->get_last_error();
	}
	return ret;
}

// the following table api symbols act as dispatcher for the table API
// interface, which is implemented through the type ss_plugin_table_input.
// For sinsp-defined tables, the ss_plugin_table_input is a wrapper around
// the libsinsp::state::table interface. For plugin-defined tables, the
// ss_plugin_table_input is provided by the table-owner plugin itself.
static const ss_plugin_table_fieldinfo* dispatch_list_fields(ss_plugin_table_t* _t,
                                                             uint32_t* nfields) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->fields_ext->list_table_fields(t->table, nfields);
}

static ss_plugin_table_field_t* dispatch_get_field(ss_plugin_table_t* _t,
                                                   const char* name,
                                                   ss_plugin_state_type data_type) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->fields_ext->get_table_field(t->table, name, data_type);
}

static ss_plugin_table_field_t* dispatch_add_field(ss_plugin_table_t* _t,
                                                   const char* name,
                                                   ss_plugin_state_type data_type) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->fields_ext->add_table_field(t->table, name, data_type);
}

static const char* dispatch_get_name(ss_plugin_table_t* _t) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->reader_ext->get_table_name(t->table);
}

static uint64_t dispatch_get_size(ss_plugin_table_t* _t) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->reader_ext->get_table_size(t->table);
}

static ss_plugin_table_entry_t* dispatch_get_entry(ss_plugin_table_t* _t,
                                                   const ss_plugin_state_data* key) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->reader_ext->get_table_entry(t->table, key);
}

static ss_plugin_rc dispatch_read_entry_field(ss_plugin_table_t* _t,
                                              ss_plugin_table_entry_t* e,
                                              const ss_plugin_table_field_t* f,
                                              ss_plugin_state_data* out) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->reader_ext->read_entry_field(t->table, e, f, out);
}

static void dispatch_release_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* e) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	t->reader_ext->release_table_entry(t->table, e);
}

static ss_plugin_bool dispatch_iterate_entries(ss_plugin_table_t* _t,
                                               ss_plugin_table_iterator_func_t it,
                                               ss_plugin_table_iterator_state_t* s) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->reader_ext->iterate_entries(t->table, it, s);
}

static ss_plugin_rc dispatch_clear(ss_plugin_table_t* _t) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->writer_ext->clear_table(t->table);
}

static ss_plugin_rc dispatch_erase_entry(ss_plugin_table_t* _t, const ss_plugin_state_data* key) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->writer_ext->erase_table_entry(t->table, key);
}

static ss_plugin_table_entry_t* dispatch_create_table_entry(ss_plugin_table_t* _t) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->writer_ext->create_table_entry(t->table);
}

static void dispatch_destroy_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* e) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->writer_ext->destroy_table_entry(t->table, e);
}

static ss_plugin_table_entry_t* dispatch_add_entry(ss_plugin_table_t* _t,
                                                   const ss_plugin_state_data* key,
                                                   ss_plugin_table_entry_t* entry) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->writer_ext->add_table_entry(t->table, key, entry);
}

static ss_plugin_rc dispatch_write_entry_field(ss_plugin_table_t* _t,
                                               ss_plugin_table_entry_t* e,
                                               const ss_plugin_table_field_t* f,
                                               const ss_plugin_state_data* in) {
	auto t = static_cast<ss_plugin_table_input*>(_t);
	return t->writer_ext->write_entry_field(t->table, e, f, in);
}

//
// sinsp_plugin table helpers implementation
//
void sinsp_plugin::table_field_api(ss_plugin_table_fields_vtable& out,
                                   ss_plugin_table_fields_vtable_ext& extout) {
	extout.list_table_fields = dispatch_list_fields;
	extout.add_table_field = dispatch_add_field;
	extout.get_table_field = dispatch_get_field;
	/* Deprecated */
	out.list_table_fields = extout.list_table_fields;
	out.add_table_field = extout.add_table_field;
	out.get_table_field = extout.get_table_field;
}

void sinsp_plugin::table_read_api(ss_plugin_table_reader_vtable& out,
                                  ss_plugin_table_reader_vtable_ext& extout) {
	extout.get_table_name = dispatch_get_name;
	extout.get_table_size = dispatch_get_size;
	extout.get_table_entry = dispatch_get_entry;
	extout.read_entry_field = dispatch_read_entry_field;
	extout.release_table_entry = dispatch_release_table_entry;
	extout.iterate_entries = dispatch_iterate_entries;
	/* Deprecated */
	out.get_table_name = extout.get_table_name;
	out.get_table_size = extout.get_table_size;
	out.get_table_entry = extout.get_table_entry;
	out.read_entry_field = extout.read_entry_field;
}

void sinsp_plugin::table_write_api(ss_plugin_table_writer_vtable& out,
                                   ss_plugin_table_writer_vtable_ext& extout) {
	extout.clear_table = dispatch_clear;
	extout.erase_table_entry = dispatch_erase_entry;
	extout.create_table_entry = dispatch_create_table_entry;
	extout.destroy_table_entry = dispatch_destroy_table_entry;
	extout.add_table_entry = dispatch_add_entry;
	extout.write_entry_field = dispatch_write_entry_field;
	out.clear_table = extout.clear_table;
	out.erase_table_entry = extout.erase_table_entry;
	out.create_table_entry = extout.create_table_entry;
	out.destroy_table_entry = extout.destroy_table_entry;
	out.add_table_entry = extout.add_table_entry;
	out.write_entry_field = extout.write_entry_field;
}

ss_plugin_table_info* sinsp_plugin::table_api_list_tables(ss_plugin_owner_t* o, uint32_t* ntables) {
	auto p = static_cast<sinsp_plugin*>(o);
	__CATCH_ERR_MSG(p->m_last_owner_err, {
		*ntables = 0;
		p->m_table_infos.clear();
		for(const auto& d : p->m_table_registry->tables()) {
			ss_plugin_table_info info;
			info.name = d.second->name();
			info.key_type = d.second->key_type();
			p->m_table_infos.push_back(info);
		}
		*ntables = p->m_table_infos.size();
		return p->m_table_infos.data();
	});
	return NULL;
}

ss_plugin_table_t* sinsp_plugin::table_api_get_table(ss_plugin_owner_t* o,
                                                     const char* name,
                                                     ss_plugin_state_type key_type) {
	auto p = static_cast<sinsp_plugin*>(o);

// if a plugin is accessing a plugin-owned table, we return it as-is
// instead of wrapping it. This is both more performant and safer from
// a memory ownership perspective, because the other plugin is the actual
// total owner of the table's memory. Note, even though dynamic_cast is
// generally quite expensive, the "get_table" primitive can only be
// used during plugin initialization, so it's not in the hot path.
#define _X(_type, _dtype)                                                          \
	{                                                                              \
		auto t = p->m_table_registry->get_table<_type>(name);                      \
		if(!t) {                                                                   \
			return NULL;                                                           \
		}                                                                          \
		p->m_accessed_tables[name].set(p, t);                                      \
		return static_cast<ss_plugin_table_t*>(&p->m_accessed_tables[name].input); \
	};
	__CATCH_ERR_MSG(p->m_last_owner_err, {
		auto& tables = p->m_accessed_tables;
		auto it = tables.find(name);
		if(it == tables.end()) {
			__PLUGIN_STATETYPE_SWITCH(key_type);
		}
		return static_cast<ss_plugin_table_t*>(&it->second.input);
	});
#undef _X
	return NULL;
}

ss_plugin_rc sinsp_plugin::table_api_add_table(ss_plugin_owner_t* o,
                                               const ss_plugin_table_input* in) {
	auto p = static_cast<sinsp_plugin*>(o);
#define _X(_type, _dtype)                                                              \
	{                                                                                  \
		auto t = new plugin_table_wrapper<_type>(p, in);                               \
		p->m_table_registry->add_table(t);                                             \
		p->m_owned_tables[in->name] = std::unique_ptr<libsinsp::state::base_table>(t); \
		break;                                                                         \
	}
	__CATCH_ERR_MSG(p->m_last_owner_err, {
		__PLUGIN_STATETYPE_SWITCH(in->key_type);
		return SS_PLUGIN_SUCCESS;
	});
#undef _X
	return SS_PLUGIN_FAILURE;
}
