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

#pragma once

#include <memory>
#include <unordered_set>
#include <string>
#include <vector>
#include <atomic>
#include <libscap/engine/source_plugin/source_plugin_public.h>
#include <libsinsp/event.h>
#include <libsinsp/dumper.h>
#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/version.h>
#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/state/table_registry.h>
#include <plugin/plugin_loader.h>

#if defined(ENABLE_THREAD_POOL) && !defined(__EMSCRIPTEN__)
#include <libsinsp/sinsp_thread_pool_bs.h>
#else
#include <libsinsp/sinsp_thread_pool.h>
#endif

namespace libsinsp::state {
class base_table;
}
/**
 * @brief An object-oriented representation of a plugin.
 */
class sinsp_plugin : public libsinsp::state::sinsp_table_owner {
public:
	struct open_param {
		open_param() = default;
		~open_param() = default;
		open_param(open_param&&) = default;
		open_param& operator=(open_param&&) = default;
		open_param(const open_param& s) = default;
		open_param& operator=(const open_param& s) = default;

		std::string value;
		std::string desc;
		std::string separator;
	};

	/**
	 * @brief Create a plugin from the dynamic library at the provided path.
	 * On error, the shared_ptr will == nullptr and errstr is set with an error.
	 */
	static std::shared_ptr<sinsp_plugin> create(
	        const std::string& path,
	        const std::shared_ptr<libsinsp::state::table_registry>& treg,
	        const std::shared_ptr<sinsp_thread_pool>& tpool,
	        std::string& errstr);

	/**
	 * @brief Create a plugin from the provided api vtable.
	 * On error, the shared_ptr will == nullptr and errstr is set with an error.
	 */
	static std::shared_ptr<sinsp_plugin> create(
	        const plugin_api* api,
	        const std::shared_ptr<libsinsp::state::table_registry>& treg,
	        const std::shared_ptr<sinsp_thread_pool>& tpool,
	        std::string& errstr);

	/**
	 * @brief Return whether a filesystem dynamic library object is loaded.
	 */
	static bool is_plugin_loaded(const std::string& filepath);

	/**
	 * @brief If the plugin has CAP_EXTRACTION capability, returns a
	 * filtercheck with its exported fields. Returns NULL otherwise.
	 *
	 * todo(jasondellaluce): make this return a unique_ptr
	 */
	static std::unique_ptr<sinsp_filter_check> new_filtercheck(
	        const std::shared_ptr<sinsp_plugin>& plugin);

	/**
	 * @brief Returns true if the source is compatible with the given set
	 * of sources.
	 */
	static inline bool is_source_compatible(const std::unordered_set<std::string>& sources,
	                                        const std::string& source) {
		return sources.empty() || sources.find(source) != sources.end();
	}

	sinsp_plugin(plugin_handle_t* handle,
	             const std::shared_ptr<libsinsp::state::table_registry>& treg,
	             const std::shared_ptr<sinsp_thread_pool>& tpool):
	        m_caps(CAP_NONE),
	        m_name(),
	        m_description(),
	        m_contact(),
	        m_plugin_version(),
	        m_required_api_version(),
	        m_id(0),
	        m_event_source(),
	        m_inited(false),
	        m_state(nullptr),
	        m_handle(handle),
	        m_scap_source_plugin(),
	        m_fields_info(),
	        m_fields(),
	        m_extract_event_sources(),
	        m_extract_event_codes(),
	        m_parse_event_sources(),
	        m_parse_event_codes(),
	        m_async_event_sources(),
	        m_async_event_names(),
	        m_async_evt_handler(nullptr),
	        m_table_registry(treg),
	        m_table_infos(),
	        m_owned_tables(),
	        m_accessed_tables(),
	        m_thread_pool(tpool) {}
	virtual ~sinsp_plugin();
	sinsp_plugin(const sinsp_plugin& s) = delete;
	sinsp_plugin& operator=(const sinsp_plugin& s) = delete;

	/** Common API **/
	inline plugin_caps_t caps() const { return m_caps; }

	inline const std::string& name() const { return m_name; }

	inline const std::string& description() const { return m_description; }

	inline const std::string& contact() const { return m_contact; }

	inline const sinsp_version& plugin_version() const { return m_plugin_version; }

	inline const sinsp_version& required_api_version() const { return m_required_api_version; }

	bool init(const std::string& config, std::string& errstr);
	void destroy();
	std::string get_last_error() const;
	std::string get_init_schema(ss_plugin_schema_type& schema_type) const;
	bool set_config(const std::string& config);
	std::vector<metrics_v2> get_metrics() const;
	bool capture_open();
	bool capture_close();
	sinsp_thread_pool::routine_id_t subscribe_routine(ss_plugin_routine_fn_t routine_fn,
	                                                  ss_plugin_routine_state_t* routine_state);
	bool unsubscribe_routine(sinsp_thread_pool::routine_id_t routine_id);
	bool dump_state(sinsp_dumper& dumper);

	/** Event Sourcing **/
	inline uint32_t id() const { return m_id; }

	inline const std::string& event_source() const { return m_event_source; }

	scap_source_plugin& as_scap_source();
	std::string get_progress(uint32_t& progress_pct) const;
	std::string event_to_string(sinsp_evt* evt) const;
	std::vector<open_param> list_open_params() const;

	/** Field Extraction **/
	inline const std::unordered_set<std::string>& extract_event_sources() const {
		return m_extract_event_sources;
	}

	const libsinsp::events::set<ppm_event_code>& extract_event_codes() const;

	inline const filter_check_info* fields_info() const { return &m_fields_info; }

	inline const std::vector<filtercheck_field_info>& fields() const { return m_fields; }

	bool extract_fields(sinsp_evt* evt, uint32_t num_fields, ss_plugin_extract_field* fields);

	bool extract_fields_and_offsets(sinsp_evt* evt,
	                                uint32_t num_fields,
	                                ss_plugin_extract_field* fields,
	                                ss_plugin_extract_value_offsets* value_offsets);

	/** Event Parsing **/
	inline const std::unordered_set<std::string>& parse_event_sources() const {
		return m_parse_event_sources;
	}

	const libsinsp::events::set<ppm_event_code>& parse_event_codes() const;

	bool parse_event(sinsp_evt* evt);

	/** Async Events **/
	inline const std::unordered_set<std::string>& async_event_sources() const {
		return m_async_event_sources;
	}

	inline const std::unordered_set<std::string>& async_event_names() const {
		return m_async_event_names;
	}

	using async_event_handler_t =
	        std::function<void(const sinsp_plugin&, std::unique_ptr<sinsp_evt>)>;

	using async_dump_handler_t = std::function<void(std::unique_ptr<sinsp_evt>)>;

	bool set_async_event_handler(async_event_handler_t handler);

	/*
	 * @brief Check if the plugin is compatible with the given event schema version.
	 * @param event_schema_version The event schema version to check.
	 * @param err The error message to return if the plugin is not compatible.
	 * @return True if the plugin is compatible, false otherwise.
	 */
	bool check_required_schema_version(sinsp_version event_schema_version, std::string& err);

	// note(jasondellaluce): we set these as protected in order to allow unit
	// testing mocking these values, without having to declare their accessors
	// as virtual (thus avoiding performance loss in some hot paths).
protected:
	plugin_caps_t m_caps;
	std::string m_name;
	std::string m_description;
	std::string m_contact;
	sinsp_version m_plugin_version;
	sinsp_version m_required_api_version;

	/** Event Sourcing */
	uint32_t m_id;
	std::string m_event_source;

private:
	/* this checks if we already called the init API */
	bool m_inited;
	ss_plugin_t* m_state;
	plugin_handle_t* m_handle;

	/** Event Sourcing **/
	scap_source_plugin m_scap_source_plugin;

	/** Field Extraction **/
	filter_check_info m_fields_info;
	std::vector<filtercheck_field_info> m_fields;
	std::unordered_set<std::string> m_extract_event_sources;
	libsinsp::events::set<ppm_event_code> m_extract_event_codes;

	/** Event Parsing **/
	std::unordered_set<std::string> m_parse_event_sources;
	libsinsp::events::set<ppm_event_code> m_parse_event_codes;

	/** Async Events state and helpers **/
	std::unordered_set<std::string> m_async_event_sources;
	std::unordered_set<std::string> m_async_event_names;
	std::atomic<async_event_handler_t*>
	        m_async_evt_handler;  // note: we don't have thread-safe smart pointers
	async_dump_handler_t m_async_dump_handler;

	static ss_plugin_rc handle_plugin_async_event(ss_plugin_owner_t* o,
	                                              const ss_plugin_event* evt,
	                                              char* err);
	static ss_plugin_rc handle_plugin_async_dump(ss_plugin_owner_t* o,
	                                             const ss_plugin_event* evt,
	                                             char* err);

	/** Generic helpers **/
	void validate_config(std::string& config);
	bool resolve_dylib_symbols(std::string& errstr);
	void resolve_dylib_field_arg(Json::Value root, filtercheck_field_info& tf);
	void resolve_dylib_compatible_sources(const std::string& symbol,
	                                      const char* (*get_sources)(),
	                                      std::unordered_set<std::string>& sources);
	void resolve_dylib_compatible_codes(uint16_t* (*get_codes)(uint32_t* numtypes, ss_plugin_t* s),
	                                    const std::unordered_set<std::string>& sources,
	                                    libsinsp::events::set<ppm_event_code>& codes);
	void validate_config_json_schema(std::string& config, std::string& schema);
	static const char* get_owner_last_error(ss_plugin_owner_t* o);

	/** Table API state and helpers **/

	std::shared_ptr<libsinsp::state::table_registry> m_table_registry;
	std::vector<ss_plugin_table_info> m_table_infos;
	std::unordered_map<std::string, std::unique_ptr<libsinsp::state::base_table>> m_owned_tables;
	/* contains tables that the plugin accessed at least once */
	std::unordered_map<std::string, libsinsp::state::table_accessor> m_accessed_tables;
	static void table_field_api(ss_plugin_table_fields_vtable& out,
	                            ss_plugin_table_fields_vtable_ext& extout);
	static void table_read_api(ss_plugin_table_reader_vtable& out,
	                           ss_plugin_table_reader_vtable_ext& extout);
	static void table_write_api(ss_plugin_table_writer_vtable& out,
	                            ss_plugin_table_writer_vtable_ext& extout);
	static ss_plugin_table_info* table_api_list_tables(ss_plugin_owner_t* o, uint32_t* ntables);
	static ss_plugin_table_t* table_api_get_table(ss_plugin_owner_t* o,
	                                              const char* name,
	                                              ss_plugin_state_type key_type);
	static ss_plugin_rc table_api_add_table(ss_plugin_owner_t* o, const ss_plugin_table_input* in);

	std::shared_ptr<sinsp_thread_pool> m_thread_pool;
};

template<typename T>
struct span {
	T* m_begin;
	size_t m_size;

	T* begin() const noexcept { return m_begin; }

	T* end() const noexcept { return m_begin + m_size; }

	auto size() const { return m_size; }
};

template<typename KeyType>
static void wrap_state_data(const KeyType& key, ss_plugin_state_data& out);

template<>
inline void wrap_state_data<int8_t>(const int8_t& key, ss_plugin_state_data& out) {
	out.s8 = key;
}

template<>
inline void wrap_state_data<int16_t>(const int16_t& key, ss_plugin_state_data& out) {
	out.s16 = key;
}

template<>
inline void wrap_state_data<int32_t>(const int32_t& key, ss_plugin_state_data& out) {
	out.s32 = key;
}

template<>
inline void wrap_state_data<int64_t>(const int64_t& key, ss_plugin_state_data& out) {
	out.s64 = key;
}

template<>
inline void wrap_state_data<uint8_t>(const uint8_t& key, ss_plugin_state_data& out) {
	out.u8 = key;
}

template<>
inline void wrap_state_data<uint16_t>(const uint16_t& key, ss_plugin_state_data& out) {
	out.u16 = key;
}

template<>
inline void wrap_state_data<uint32_t>(const uint32_t& key, ss_plugin_state_data& out) {
	out.u32 = key;
}

template<>
inline void wrap_state_data<uint64_t>(const uint64_t& key, ss_plugin_state_data& out) {
	out.u64 = key;
}

template<>
inline void wrap_state_data<std::string>(const std::string& key, ss_plugin_state_data& out) {
	out.str = key.c_str();
}

template<>
inline void wrap_state_data<bool>(const bool& key, ss_plugin_state_data& out) {
	out.b = key;
}

template<>
inline void wrap_state_data<libsinsp::state::base_table*>(libsinsp::state::base_table* const& key,
                                                          ss_plugin_state_data& out) {
	out.table = static_cast<ss_plugin_table_t*>(key);
}

template<typename FieldType>
static void unwrap_state_data(const ss_plugin_state_data& val, FieldType& out);

template<>
inline void unwrap_state_data<int8_t>(const ss_plugin_state_data& val, int8_t& out) {
	out = val.s8;
}

template<>
inline void unwrap_state_data<int16_t>(const ss_plugin_state_data& val, int16_t& out) {
	out = val.s16;
}

template<>
inline void unwrap_state_data<int32_t>(const ss_plugin_state_data& val, int32_t& out) {
	out = val.s32;
}

template<>
inline void unwrap_state_data<int64_t>(const ss_plugin_state_data& val, int64_t& out) {
	out = val.s64;
}

template<>
inline void unwrap_state_data<uint8_t>(const ss_plugin_state_data& val, uint8_t& out) {
	out = val.u8;
}

template<>
inline void unwrap_state_data<uint16_t>(const ss_plugin_state_data& val, uint16_t& out) {
	out = val.u16;
}

template<>
inline void unwrap_state_data<uint32_t>(const ss_plugin_state_data& val, uint32_t& out) {
	out = val.u32;
}

template<>
inline void unwrap_state_data<uint64_t>(const ss_plugin_state_data& val, uint64_t& out) {
	out = val.u64;
}

template<>
inline void unwrap_state_data<std::string>(const ss_plugin_state_data& val, std::string& out) {
	out = val.str;
}

template<>
inline void unwrap_state_data<bool>(const ss_plugin_state_data& val, bool& out) {
	out = val.b != 0;
}

template<>
inline void unwrap_state_data<ss_plugin_table_t*>(const ss_plugin_state_data& val,
                                                  ss_plugin_table_t*& out) {
	out = val.table;
}

class sinsp_table_entry {
	enum class entry_dtor { NONE, DESTROY, RELEASE };

public:
	sinsp_table_entry() = delete;
	sinsp_table_entry(libsinsp::state::sinsp_table_owner* owner,
	                  ss_plugin_table_entry_t* entry,
	                  libsinsp::state::base_table* table,
	                  entry_dtor dtor):
	        m_owner(owner),
	        m_entry(entry),
	        m_table(table),
	        m_dtor(dtor) {}
	sinsp_table_entry(const sinsp_table_entry& s) = delete;
	sinsp_table_entry& operator=(const sinsp_table_entry& s) = delete;
	sinsp_table_entry(sinsp_table_entry&& s) = default;
	sinsp_table_entry& operator=(sinsp_table_entry&& s) = default;
	~sinsp_table_entry() {
		if(m_entry == nullptr) {
			return;
		}
		switch(m_dtor) {
		case entry_dtor::NONE:
			break;
		case entry_dtor::DESTROY:
			m_table->destroy_table_entry(m_owner, m_entry);
			break;
		case entry_dtor::RELEASE:
			m_table->release_table_entry(m_owner, m_entry);
			break;
		default:
			ASSERT(false);
		}
	}

	template<typename FieldType>
	void read_field(const ss_plugin_table_field_t* field, FieldType& out) {
		ss_plugin_state_data data;
		auto rc = m_table->read_entry_field(m_owner, m_entry, field, &data);
		if(rc != SS_PLUGIN_SUCCESS) {
			throw sinsp_exception("failed to read field: " + this->m_owner->m_last_owner_err);
		}

		unwrap_state_data<FieldType>(data, out);
	}

	template<typename FieldType>
	void write_field(const ss_plugin_table_field_t* field, const FieldType& in) {
		ss_plugin_state_data data;
		wrap_state_data<FieldType>(in, data);
		auto rc = m_table->write_entry_field(m_owner, m_entry, field, &data);
		if(rc != SS_PLUGIN_SUCCESS) {
			throw sinsp_exception("failed to write field: " + this->m_owner->m_last_owner_err);
		}
	}

private:
	libsinsp::state::sinsp_table_owner* m_owner;
	ss_plugin_table_entry_t* m_entry;
	libsinsp::state::base_table* m_table;
	entry_dtor m_dtor;

	template<typename KeyType>
	friend class sinsp_table;
};

template<typename KeyType>
class sinsp_table {
public:
	sinsp_table(libsinsp::state::sinsp_table_owner* p, libsinsp::state::base_table* t):
	        m_owner_plugin(p),
	        m_table(t) {
		if(m_table->key_type() != libsinsp::state::type_id_of<KeyType>()) {
			std::string req_type = libsinsp::state::typeinfo::of<KeyType>().name();
			std::string key_type = libsinsp::state::typeinfo::from(m_table->key_type()).name();
			throw sinsp_exception("table key type mismatch, requested='" + req_type +
			                      "', actual='" + key_type + "'");
		}
	}

	std::string_view name() const { return m_table->name(); }

	size_t entries_count() const { return m_table->get_size(m_owner_plugin); }

	ss_plugin_state_type key_type() const { return m_table->key_type(); }

	span<const ss_plugin_table_fieldinfo> fields() const {
		uint32_t nfields;
		return {m_table->list_fields(m_owner_plugin, &nfields), nfields};
	}

	const ss_plugin_table_fieldinfo* get_field_info(const char* name) const {
		auto fields = this->fields();
		auto field_name = std::string_view(name);
		auto field =
		        std::find_if(fields.begin(), fields.end(), [&](const ss_plugin_table_fieldinfo& f) {
			        return f.name == field_name;
		        });

		return field;
	}

	template<typename FieldType>
	ss_plugin_table_field_t* get_field(const char* name) {
		auto typeinfo = libsinsp::state::typeinfo::of<FieldType>();
		return m_table->get_field(m_owner_plugin, name, typeinfo.type_id());
	}

	template<typename FieldType>
	ss_plugin_table_field_t* add_field(const char* name) {
		auto typeinfo = libsinsp::state::typeinfo::of<FieldType>();
		return m_table->add_field(m_owner_plugin, name, typeinfo.type_id());
	}

	sinsp_table_entry get_entry(const KeyType& key) {
		ss_plugin_state_data key_data;
		wrap_state_data(key, key_data);
		auto entry = m_table->get_entry(m_owner_plugin, &key_data);
		if(entry == nullptr) {
			throw sinsp_exception("could not get entry: " + m_owner_plugin->m_last_owner_err);
		}
		return sinsp_table_entry(m_owner_plugin,
		                         entry,
		                         m_table,
		                         sinsp_table_entry::entry_dtor::RELEASE);
	}

	sinsp_table_entry new_entry() {
		auto entry = m_table->create_table_entry(m_owner_plugin);
		if(entry == nullptr) {
			throw sinsp_exception("could not create entry: " + m_owner_plugin->m_last_owner_err);
		}
		return sinsp_table_entry(m_owner_plugin,
		                         entry,
		                         m_table,
		                         sinsp_table_entry::entry_dtor::DESTROY);
	}

	void add_entry(const KeyType& key, sinsp_table_entry& entry) {
		ss_plugin_state_data key_data;
		wrap_state_data(key, key_data);

		auto table_entry = m_table->add_entry(m_owner_plugin, &key_data, entry.m_entry);
		entry.m_entry = table_entry;
		entry.m_dtor = sinsp_table_entry::entry_dtor::RELEASE;
	}

	bool foreach_entry(std::function<bool(sinsp_table_entry& e)> pred) {
		struct iter_state {
			libsinsp::state::sinsp_table_owner* m_owner_plugin;
			libsinsp::state::base_table* m_table;
			std::function<bool(sinsp_table_entry& e)>& pred;
		} state = {m_owner_plugin, m_table, pred};

		return m_table->iterate_entries(
		        m_owner_plugin,
		        [](void* s, ss_plugin_table_entry_t* e) {
			        auto state = static_cast<iter_state*>(s);
			        sinsp_table_entry entry(state->m_owner_plugin,
			                                e,
			                                state->m_table,
			                                sinsp_table_entry::entry_dtor::NONE);
			        return static_cast<ss_plugin_bool>(state->pred(entry));
		        },
		        &state);
	}

	void erase_entry(const KeyType& key) {
		ss_plugin_state_data key_data;
		wrap_state_data(key, key_data);
		if(m_table->erase_entry(m_owner_plugin, &key_data) != SS_PLUGIN_SUCCESS) {
			throw sinsp_exception("could not erase entry: " + m_owner_plugin->m_last_owner_err);
		}
	}

	void clear_entries() { m_table->clear_entries(m_owner_plugin); }

private:
	libsinsp::state::sinsp_table_owner* m_owner_plugin = nullptr;
	libsinsp::state::base_table* m_table = nullptr;
};
