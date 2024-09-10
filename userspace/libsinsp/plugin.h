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
#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/version.h>
#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/state/table_registry.h>
#include <plugin/plugin_loader.h>

#if defined(ENABLE_THREAD_POOL) && !defined(__EMSCRIPTEN__)
#include <libsinsp/thread_pool_bs.h>
#else
#include <libsinsp/thread_pool.h>
#endif

/**
 * @brief An object-oriented representation of a plugin.
 */
class sinsp_plugin {
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
	        const std::shared_ptr<thread_pool>& tpool,
	        std::string& errstr);

	/**
	 * @brief Create a plugin from the provided api vtable.
	 * On error, the shared_ptr will == nullptr and errstr is set with an error.
	 */
	static std::shared_ptr<sinsp_plugin> create(
	        const plugin_api* api,
	        const std::shared_ptr<libsinsp::state::table_registry>& treg,
	        const std::shared_ptr<thread_pool>& tpool,
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
	             const std::shared_ptr<thread_pool>& tpool):
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
	        m_last_owner_err(),
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
	        m_accessed_entries(),
	        m_accessed_table_fields(),
	        m_ephemeral_tables(),
	        m_ephemeral_tables_clear(false),
	        m_accessed_entries_clear(false),
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
	thread_pool::routine_id_t subscribe_routine(ss_plugin_routine_fn_t routine_fn,
	                                            ss_plugin_routine_state_t* routine_state);
	bool unsubscribe_routine(thread_pool::routine_id_t routine_id);

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

	bool set_async_event_handler(async_event_handler_t handler);

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
	std::string m_last_owner_err;

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
	static ss_plugin_rc handle_plugin_async_event(ss_plugin_owner_t* o,
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

	// wraps instances of libsinsp::state::XXX_struct::field_accessor and
	// help making them comply to the plugin API state tables definitions
	struct sinsp_field_accessor_wrapper {
		// depending on the value of `dynamic`, one of:
		// - libsinsp::state::static_struct::field_accessor
		// - libsinsp::state::dynamic_struct::field_accessor
		void* accessor = nullptr;
		bool dynamic = false;
		ss_plugin_state_type data_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;
		ss_plugin_state_type subtable_key_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;

		inline sinsp_field_accessor_wrapper() = default;
		~sinsp_field_accessor_wrapper();
		inline sinsp_field_accessor_wrapper(const sinsp_field_accessor_wrapper& s) = delete;
		inline sinsp_field_accessor_wrapper& operator=(const sinsp_field_accessor_wrapper& s) =
		        delete;
		inline sinsp_field_accessor_wrapper(sinsp_field_accessor_wrapper&& s);
		inline sinsp_field_accessor_wrapper& operator=(sinsp_field_accessor_wrapper&& s);
	};

	// wraps instances of libsinsp::state::table and help making them comply
	// to the plugin API state tables definitions
	struct sinsp_table_wrapper {
		ss_plugin_state_type m_key_type = ss_plugin_state_type::SS_PLUGIN_ST_INT8;
		sinsp_plugin* m_owner_plugin = nullptr;
		libsinsp::state::base_table* m_table = nullptr;
		std::vector<ss_plugin_table_fieldinfo> m_field_list;
		std::unordered_map<std::string, sinsp_plugin::sinsp_field_accessor_wrapper*>
		        m_field_accessors;

		// used to optimize cases where this wraps a plugin-defined table directly
		const sinsp_plugin* m_table_plugin_owner = nullptr;
		ss_plugin_table_input* m_table_plugin_input = nullptr;

		inline sinsp_table_wrapper() = default;
		virtual ~sinsp_table_wrapper() = default;
		inline sinsp_table_wrapper(const sinsp_table_wrapper& s) = delete;
		inline sinsp_table_wrapper& operator=(const sinsp_table_wrapper& s) = delete;

		void unset();
		bool is_set() const;
		template<typename T>
		void set(sinsp_plugin* p, libsinsp::state::table<T>* t);

		// static functions, will be used to populate vtable functions where
		// ss_plugin_table_t* will be represented by a sinsp_table_wrapper*
		static inline const ss_plugin_table_fieldinfo* list_fields(ss_plugin_table_t* _t,
		                                                           uint32_t* nfields);
		static inline ss_plugin_table_field_t* get_field(ss_plugin_table_t* _t,
		                                                 const char* name,
		                                                 ss_plugin_state_type data_type);
		static inline ss_plugin_table_field_t* add_field(ss_plugin_table_t* _t,
		                                                 const char* name,
		                                                 ss_plugin_state_type data_type);
		static inline const char* get_name(ss_plugin_table_t* _t);
		static inline uint64_t get_size(ss_plugin_table_t* _t);
		static inline ss_plugin_table_entry_t* get_entry(ss_plugin_table_t* _t,
		                                                 const ss_plugin_state_data* key);
		static inline ss_plugin_rc read_entry_field(ss_plugin_table_t* _t,
		                                            ss_plugin_table_entry_t* _e,
		                                            const ss_plugin_table_field_t* f,
		                                            ss_plugin_state_data* out);
		;
		static inline void release_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e);
		static inline ss_plugin_bool iterate_entries(ss_plugin_table_t* _t,
		                                             ss_plugin_table_iterator_func_t it,
		                                             ss_plugin_table_iterator_state_t* s);
		static inline ss_plugin_rc clear(ss_plugin_table_t* _t);
		static inline ss_plugin_rc erase_entry(ss_plugin_table_t* _t,
		                                       const ss_plugin_state_data* key);
		static inline ss_plugin_table_entry_t* create_table_entry(ss_plugin_table_t* _t);
		static inline void destroy_table_entry(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e);
		static inline ss_plugin_table_entry_t* add_entry(ss_plugin_table_t* _t,
		                                                 const ss_plugin_state_data* key,
		                                                 ss_plugin_table_entry_t* _e);
		static inline ss_plugin_rc write_entry_field(ss_plugin_table_t* _t,
		                                             ss_plugin_table_entry_t* e,
		                                             const ss_plugin_table_field_t* f,
		                                             const ss_plugin_state_data* in);
		;
	};

	// a wrapper around sinsp_table_wrapper (yes...) that makes it comply to the
	// ss_plugin_table_input facade, thus being accessible through plugin API
	struct sinsp_table_input {
		ss_plugin_table_input input;
		ss_plugin_table_fields_vtable_ext fields_vtable;
		ss_plugin_table_reader_vtable_ext reader_vtable;
		ss_plugin_table_writer_vtable_ext writer_vtable;
		sinsp_table_wrapper wrapper;

		sinsp_table_input();
		inline ~sinsp_table_input() = default;
		inline sinsp_table_input(const sinsp_table_input& s) = delete;
		inline sinsp_table_input& operator=(const sinsp_table_input& s) = delete;

		void update();
	};

	std::shared_ptr<libsinsp::state::table_registry> m_table_registry;
	std::vector<ss_plugin_table_info> m_table_infos;
	std::unordered_map<std::string, std::unique_ptr<libsinsp::state::base_table>> m_owned_tables;
	/* contains tables that the plugin accessed at least once */
	std::unordered_map<std::string, sinsp_table_input> m_accessed_tables;
	std::list<std::shared_ptr<libsinsp::state::table_entry>>
	        m_accessed_entries;  // using lists for ptr stability
	std::list<sinsp_field_accessor_wrapper>
	        m_accessed_table_fields;                  // note: lists have pointer stability
	std::list<sinsp_table_input> m_ephemeral_tables;  // note: lists have pointer stability
	bool m_ephemeral_tables_clear;
	bool m_accessed_entries_clear;

	inline void clear_ephemeral_tables() {
		if(m_ephemeral_tables_clear) {
			// quick break-out that prevents us from looping over the
			// whole list in the critical path, in case of no accessed table
			return;
		}
		for(auto& et : m_ephemeral_tables) {
			et.wrapper.unset();
			et.update();
		}
		m_ephemeral_tables_clear = true;
	}

	inline sinsp_table_input& find_unset_ephemeral_table() {
		m_ephemeral_tables_clear = false;
		for(auto& et : m_ephemeral_tables) {
			if(!et.wrapper.is_set()) {
				return et;
			}
		}
		return m_ephemeral_tables.emplace_back();
	}

	inline void clear_accessed_entries() {
		if(m_accessed_entries_clear) {
			// quick break-out that prevents us from looping over the
			// whole list in the critical path
			return;
		}
		for(auto& et : m_accessed_entries) {
			if(et != nullptr) {
				// if we get here, it means that the plugin did not
				// release some of the entries it acquired
				ASSERT(false);
				et.reset();
			};
		}
		m_accessed_entries_clear = true;
	}

	inline std::shared_ptr<libsinsp::state::table_entry>* find_unset_accessed_table_entry() {
		m_accessed_entries_clear = false;
		for(auto& et : m_accessed_entries) {
			if(et == nullptr) {
				return &et;
			}
		}
		return &m_accessed_entries.emplace_back();
	}

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

	std::shared_ptr<thread_pool> m_thread_pool;

	friend struct sinsp_table_wrapper;
};
