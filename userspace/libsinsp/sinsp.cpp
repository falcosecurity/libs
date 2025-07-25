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

#include <libscap/scap_config.h>
#include <libscap/scap_engines.h>
#include <libsinsp/scap_open_exception.h>
#include <libscap/scap_platform.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/filter.h>
#include <libsinsp/filterchecks.h>
#include <libsinsp/dns_manager.h>
#include <libsinsp/plugin.h>
#include <libsinsp/plugin_manager.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/sinsp_threadinfo_factory.h>
#include <libscap/strl.h>
#include <libscap/scap-int.h>

#ifndef _WIN32
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#endif  // _WIN32

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <user.h>

/**
 * This is the maximum size assigned to the concurrent asynchronous event
 * queue that can be used to inject async events during an event capture.
 * The queue is built to have a throughput orders of magnitude lower than the
 * one of kernel events. As such, this size value is assigned to a number that's
 * big enough to prevent the queue to ever fill-up in standard circumstances,
 * while at the same time avoiding it growing uncontrollably in case of anomalies.
 */
#define DEFAULT_ASYNC_EVENT_QUEUE_SIZE 4096

// Small sinsp event filter wrapper logic
// that uses RAII to eventually filter out events.
struct sinsp_evt_filter {
	bool do_filter_later;
	sinsp_evt* evt;

	explicit sinsp_evt_filter(sinsp_evt* e): do_filter_later(false), evt(e) {
		//
		// Filtering
		//
		const auto inspector = evt->get_inspector();
		const bool is_live = inspector->is_live() || inspector->is_syscall_plugin();
		const uint16_t etype = evt->get_type();

		evt->set_filtered_out(false);

		//
		// When debug mode is not enabled, filter out events about itself
		//
		if(is_live && !inspector->is_debug_enabled()) {
			if(evt->get_tid() == inspector->m_self_pid && etype != PPME_SCHEDSWITCH_1_E &&
			   etype != PPME_SCHEDSWITCH_6_E && etype != PPME_DROP_E && etype != PPME_DROP_X &&
			   etype != PPME_SCAPEVENT_E && etype != PPME_PROCINFO_E &&
			   etype != PPME_CPU_HOTPLUG_E && inspector->m_self_pid) {
				evt->set_filtered_out(true);
				return;
			}
		}

		if(inspector->m_filter) {
			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & EF_MODIFIES_STATE) {
				do_filter_later = true;
			} else {
				if(!inspector->run_filters_on_evt(evt)) {
					if(evt->get_tinfo() != nullptr) {
						if(!(eflags & EF_SKIPPARSERESET || etype == PPME_SCHEDSWITCH_6_E)) {
							evt->get_tinfo()->set_lastevent_type(PPM_EVENT_MAX);
						}
					}
					evt->set_filtered_out(true);
				}
			}
		}
	}

	~sinsp_evt_filter() {
		//
		// With some state-changing events like clone, execve and open, we do the
		// filtering after having updated the state
		//
		const auto inspector = evt->get_inspector();
		if(do_filter_later) {
			if(!inspector->run_filters_on_evt(evt)) {
				evt->set_filtered_out(true);
				return;
			}
			evt->set_filtered_out(false);
		}

		//
		// Offline captures can produce events with the SCAP_DF_STATE_ONLY. They are
		// supposed to go through the engine, but they must be filtered out before
		// reaching the user.
		//
		if(inspector->is_capture()) {
			if(evt->get_dump_flags() & SCAP_DF_STATE_ONLY) {
				evt->set_filtered_out(true);
			}
		}
	}
};

int32_t on_new_entry_from_proc(void* context,
                               char* error,
                               int64_t tid,
                               scap_threadinfo* tinfo,
                               scap_fdinfo* fdinfo,
                               scap_threadinfo** new_tinfo);

void on_proc_table_refresh_start(void* context);
void on_proc_table_refresh_end(void* context);

///////////////////////////////////////////////////////////////////////////////
// sinsp implementation
///////////////////////////////////////////////////////////////////////////////
std::atomic<int> sinsp::instance_count{0};

sinsp::sinsp(bool with_metrics):
        m_external_event_processor(),
        m_sinsp_stats_v2(with_metrics ? std::make_shared<sinsp_stats_v2>() : nullptr),
        m_evt(this),
        m_timestamper{0},
        m_host_root(scap_get_host_root()),
        m_thread_manager_dyn_fields{
                std::make_shared<libsinsp::state::dynamic_struct::field_infos>()},
        m_fdtable_dyn_fields{std::make_shared<libsinsp::state::dynamic_struct::field_infos>()},
        m_fdinfo_factory{this, &m_external_event_processor, m_fdtable_dyn_fields},
        m_fdtable_ctor_params{std::make_shared<sinsp_fdtable::ctor_params>(
                sinsp_fdtable::ctor_params{m_mode,
                                           s_max_fdtable_size,
                                           m_fdinfo_factory,
                                           m_input_plugin,
                                           m_sinsp_stats_v2,
                                           m_platform})},
        m_fdtable_factory{m_fdtable_ctor_params},
        // After m_threadinfo_ctor_params initialization, the thread manager and the usergroup
        // manager refer to non-initialized sinsp's fields. This is not a problem as long
        // as the m_threadinfo_factory (which will use the m_threadinfo_ctor_params) is not used
        // before the initialization of these fields is completed.
        m_threadinfo_ctor_params{std::make_shared<sinsp_threadinfo::ctor_params>(
                sinsp_threadinfo::ctor_params{m_network_interfaces,
                                              m_fdinfo_factory,
                                              m_fdtable_factory,
                                              m_thread_manager_dyn_fields,
                                              m_thread_manager,
                                              m_usergroup_manager})},
        m_threadinfo_factory{
                m_threadinfo_ctor_params,
                m_external_event_processor,
                m_fdtable_dyn_fields,
        },
        m_thread_manager_factory{
                m_mode,
                m_threadinfo_factory,
                m_observer,
                m_input_plugin,
                m_large_envs_enabled,
                m_timestamper,
                m_self_pid,
                m_threads_purging_scan_time_ns,
                m_thread_timeout_ns,
                m_sinsp_stats_v2,
                m_platform,
                m_h,
                m_thread_manager_dyn_fields,
                m_fdtable_dyn_fields,

        },
        m_table_registry{std::make_shared<libsinsp::state::table_registry>()},
        m_async_events_queue(DEFAULT_ASYNC_EVENT_QUEUE_SIZE),
        m_inited(false) {
	++instance_count;

	m_h = nullptr;
	m_parser = nullptr;
	m_is_dumping = false;
	m_parser_tmp_evt = sinsp_evt{this};
	m_thread_manager = m_thread_manager_factory.create();
	// Add thread manager table to state tables registry.
	m_table_registry->add_table(m_thread_manager.get());
	m_usergroup_manager = std::make_shared<sinsp_usergroup_manager>(this, m_timestamper);
	m_filter = nullptr;
	m_machine_info = nullptr;
	m_agent_info = nullptr;
	m_snaplen = DEFAULT_SNAPLEN;
	m_buffer_format = sinsp_evt::PF_NORMAL;
	m_input_fd = 0;
	m_isdebug_enabled = false;
	m_isfatfile_enabled = false;
	m_isinternal_events_enabled = false;
	m_hostname_and_port_resolution_enabled = false;
	m_output_time_flag = 'h';
	m_max_evt_output_len = 0;
	m_filesize = -1;
	m_next_flush_time_ns = 0;
	m_last_procrequest_tod = 0;
	m_get_procs_cpu_from_driver = false;
	m_next_stats_print_time_ns = 0;
	m_large_envs_enabled = false;
	m_increased_snaplen_port_range = DEFAULT_INCREASE_SNAPLEN_PORT_RANGE;
	m_statsd_port = -1;
	m_platform = nullptr;

	m_self_pid = getpid();

	m_proc_scan_timeout_ms = SCAP_PROC_SCAN_TIMEOUT_NONE;
	m_proc_scan_log_interval_ms = SCAP_PROC_SCAN_LOG_NONE;

	m_replay_scap_evt = nullptr;

	m_plugin_parsers.clear();
	// The "syscall" event source is implemented by sinsp itself and is always present at index 0.
	constexpr size_t syscall_event_source_idx = 0;
	m_event_sources.push_back(sinsp_syscall_event_source_name);
	m_plugin_manager = std::make_shared<sinsp_plugin_manager>(m_event_sources);

	m_parser = std::make_unique<sinsp_parser>(m_mode,
	                                          m_machine_info,
	                                          m_event_sources,
	                                          syscall_event_source_idx,
	                                          m_network_interfaces,
	                                          m_hostname_and_port_resolution_enabled,
	                                          m_threadinfo_factory,
	                                          m_fdinfo_factory,
	                                          m_input_plugin,
	                                          m_large_envs_enabled,
	                                          m_plugin_manager,
	                                          m_thread_manager,
	                                          m_usergroup_manager,
	                                          m_sinsp_stats_v2,
	                                          m_observer,
	                                          m_parser_tmp_evt,
	                                          m_platform);

#if defined(ENABLE_THREAD_POOL) && !defined(__EMSCRIPTEN__)
	m_thread_pool = std::make_shared<sinsp_thread_pool_bs>();
#else
	m_thread_pool = nullptr;
#endif
}

sinsp::~sinsp() {
	close();

	if(--instance_count == 0) {
		sinsp_dns_manager::get().cleanup();
	}
}

bool sinsp::is_initialstate_event(const scap_evt& pevent) {
	const auto evt_type = pevent.type;
	return evt_type == PPME_CONTAINER_E || evt_type == PPME_CONTAINER_JSON_E ||
	       evt_type == PPME_CONTAINER_JSON_2_E || evt_type == PPME_USER_ADDED_E ||
	       evt_type == PPME_USER_DELETED_E || evt_type == PPME_GROUP_ADDED_E ||
	       evt_type == PPME_GROUP_DELETED_E || evt_type == PPME_ASYNCEVENT_E;
}

void sinsp::consume_initialstate_events() {
	scap_evt* pevent;
	uint16_t pcpuid;
	sinsp_evt* tevt;
	uint32_t flags;

	if(m_external_event_processor) {
		m_external_event_processor->on_capture_start();
	}

	//
	// Consume every state event we have
	//
	while(true) {
		int32_t res = scap_next(m_h, &pevent, &pcpuid, &flags);

		if(res == SCAP_SUCCESS) {
			// Setting these to non-null will make sinsp::next use them as a scap event
			// to avoid a call to scap_next. In this way, we can avoid the state parsing phase
			// once we reach a non-initialstate event.
			m_replay_scap_evt = pevent;
			m_replay_scap_cpuid = pcpuid;
			m_replay_scap_flags = flags;
			if(!is_initialstate_event(*pevent)) {
				break;
			} else {
				next(&tevt);
				continue;
			}
		} else {
			break;
		}
	}
}

void sinsp::init() {
	//
	// Retrieve machine information
	//
	m_machine_info = scap_get_machine_info(get_scap_platform());
	if(m_machine_info != nullptr) {
		m_num_cpus = m_machine_info->num_cpus;
	} else {
		ASSERT(false);
		m_num_cpus = 0;
	}

	//
	// Retrieve agent information
	//
	m_agent_info = scap_get_agent_info(get_scap_platform());
	if(m_agent_info == nullptr) {
		ASSERT(false);
	}

	//
	// Basic inits
	//

	m_nevts = 0;
	m_parser_verdict.clear();
	m_timestamper.reset();
	m_firstevent_ts = 0;

	//
	// If we're reading from file, we try to pre-parse all initial state-building events before
	// importing the thread table, so that thread table filtering will work with
	// full information.
	//
	if(is_capture()) {
		consume_initialstate_events();
	}

	import_ifaddr_list();

	import_user_list();

	/* Create parent/child dependencies */
	m_thread_manager->create_thread_dependencies_after_proc_scan();

	//
	// Scan the list to fix the direction of the sockets
	//
	m_thread_manager->fix_sockets_coming_from_proc(m_hostname_and_port_resolution_enabled);

	//
	// Load state table API field accessors and tables
	//
	set_thread_manager_foreign_accessors_and_tables();

	// If we are in capture, this is already called by consume_initialstate_events
	if(!is_capture() && m_external_event_processor) {
		m_external_event_processor->on_capture_start();
	}

	//
	// If m_snaplen was modified, we set snaplen now
	//
	if(m_snaplen != DEFAULT_SNAPLEN) {
		set_snaplen(m_snaplen);
	}

	//
	// If the port range for increased snaplen was modified, set it now
	//
#ifndef _WIN32
	if(increased_snaplen_port_range_set()) {
		set_fullcapture_port_range(m_increased_snaplen_port_range.range_start,
		                           m_increased_snaplen_port_range.range_end);
	}
#endif

	//
	// If the statsd port was modified, push it to the kernel now.
	//
	if(m_statsd_port != -1) {
		set_statsd_port(m_statsd_port);
	}

	if(is_live()) {
		int32_t res = scap_getpid_global(get_scap_platform(), &m_self_pid);
		ASSERT(res == SCAP_SUCCESS || res == SCAP_NOT_SUPPORTED);
		(void)res;
	}
	m_inited = true;
}

void sinsp::set_thread_manager_foreign_accessors_and_tables() const {
	std::vector<sinsp_thread_manager::foreign_field_accessor_entry> accessors;
	std::vector<sinsp_thread_manager::foreign_table_entry> tables;

	// Add "container_id" accessor.
	const auto& container_id_field_name = sinsp_thread_manager::s_container_id_field_name;
	const auto& fields = m_thread_manager->dynamic_fields()->fields();
	if(const auto field = fields.find(container_id_field_name); field != fields.end()) {
		accessors.emplace_back(container_id_field_name, field->second.new_accessor<std::string>());
	}

	// Add "containers" table.
	const auto& containers_table_name = sinsp_thread_manager::s_containers_table_name;
	const auto containers_table = dynamic_cast<libsinsp::state::base_table*>(
	        get_table_registry()->get_table<std::string>(containers_table_name));
	if(containers_table != nullptr) {
		tables.emplace_back(containers_table_name, containers_table);
	}

	// Add other accessors/tables here

	m_thread_manager->set_foreign_field_accessors(accessors);
	m_thread_manager->set_foreign_tables(tables);
}

void sinsp::set_import_users(bool import_users) {
	m_usergroup_manager->m_import_users = import_users;
}

/*=============================== OPEN METHODS ===============================*/

void sinsp::open_common(scap_open_args* oargs,
                        const scap_vtable* vtable,
                        scap_platform* platform,
                        sinsp_mode_t mode) {
	libsinsp_logger()->log("Trying to open the right engine!");

	/* Reset the thread manager */
	m_thread_manager->clear();

	/* We need to save the actual mode and the engine used by the inspector. */
	m_mode = mode;

	oargs->import_users = m_usergroup_manager->m_import_users;
	oargs->log_fn = &sinsp_scap_log_fn;
	oargs->proc_scan_timeout_ms = m_proc_scan_timeout_ms;
	oargs->proc_scan_log_interval_ms = m_proc_scan_log_interval_ms;

	m_h = scap_alloc();
	if(m_h == nullptr) {
		throw scap_open_exception("failed to allocate scap handle", SCAP_FAILURE);
	}

	int32_t scap_rc = scap_init(m_h, oargs, vtable);
	if(scap_rc != SCAP_SUCCESS) {
		scap_platform_close(platform);
		scap_platform_free(platform);
		m_platform = nullptr;

		std::string error = scap_getlasterr(m_h);
		scap_close(m_h);
		m_h = nullptr;
		if(error.empty()) {
			error = "Initialization issues during scap_init";
		}
		throw scap_open_exception(error, scap_rc);
	}

	m_platform = platform;
	scap_rc = scap_platform_init(platform, m_platform_lasterr, m_h->m_engine, oargs);
	if(scap_rc != SCAP_SUCCESS) {
		scap_platform_close(platform);
		scap_platform_free(platform);
		m_platform = nullptr;

		scap_close(m_h);
		m_h = nullptr;

		throw scap_open_exception(m_platform_lasterr, scap_rc);
	}

	init();

	// enable generation of async meta-events for all loaded plugins supporting
	// that capability. Meta-events are considered only during live captures,
	// because offline captures will have the async events already encoded
	// in the event stream.
	if(!is_capture()) {
		// note(jasondellaluce,rohith-raju): for now the emscripten build does not support
		// tbb queues, so async event production is disabled
		for(auto& p : m_plugin_manager->plugins()) {
			if(p->caps() & CAP_ASYNC) {
				auto res = p->set_async_event_handler([this](auto& p, auto e) {
					this->handle_plugin_async_event(p, std::move(e));
				});
				if(!res) {
					throw sinsp_exception("can't set async event handler for plugin '" + p->name() +
					                      "' : " + p->get_last_error());
				}
			}
		}
	}

	// notify registered plugins of capture open
	for(auto& p : m_plugin_manager->plugins()) {
		if(p->caps() & CAP_CAPTURE_LISTENING) {
			if(!p->capture_open()) {
				throw sinsp_exception("capture_open error for plugin '" + p->name() +
				                      "' : " + p->get_last_error());
			}
		}
	}
}

void sinsp::mark_ppm_sc_of_interest(ppm_sc_code ppm_sc, bool enable) {
	/* This API must be used only after the initialization phase. */
	if(!m_inited) {
		throw sinsp_exception("you cannot use this method before opening the inspector!");
	}
	if(ppm_sc >= PPM_SC_MAX) {
		throw sinsp_exception("inexistent ppm_sc code: " + std::to_string(ppm_sc));
	}
	int ret = scap_set_ppm_sc(m_h, ppm_sc, enable);
	if(ret != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

static void fill_ppm_sc_of_interest(scap_open_args* oargs,
                                    const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest) {
	for(int i = 0; i < PPM_SC_MAX; i++) {
		/* If the set is empty, fallback to all interesting syscalls */
		if(ppm_sc_of_interest.empty()) {
			oargs->ppm_sc_of_interest.ppm_sc[i] = true;
		} else {
			oargs->ppm_sc_of_interest.ppm_sc[i] = ppm_sc_of_interest.contains((ppm_sc_code)i);
		}
	}
}

void sinsp::open_kmod(unsigned long driver_buffer_bytes_dim,
                      const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest) {
#ifdef HAS_ENGINE_KMOD
	scap_open_args oargs{};

	/* Set interesting syscalls and tracepoints. */
	fill_ppm_sc_of_interest(&oargs, ppm_sc_of_interest);

	/* Engine-specific args. */
	scap_kmod_engine_params params;
	params.buffer_bytes_dim = driver_buffer_bytes_dim;
	oargs.engine_params = &params;

	scap_platform* platform = scap_linux_alloc_platform({::on_proc_table_refresh_start,
	                                                     ::on_proc_table_refresh_end,
	                                                     ::on_new_entry_from_proc,
	                                                     this});
	if(platform) {
		auto linux_plat = (scap_linux_platform*)platform;
		linux_plat->m_linux_vtable = &scap_kmod_linux_vtable;
	}

	open_common(&oargs, &scap_kmod_engine, platform, SINSP_MODE_LIVE);
#else
	throw sinsp_exception("KMOD engine is not supported in this build");
#endif
}

void sinsp::open_bpf(const std::string& bpf_path,
                     unsigned long driver_buffer_bytes_dim,
                     const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest) {
#ifdef HAS_ENGINE_BPF
	/* Validate the BPF path. */
	if(bpf_path.empty()) {
		throw sinsp_exception(
		        "When you use the 'BPF' engine you need to provide a path to the bpf object "
		        "file.");
	}

	scap_open_args oargs{};

	/* Set interesting syscalls and tracepoints. */
	fill_ppm_sc_of_interest(&oargs, ppm_sc_of_interest);

	/* Engine-specific args. */
	scap_bpf_engine_params params;
	params.buffer_bytes_dim = driver_buffer_bytes_dim;
	params.bpf_probe = bpf_path.data();
	oargs.engine_params = &params;

	scap_platform* platform = scap_linux_alloc_platform({::on_proc_table_refresh_start,
	                                                     ::on_proc_table_refresh_end,
	                                                     ::on_new_entry_from_proc,
	                                                     this});
	open_common(&oargs, &scap_bpf_engine, platform, SINSP_MODE_LIVE);
#else
	throw sinsp_exception("BPF engine is not supported in this build");
#endif
}

void sinsp::open_nodriver(bool full_proc_scan) {
#ifdef HAS_ENGINE_NODRIVER
	scap_open_args oargs{};
	scap_platform* platform = scap_linux_alloc_platform({::on_proc_table_refresh_start,
	                                                     ::on_proc_table_refresh_end,
	                                                     ::on_new_entry_from_proc,
	                                                     this});
	if(platform) {
		if(!full_proc_scan) {
			auto linux_plat = (scap_linux_platform*)platform;
			linux_plat->m_fd_lookup_limit = SCAP_NODRIVER_MAX_FD_LOOKUP;
			linux_plat->m_minimal_scan = true;
		}
	} else {
		platform = scap_generic_alloc_platform({::on_proc_table_refresh_start,
		                                        ::on_proc_table_refresh_end,
		                                        ::on_new_entry_from_proc,
		                                        this});
	}

	open_common(&oargs, &scap_nodriver_engine, platform, SINSP_MODE_NODRIVER);
#else
	throw sinsp_exception("NODRIVER engine is not supported in this build");
#endif
}

void sinsp::open_savefile(const std::string& filename, int fd) {
#ifdef HAS_ENGINE_SAVEFILE
	scap_open_args oargs{};
	scap_savefile_engine_params params;

	m_input_filename = filename;
	m_input_fd = fd; /* default is 0. */

	if(m_input_fd != 0) {
		/* In this case, we can't get a reliable filesize */
		params.fd = m_input_fd;
		params.fname = nullptr;
		m_filesize = 0;
	} else {
		if(filename.empty()) {
			throw sinsp_exception(
			        "When you use the 'savefile' engine you need to provide a path to the "
			        "file.");
		}

		params.fname = filename.c_str();
		params.fd = 0;

		char error[SCAP_LASTERR_SIZE]{};
		m_filesize = get_file_size(params.fname, error);
		if(m_filesize < 0) {
			throw sinsp_exception(error);
		}
	}

	params.start_offset = 0;
	params.fbuffer_size = 0;
	oargs.engine_params = &params;

	scap_platform* platform = scap_savefile_alloc_platform({::on_proc_table_refresh_start,
	                                                        ::on_proc_table_refresh_end,
	                                                        ::on_new_entry_from_proc,
	                                                        this});
	;
	params.platform = platform;
	open_common(&oargs, &scap_savefile_engine, platform, SINSP_MODE_CAPTURE);
#else
	throw sinsp_exception("SAVEFILE engine is not supported in this build");
#endif
}

void sinsp::open_plugin(const std::string& plugin_name,
                        const std::string& plugin_open_params,
                        sinsp_plugin_platform platform_type) {
#ifdef HAS_ENGINE_SOURCE_PLUGIN
	scap_open_args oargs{};
	scap_source_plugin_engine_params params;
	set_input_plugin(plugin_name, plugin_open_params);
	params.input_plugin = &m_input_plugin->as_scap_source();
	params.input_plugin_params = (char*)m_input_plugin_open_params.c_str();
	oargs.engine_params = &params;

	scap_platform* platform;
	sinsp_mode_t mode;
	switch(platform_type) {
	case sinsp_plugin_platform::SINSP_PLATFORM_GENERIC:
		mode = SINSP_MODE_PLUGIN;
		platform = scap_generic_alloc_platform({::on_proc_table_refresh_start,
		                                        ::on_proc_table_refresh_end,
		                                        ::on_new_entry_from_proc,
		                                        this});
		;
		break;
	case sinsp_plugin_platform::SINSP_PLATFORM_HOSTINFO:
		mode = SINSP_MODE_PLUGIN;
		platform = scap_linux_hostinfo_alloc_platform();
		break;
	case sinsp_plugin_platform::SINSP_PLATFORM_FULL:
		mode = SINSP_MODE_LIVE;
		platform = scap_linux_alloc_platform({::on_proc_table_refresh_start,
		                                      ::on_proc_table_refresh_end,
		                                      ::on_new_entry_from_proc,
		                                      this});
		break;
	default:
		throw sinsp_exception("Unsupported mode for SOURCE_PLUGIN engine");
	}
	open_common(&oargs, &scap_source_plugin_engine, platform, mode);
#else
	throw sinsp_exception("SOURCE_PLUGIN engine is not supported in this build");
#endif
}

void sinsp::open_gvisor(const std::string& config_path,
                        const std::string& root_path,
                        bool no_events,
                        int epoll_timeout) {
#ifdef HAS_ENGINE_GVISOR
	if(config_path.empty()) {
		throw sinsp_exception(
		        "When you use the 'gvisor' engine you need to provide a path to the config "
		        "file.");
	}

	scap_open_args oargs{};
	scap_gvisor_engine_params params;
	params.gvisor_root_path = root_path.c_str();
	params.gvisor_config_path = config_path.c_str();
	params.no_events = no_events;
	params.gvisor_epoll_timeout = epoll_timeout;

	scap_platform* platform = scap_gvisor_alloc_platform({::on_proc_table_refresh_start,
	                                                      ::on_proc_table_refresh_end,
	                                                      ::on_new_entry_from_proc,
	                                                      this});
	;
	params.gvisor_platform = reinterpret_cast<scap_gvisor_platform*>(platform);

	oargs.engine_params = &params;

	open_common(&oargs, &scap_gvisor_engine, platform, SINSP_MODE_LIVE);

	set_get_procs_cpu_from_driver(false);
#else
	throw sinsp_exception("GVISOR engine is not supported in this build");
#endif
}

void sinsp::open_modern_bpf(unsigned long driver_buffer_bytes_dim,
                            uint16_t cpus_for_each_buffer,
                            bool online_only,
                            const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest) {
#ifdef HAS_ENGINE_MODERN_BPF
	scap_open_args oargs{};

	/* Set interesting syscalls and tracepoints. */
	fill_ppm_sc_of_interest(&oargs, ppm_sc_of_interest);

	/* Engine-specific args. */
	scap_modern_bpf_engine_params params;
	params.buffer_bytes_dim = driver_buffer_bytes_dim;
	params.cpus_for_each_buffer = cpus_for_each_buffer;
	params.allocate_online_only = online_only;
	oargs.engine_params = &params;

	scap_platform* platform = scap_linux_alloc_platform({::on_proc_table_refresh_start,
	                                                     ::on_proc_table_refresh_end,
	                                                     ::on_new_entry_from_proc,
	                                                     this});
	open_common(&oargs, &scap_modern_bpf_engine, platform, SINSP_MODE_LIVE);
#else
	throw sinsp_exception("MODERN_BPF engine is not supported in this build");
#endif
}

void sinsp::open_test_input(scap_test_input_data* data, sinsp_mode_t mode) {
#ifdef HAS_ENGINE_TEST_INPUT
	scap_open_args oargs{};
	scap_test_input_engine_params params;
	params.test_input_data = data;
	oargs.engine_params = &params;

	scap_platform* platform;
	switch(mode) {
	case SINSP_MODE_TEST:
		platform = scap_test_input_alloc_platform({default_refresh_start_end_callback,
		                                           default_refresh_start_end_callback,
		                                           ::on_new_entry_from_proc,
		                                           this});
		break;
	case SINSP_MODE_LIVE:
		platform = scap_linux_alloc_platform({default_refresh_start_end_callback,
		                                      default_refresh_start_end_callback,
		                                      ::on_new_entry_from_proc,
		                                      this});
		break;
	default:
		throw sinsp_exception("Unsupported mode for TEST_INPUT engine");
	}
	open_common(&oargs, &scap_test_input_engine, platform, mode);

	set_get_procs_cpu_from_driver(false);
#else
	throw sinsp_exception("TEST_INPUT engine is not supported in this build");
#endif
}

/*=============================== OPEN METHODS ===============================*/

/*=============================== Engine related ===============================*/

bool sinsp::check_current_engine(const std::string& engine_name) const {
	return scap_check_current_engine(m_h, engine_name.data());
}

/*=============================== Engine related ===============================*/

std::string sinsp::generate_gvisor_config(const std::string& socket_path) {
	return gvisor_config::generate(socket_path);
}

int64_t sinsp::get_file_size(const std::string& fname, char* error) {
	std::filesystem::path p(fname);
	auto s = std::filesystem::status(p);

	// scap files can be streamed and the source can be one
	// of the following. In that case we return 0 as file size.
	if(s.type() == std::filesystem::file_type::character ||
	   s.type() == std::filesystem::file_type::fifo ||
	   s.type() == std::filesystem::file_type::socket) {
		return 0;
	}

	std::error_code ec;
	auto sz = std::filesystem::file_size(p, ec);
	if(ec) {
		strlcpy(error, ec.message().c_str(), SCAP_LASTERR_SIZE);
		return -1;
	}
	return sz;
}

unsigned sinsp::m_num_possible_cpus = 0;

unsigned sinsp::num_possible_cpus() {
	if(m_num_possible_cpus == 0) {
		m_num_possible_cpus = read_num_possible_cpus();
		if(m_num_possible_cpus == 0) {
			libsinsp_logger()->log("Unable to read num_possible_cpus, falling back to 128",
			                       sinsp_logger::SEV_WARNING);
			m_num_possible_cpus = 128;
		}
	}
	return m_num_possible_cpus;
}

std::vector<long> sinsp::get_n_tracepoint_hit() const {
	std::vector<long> ret(num_possible_cpus(), 0);
	if(scap_get_n_tracepoint_hit(m_h, ret.data()) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
	return ret;
}

std::string sinsp::get_error_desc(const std::string& msg) {
#ifdef _WIN32
	DWORD err_no = GetLastError();  // first, so error is not wiped out by intermediate calls
	std::string errstr = msg;
	DWORD flg = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
	            FORMAT_MESSAGE_IGNORE_INSERTS;
	LPTSTR msg_buf = 0;
	if(FormatMessageA(flg, 0, err_no, 0, (LPTSTR)&msg_buf, 0, nullptr))
		if(msg_buf) {
			errstr.append(msg_buf, strlen(msg_buf));
			LocalFree(msg_buf);
		}
#else
	char* msg_buf = strerror(errno);  // first, so error is not wiped out by intermediate calls
	std::string errstr = msg;
	if(msg_buf) {
		errstr.append(msg_buf, strlen(msg_buf));
	}
#endif
	return errstr;
}

void sinsp::close() {
	if(m_platform) {
		scap_platform_close(m_platform);
		scap_platform_free(m_platform);
		m_platform = nullptr;
	}

	if(m_h) {
		scap_close(m_h);
		m_h = nullptr;
	}

	m_is_dumping = false;

	deinit_state();

	m_filter.reset();

	// unset the meta-event callback to all plugins that support it
	if(!is_capture() && m_mode != SINSP_MODE_NONE) {
		std::string err;
		for(auto& p : m_plugin_manager->plugins()) {
			if(p->caps() & CAP_ASYNC) {
				// collect errors but let's make sure we reset all the handlers
				// event in case of one failure.
				auto res = p->set_async_event_handler(nullptr);
				if(!res) {
					err += err.empty() ? "" : ", ";
					err += "can't reset async event handler for plugin '" + p->name() +
					       "' : " + p->get_last_error();
				}
			}
		}
		if(!err.empty()) {
			throw sinsp_exception(err);
		}
	}

	// notify registered plugins of capture close
	if(m_mode != SINSP_MODE_NONE) {
		for(auto& p : m_plugin_manager->plugins()) {
			if(p->caps() & CAP_CAPTURE_LISTENING) {
				if(!p->capture_close()) {
					throw sinsp_exception("capture_close error for plugin '" + p->name() +
					                      "' : " + p->get_last_error());
				}
			}
		}
	}

	// purge pending routines and wait for the running ones
	if(m_thread_pool) {
		m_thread_pool->purge();
	}

	m_mode = SINSP_MODE_NONE;
}

//
// This deinitializes the sinsp internal state, and it's used
// internally while closing or restarting the capture.
//
void sinsp::deinit_state() {
	m_network_interfaces.clear();
	m_thread_manager->clear();
}

void sinsp::on_new_entry_from_proc(void* context,
                                   int64_t tid,
                                   scap_threadinfo* tinfo,
                                   scap_fdinfo* fdinfo) {
	//
	// Retrieve machine information if we don't have it yet
	//
	{
		m_machine_info = scap_get_machine_info(get_scap_platform());
		if(m_machine_info != nullptr) {
			m_num_cpus = m_machine_info->num_cpus;
		} else {
			m_num_cpus = 0;
		}
	}

	if(tinfo && m_suppress.check_suppressed_comm(tid, tinfo->ptid, tinfo->comm)) {
		return;
	}

	//
	// Add the thread or FD
	//
	if(fdinfo == nullptr) {
		ASSERT(tinfo != nullptr);

		threadinfo_map_t::ptr_t sinsp_tinfo;
		auto newti = m_threadinfo_factory.create();
		newti->init(*tinfo,
		            large_envs_enabled(),
		            must_notify_thread_user_update(),
		            must_notify_thread_group_update());
		if(is_nodriver()) {
			auto existing_tinfo = find_thread(tid, true);
			if(existing_tinfo == nullptr || newti->m_clone_ts > existing_tinfo->m_clone_ts) {
				sinsp_tinfo = m_thread_manager->add_thread(std::move(newti), true);
			}
		} else {
			sinsp_tinfo = m_thread_manager->add_thread(std::move(newti), true);
		}
		if(sinsp_tinfo) {
			// in case the inspector is configured with an internal filter,
			// we filter out thread infos in case we determine them not passing
			// the given filter. Filtered out thread infos will not be dumped
			// in capture files.
			//
			// In case we have a filter, we set the "filtered out" thread info
			// flag as true by default and toggle it to false later when one of
			// the following cases occurs:
			//   - One event referencing the thread info passes the filter
			//   - One event referencing one of the file descriptors
			//     owned by the thread info passes the filter
			// However, when first adding a thread info or a file descriptor
			// we have no guarantee that an event referencing them will actually
			// ever occur, so we simulate an internal event right away and
			// see if it gets filtered out or not.
			sinsp_tinfo->m_filtered_out = false;
			if(m_filter != nullptr && is_capture()) {
				// note: the choice of PPME_SCAPEVENT_E is opinionated as by
				// nature it will always pass filters using "evt.type=scapevent".
				// However:
				//   1. It does not represent a real-world use case given that
				//      PPME_SCAPEVENT_E is an internal-usage mock event
				//   2. This approach is still not effective for evttype-based
				//      filtering: a filter like "evt.type=execve" will filter-out
				//      any simulated event that is not an execve. Performing
				//      correct thread info filtering based on the type of event
				//      would require scanning the whole capture file twice, which
				//      is a performance overhead not acceptable for some use cases.
				scap_evt tscapevt = {};
				tscapevt.type = PPME_SCAPEVENT_X;
				tscapevt.tid = tid;
				tscapevt.ts = 0;
				tscapevt.nparams = 0;
				tscapevt.len = sizeof(scap_evt);

				sinsp_evt tevt = {};
				tevt.set_scap_evt(&tscapevt);
				tevt.set_info(&(g_infotables.m_event_info[PPME_SCAPEVENT_X]));
				tevt.set_cpuid(0);
				tevt.set_num(0);
				tevt.set_inspector(this);
				tevt.set_tinfo(sinsp_tinfo.get());
				tevt.set_fdinfo_ref(nullptr);
				tevt.set_fd_info(nullptr);
				sinsp_tinfo->m_lastevent_fd = -1;
				sinsp_tinfo->set_last_event_data(nullptr);

				sinsp_tinfo->m_filtered_out = !m_filter->run(&tevt);
			}

			// we shouldn't see any fds yet
			ASSERT(tinfo->fdlist == nullptr);
		}
	} else {
		auto sinsp_tinfo = find_thread(tid, true);

		if(!sinsp_tinfo) {
			if(tinfo == nullptr) {
				// we have an fd but no associated tinfo, skip it
				return;
			}

			auto newti = m_threadinfo_factory.create();
			newti->init(*tinfo,
			            large_envs_enabled(),
			            must_notify_thread_user_update(),
			            must_notify_thread_group_update());
			sinsp_tinfo = m_thread_manager->add_thread(std::move(newti), true);
			if(sinsp_tinfo == nullptr) {
				ASSERT(false);
				return;
			}
		}

		const auto added_fdinfo =
		        m_thread_manager->add_thread_fd_from_scap(*sinsp_tinfo,
		                                                  *fdinfo,
		                                                  m_hostname_and_port_resolution_enabled);
		if(m_filter != nullptr && m_mode.is_capture()) {
			// in case the inspector is configured with an internal filter, we can
			// filter-out thread infos (and their fd infos) to not dump them in
			// captures unless actually used. Here, we simulate an internal event
			// using the new file descriptor info to understand if we can set
			// its thread info as non-filterable.

			// note: just like the case of  PPME_SCAPEVENT_E used for thread info
			// filtering, the usage of PPME_SYSCALL_READ_X is opinionated. This
			// kind of event has been chosen as a tradeoff of a lightweight and
			// usually-ignored event (in the context of filtering), but that is also
			// marked as using a file descriptor so that file-descriptor filter fields
			// can extract meaningful values.
			scap_evt tscapevt = {};
			tscapevt.type = PPME_SYSCALL_READ_X;
			tscapevt.tid = tid;
			tscapevt.ts = 0;
			tscapevt.nparams = 0;
			tscapevt.len = sizeof(scap_evt);

			sinsp_evt tevt = {};
			tevt.set_scap_evt(&tscapevt);
			tevt.set_info(&(g_infotables.m_event_info[PPME_SYSCALL_READ_X]));
			tevt.set_cpuid(0);
			tevt.set_num(0);
			tevt.set_tinfo(sinsp_tinfo.get());
			tevt.set_fdinfo_ref(nullptr);
			tevt.set_fd_info(added_fdinfo);
			int64_t tlefd = sinsp_tinfo->m_lastevent_fd;
			sinsp_tinfo->m_lastevent_fd = fdinfo->fd;

			if(m_filter->run(&tevt)) {
				// we mark the thread info as non-filterable due to one event
				// using one of its file descriptor has passed the filter
				sinsp_tinfo->m_filtered_out = false;
			} else {
				// we can't say if the thread info for this fd is filterable or not,
				// but we can mark the given file descriptor as filterable. This flag
				// will prevent the fd info from being written in captures.
				fdinfo->type = SCAP_FD_UNINITIALIZED;
			}

			sinsp_tinfo->m_lastevent_fd = tlefd;
			sinsp_tinfo->set_last_event_data(nullptr);
		}
	}
}

void sinsp::on_proc_table_refresh_start() {
	m_suppress.initialize();
}

void sinsp::on_proc_table_refresh_end() {
	m_suppress.finalize();
}

int32_t on_new_entry_from_proc(void* context,
                               char* error,
                               int64_t tid,
                               scap_threadinfo* tinfo,
                               scap_fdinfo* fdinfo,
                               scap_threadinfo** new_tinfo) {
	sinsp* _this = (sinsp*)context;
	_this->on_new_entry_from_proc(context, tid, tinfo, fdinfo);

	if(new_tinfo != nullptr) {
		*new_tinfo = tinfo;
	}

	return SCAP_SUCCESS;
}

void on_proc_table_refresh_start(void* context) {
	static_cast<sinsp*>(context)->on_proc_table_refresh_start();
}

void on_proc_table_refresh_end(void* context) {
	static_cast<sinsp*>(context)->on_proc_table_refresh_end();
}

void sinsp::import_ifaddr_list() {
	m_network_interfaces.clear();
	m_network_interfaces.import_interfaces(scap_get_ifaddr_list(get_scap_platform()));
}

const sinsp_network_interfaces& sinsp::get_ifaddr_list() const {
	return m_network_interfaces;
}

void sinsp::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo) {
	m_network_interfaces.import_ipv4_interface(ifinfo);
}

void sinsp::import_user_list() {
	uint32_t j;
	scap_userlist* ul = scap_get_user_list(get_scap_platform());

	if(ul) {
		for(j = 0; j < ul->nusers; j++) {
			m_usergroup_manager->add_user("",
			                              -1,
			                              ul->users[j].uid,
			                              ul->users[j].gid,
			                              ul->users[j].name,
			                              ul->users[j].homedir,
			                              ul->users[j].shell);
		}

		for(j = 0; j < ul->ngroups; j++) {
			m_usergroup_manager->add_group("", -1, ul->groups[j].gid, ul->groups[j].name);
		}
	}
}

void sinsp::refresh_ifaddr_list() {
#if !defined(_WIN32)
	if(is_live() || is_syscall_plugin()) {
		scap_refresh_iflist(get_scap_platform());
		import_ifaddr_list();
	}
#endif
}

//
// This restarts the current event capture. This de-initializes and
// re-initializes the internal state of both sinsp and scap, and is
// supported only for opened captures with mode SCAP_MODE_CAPTURE.
// This resets the internal states on-the-fly, which is ideally equivalent
// to closing and then re-opening the capture, but avoids losing the passed
// configurations and reuses the same underlying scap event source.
//
void sinsp::restart_capture() {
	// Save state info that could be lost during de-initialization
	uint64_t nevts = m_nevts;

	// De-initialize the insternal state
	deinit_state();

	// Restart the scap capture, which also trigger a re-initialization of
	// scap's internal state.
	if(scap_restart_capture(m_h) != SCAP_SUCCESS) {
		throw sinsp_exception(std::string("scap error: ") + scap_getlasterr(m_h));
	}

	// Re-initialize the internal state
	init();

	// Restore the saved state info
	m_nevts = nevts;
}

uint64_t sinsp::max_buf_used() const {
	if(m_h) {
		return scap_max_buf_used(m_h);
	} else {
		return 0;
	}
}

void sinsp::get_procs_cpu_from_driver(uint64_t ts) {
	if(ts <= m_next_flush_time_ns) {
		return;
	}

	uint64_t next_full_second = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;

	if(m_next_flush_time_ns == 0) {
		m_next_flush_time_ns = next_full_second;
		return;
	}

	m_next_flush_time_ns = next_full_second;

	uint64_t procrequest_tod = sinsp_utils::get_current_time_ns();
	if(procrequest_tod - m_last_procrequest_tod <= ONE_SECOND_IN_NS / 2) {
		return;
	}

	m_last_procrequest_tod = procrequest_tod;

	char error[SCAP_LASTERR_SIZE];
	auto* threadlist = scap_get_threadlist(get_scap_platform(), error);
	if(threadlist == nullptr) {
		throw sinsp_exception(std::string("scap error: ") + error);
	}

	for(int64_t i = 0; i < threadlist->n_entries; i++) {
		ppm_proc_info* pi = &(threadlist->entries[i]);

		if(pi->utime == 0 && pi->stime == 0) {
			continue;
		}

		uint32_t evlen = sizeof(scap_evt) + 2 * sizeof(uint16_t) + 2 * sizeof(uint64_t);
		auto piscapevt_buf = std::unique_ptr<uint8_t[]>(new uint8_t[evlen]);
		auto piscapevt = (scap_evt*)piscapevt_buf.get();
		piscapevt->tid = pi->pid;
		piscapevt->ts = ts;
		int32_t encode_res = scap_event_encode_params(scap_sized_buffer{piscapevt_buf.get(), evlen},
		                                              nullptr,
		                                              error,
		                                              PPME_PROCINFO_E,
		                                              2,
		                                              pi->utime,
		                                              pi->stime);

		if(encode_res != SCAP_SUCCESS) {
			throw sinsp_exception(std::string("could not encode PPME_PROCINFO_E event: ") + error);
		}

		// push event into async event queue
		handle_async_event(sinsp_evt::from_scap_evt(std::move(piscapevt_buf)));
	}
}

int32_t sinsp::fetch_next_event(sinsp_evt*& evt) {
	// check if an event must be replayed, which currently happens
	// when a capture file is read and we discover the first "event" block
	// after the initial "machine state" section
	if(m_replay_scap_evt != nullptr) {
		evt->set_scap_evt(m_replay_scap_evt);
		evt->set_cpuid(m_replay_scap_cpuid);
		evt->set_dump_flags(m_replay_scap_flags);
		m_replay_scap_evt = nullptr;
		return SCAP_SUCCESS;
	}

	// start by assuming that we already have an event successfully-fetched
	// from later that has been delayed. If our current libscap event storage
	// is empty, attempt fetching the next event in line from the scap handle
	int32_t res = SCAP_SUCCESS;
	if(m_delayed_scap_evt.empty()) {
		res = m_delayed_scap_evt.next(m_h);
	}

	// in case we receive a timeout (when there's no element to fetch and no
	// error is encountered) we attempt popping an event from the asynchronous
	// event queue. If none is available, we just return the timeout.
	// note: the queue is optimized for checking for emptyness before popping
	if(res == SCAP_TIMEOUT && !m_async_events_queue.empty()) {
		m_async_events_checker.ts = get_new_ts();
		if(m_async_events_queue.try_pop_if(m_async_evt, m_async_events_checker)) {
			evt = m_async_evt.get();
			if(evt->get_scap_evt()->ts == (uint64_t)-1) {
				evt->get_scap_evt()->ts = get_new_ts();
			}
			return SCAP_SUCCESS;
		}
	}

	// in case we successfully fetched an event, or we have one delayed from
	// before, we check that if there is any event in the async event queue
	// that should be returned first due to having a timestamp from earlier.
	// the goal is to guarantee events to be fetched ordered by timestamp.
	if(res == SCAP_SUCCESS) {
		if(!m_async_events_queue.empty()) {
			// This is thread-safe as we're in a MPSC case in which
			// sinsp::next is the single consumer
			m_async_events_checker.ts = m_delayed_scap_evt.m_pevt->ts;
			if(m_async_events_queue.try_pop_if(m_async_evt, m_async_events_checker)) {
				// the async event is the one with most priority
				evt = m_async_evt.get();
				if(evt->get_scap_evt()->ts == (uint64_t)-1) {
					evt->get_scap_evt()->ts = get_new_ts();
				}
				return SCAP_SUCCESS;
			}
		}

		// the scap event is the one with most priority
		m_delayed_scap_evt.move(evt);
	}

	return res;
}

int32_t sinsp::next(sinsp_evt** puevt) {
	*puevt = nullptr;
	sinsp_evt* evt = &m_evt;

	// fetch the next event
	int32_t res = fetch_next_event(evt);

	// if we fetched an event successfully, check if we need to suppress
	// it from userspace and update the result status
	if(res == SCAP_SUCCESS) {
		res = m_suppress.process_event(evt->get_scap_evt());
	}

	// in case we don't succeed, handle each scenario and return
	if(res != SCAP_SUCCESS) {
		if(res == SCAP_TIMEOUT) {
			if(m_external_event_processor) {
				m_external_event_processor->process_event(nullptr, libsinsp::EVENT_RETURN_TIMEOUT);
			}
		} else if(res == SCAP_EOF) {
			if(m_external_event_processor) {
				m_external_event_processor->process_event(nullptr, libsinsp::EVENT_RETURN_EOF);
			}
			*puevt = evt;
		} else if(res == SCAP_UNEXPECTED_BLOCK) {
			// This mostly happens in concatenated scap files, where an unexpected block
			// represents the end of a file and the start of the next appended one.
			// In this case, we restart the capture so that the internal states gets reset
			// and the blocks coming from the next appended file get consumed.
			restart_capture();
			res = SCAP_TIMEOUT;
		} else if(res == SCAP_FILTERED_EVENT) {
			// This will happen if SCAP has filtered the event in userspace (tid suppression).
			// A valid event was read from the driver, but we are choosing to not report it to
			// the client at the client's request.
			// However, we still need to return here so that the client doesn't time out the
			// request.
			if(m_external_event_processor) {
				m_external_event_processor->process_event(nullptr, libsinsp::EVENT_RETURN_FILTERED);
			}
		} else {
			m_lasterr = scap_getlasterr(m_h);
		}

		return res;
	}

	/* Here we shouldn't receive unknown events */
	ASSERT(!libsinsp::events::is_unknown_event((ppm_event_code)evt->get_type()));

	uint64_t ts = evt->get_ts();

	if(m_firstevent_ts == 0 && !libsinsp::events::is_metaevent((ppm_event_code)evt->get_type())) {
		m_firstevent_ts = ts;
	}

	//
	// If required, retrieve the processes cpu from the kernel
	//
	if(m_get_procs_cpu_from_driver && is_live()) {
		get_procs_cpu_from_driver(ts);
	}

	//
	// Store a couple of values that we'll need later inside the event.
	// These are potentially used both for parsing the event for internal
	// state management.
	//
	m_nevts++;
	evt->set_num(m_nevts);
	m_timestamper.set_cached_ts(ts);

	if(m_auto_threads_purging) {
		//
		// Delayed removal of threads from the thread table, so that
		// things like exit() or close() can be parsed.
		//
		if(m_parser_verdict.must_remove_tid()) {
			const auto tid = m_parser_verdict.get_tid_to_remove();
			m_thread_manager->remove_thread(tid);
			m_parser_verdict.clear_tid_to_remove();
		}

		if(!is_offline()) {
			m_thread_manager->remove_inactive_threads();
		}
	}

	if(m_auto_stats_print && is_debug_enabled() && is_live()) {
		if(ts > m_next_stats_print_time_ns) {
			if(m_next_stats_print_time_ns) {
				print_capture_stats(sinsp_logger::SEV_DEBUG);
			}

			m_next_stats_print_time_ns = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;
		}
	}

	//
	// Delayed removal of the fd, so that
	// things like exit() or close() can be parsed.
	//
	if(m_parser_verdict.must_remove_fds()) {
		/* This is a removal logic we shouldn't scan /proc. If we don't have the thread
		 * to remove we are fine.
		 */
		const auto tid_of_fds_to_remove = m_parser_verdict.get_tid_of_fds_to_remove();
		const auto& fds_to_remove = m_parser_verdict.get_fds_to_remove();
		if(sinsp_threadinfo* ptinfo =
		           m_thread_manager->get_thread_ref(tid_of_fds_to_remove, false).get()) {
			for(const auto fd : fds_to_remove) {
				ptinfo->remove_fd(fd);
			}
		}
		m_parser_verdict.clear_fds_to_remove();
	}

	//
	// Cleanup the event-related state
	//
	m_parser->reset(*evt, m_parser_verdict);

	// Since evt_filter object below uses RAII, create a new scope.
	{
		// Object that uses RAII to enable event filtered out flag
		sinsp_evt_filter evt_filter(evt);
		// Object that uses RAII to automatically update user/group associated with a threadinfo
		// upon threadinfo's container_id changes.
		// Since the threadinfo state might get changed from a plugin parser,
		// evaluate this one after all parsers get run.
		user_group_updater usr_grp_updater(evt,
		                                   must_notify_thread_user_update(),
		                                   must_notify_thread_group_update());

		if(!evt->is_filtered_out()) {
			//
			// Run the state engine
			//
			m_parser->process_event(*evt, m_parser_verdict);
		}

		// run plugin-implemented parsers
		// note: we run the parsers even if the event has been filtered out,
		// because we have no guarantee that the plugin parsers will not use a given
		// event for state updates. Sinsp understands this through the
		// EF_MODIFIES_STATE flag, which however is only relevant in the context of
		// the internal implementation of libsinsp.
		for(auto& pp : m_plugin_parsers) {
			// todo(jason): should we log parsing errors here?
			pp.process_event(evt, m_event_sources);
		}

		// Once we processed all events, make sure to call all
		// requested post-process callbacks.
		// At this point, any plugin could have modified state tables,
		// thus we can guarantee that any post-process callback
		// will see the full post-event-processed state.
		// NOTE: we don't use a RAII object because
		// we cannot guarantee that no exception will be thrown by the callbacks.
		if(m_observer != nullptr && m_parser_verdict.must_run_post_process_cbs()) {
			for(auto cbs = m_parser_verdict.get_post_process_cbs(); !cbs.empty(); cbs.pop()) {
				auto cb = cbs.front();
				cb(m_observer, evt);
			}
			m_parser_verdict.clear_post_process_cbs();
		}
	}

	// Finally set output evt;
	// From now on, any return must have the correct output being set.
	*puevt = evt;
	if(evt->is_filtered_out()) {
		ppm_event_category cat = evt->get_category();

		// Skip the event, unless we're in internal events
		// mode and the category of this event is internal.
		if(!(m_isinternal_events_enabled && (cat & EC_INTERNAL))) {
			return SCAP_FILTERED_EVENT;
		}
	}

	//
	// Run the analysis engine
	//
	if(m_external_event_processor) {
		m_external_event_processor->process_event(evt, libsinsp::EVENT_RETURN_NONE);
	}

	// Clean parse related event data after analyzer did its parsing too
	m_parser->event_cleanup(*evt);

	//
	// Update the last event time for this thread
	//
	if(evt->get_tinfo() && evt->get_type() != PPME_SCHEDSWITCH_1_E &&
	   evt->get_type() != PPME_SCHEDSWITCH_6_E) {
		evt->get_tinfo()->m_prevevent_ts = evt->get_tinfo()->m_lastevent_ts;
		evt->get_tinfo()->m_lastevent_ts = m_timestamper.get_cached_ts();
	}

	//
	// Done
	//
	return res;
}

uint64_t sinsp::get_num_events() const {
	if(m_h) {
		return scap_event_get_num(m_h);
	} else {
		return 0;
	}
}

bool sinsp::suppress_events_comm(const std::string& comm) {
	m_suppress.suppress_comm(comm);
	return true;
}

bool sinsp::suppress_events_tid(int64_t tid) {
	m_suppress.suppress_tid(tid);
	return true;
}

void sinsp::clear_suppress_events_comm() {
	m_suppress.clear_suppress_comm();
}

void sinsp::clear_suppress_events_tid() {
	m_suppress.clear_suppress_tid();
}

bool sinsp::check_suppressed(int64_t tid) const {
	return m_suppress.is_suppressed_tid(tid);
}

void sinsp::set_snaplen(uint32_t snaplen) {
	//
	// If set_snaplen is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if(m_h == nullptr) {
		m_snaplen = snaplen;
		return;
	}

	if(is_live() && scap_set_snaplen(m_h, snaplen) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::set_dropfailed(bool dropfailed) {
	if(is_live() && scap_set_dropfailed(m_h, dropfailed) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::set_fullcapture_port_range(uint16_t range_start, uint16_t range_end) {
	//
	// If set_fullcapture_port_range is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if(m_h == nullptr) {
		m_increased_snaplen_port_range = {range_start, range_end};
		return;
	}

	if(!is_live()) {
		throw sinsp_exception(
		        "set_fullcapture_port_range called on a trace file, plugin, or test engine");
	}

	if(scap_set_fullcapture_port_range(m_h, range_start, range_end) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::set_statsd_port(const uint16_t port) {
	//
	// If this method is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if(m_h == nullptr) {
		m_statsd_port = port;
		return;
	}

	if(!is_live()) {
		throw sinsp_exception("set_statsd_port called on a trace file, plugin, or test engine");
	}

	if(scap_set_statsd_port(m_h, port) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

std::shared_ptr<sinsp_plugin> sinsp::register_plugin(const std::string& filepath) {
	std::string errstr;
	std::shared_ptr<sinsp_plugin> plugin =
	        sinsp_plugin::create(filepath, m_table_registry, m_thread_pool, errstr);
	if(!plugin) {
		throw sinsp_exception("cannot load plugin " + filepath + ": " + errstr.c_str());
	}

	try {
		m_plugin_manager->add(plugin);
		if(plugin->caps() & CAP_PARSING) {
			m_plugin_parsers.push_back(sinsp_plugin_parser(plugin));
		}
	} catch(sinsp_exception const& e) {
		throw sinsp_exception("cannot register plugin " + filepath + " in inspector: " + e.what());
	}

	return plugin;
}

std::shared_ptr<sinsp_plugin> sinsp::register_plugin(const plugin_api* api) {
	std::string errstr;
	std::shared_ptr<sinsp_plugin> plugin =
	        sinsp_plugin::create(api, m_table_registry, m_thread_pool, errstr);
	if(!plugin) {
		throw sinsp_exception("cannot load plugin with custom vtable: " + errstr);
	}

	try {
		m_plugin_manager->add(plugin);
		if(plugin->caps() & CAP_PARSING) {
			m_plugin_parsers.push_back(sinsp_plugin_parser(plugin));
		}
	} catch(sinsp_exception const& e) {
		throw sinsp_exception("cannot register plugin with custom vtable in inspector: " +
		                      std::string(e.what()));
	}

	return plugin;
}

void sinsp::set_input_plugin(const std::string& name, const std::string& params) {
	for(auto& it : m_plugin_manager->plugins()) {
		if(it->name() == name) {
			if(!(it->caps() & CAP_SOURCING)) {
				throw sinsp_exception(
				        "plugin " + name +
				        " has not event sourcing capabilities and cannot be used as input.");
			}
			m_input_plugin = it;
			m_input_plugin_open_params = params;
			return;
		}
	}
	throw sinsp_exception("plugin " + name + " does not exist");
}

void sinsp::stop_capture() {
	if(scap_stop_capture(m_h) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	/* Print scap stats */
	if(m_auto_stats_print) {
		print_capture_stats(sinsp_logger::SEV_DEBUG);
	}

	/* Print the number of threads and fds in our tables */
	uint64_t thread_cnt = 0;
	uint64_t fd_cnt = 0;
	m_thread_manager->get_threads()->loop([&thread_cnt, &fd_cnt](sinsp_threadinfo& tinfo) {
		thread_cnt++;

		/* Only main threads have an associated fdtable */
		if(tinfo.is_main_thread()) {
			auto fdtable_ptr = tinfo.get_fd_table();
			if(fdtable_ptr != nullptr) {
				fd_cnt += fdtable_ptr->size();
			}
		}
		return true;
	});
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "total threads in the table:%" PRIu64
	                          ", total fds in all threads:%" PRIu64 "\n",
	                          thread_cnt,
	                          fd_cnt);
}

void sinsp::start_capture() {
	if(scap_start_capture(m_h) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

#ifndef _WIN32
void sinsp::stop_dropping_mode() {
	if(is_live()) {
		libsinsp_logger()->format(sinsp_logger::SEV_INFO, "stopping drop mode");

		if(scap_stop_dropping_mode(m_h) != SCAP_SUCCESS) {
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

void sinsp::start_dropping_mode(uint32_t sampling_ratio) {
	if(is_live()) {
		libsinsp_logger()->format(sinsp_logger::SEV_INFO,
		                          "setting drop mode to %" PRIu32,
		                          sampling_ratio);

		if(scap_start_dropping_mode(m_h, sampling_ratio) != SCAP_SUCCESS) {
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}
#endif  // _WIN32

void sinsp::set_filter(std::unique_ptr<sinsp_filter> filter, const std::string& filterstring) {
	if(m_filter != nullptr) {
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	m_filter = std::move(filter);
	m_filterstring = filterstring;
}

void sinsp::set_filter(const std::string& filter) {
	if(m_filter != nullptr) {
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	sinsp_filter_compiler compiler(this, filter);
	m_filter = compiler.compile();
	m_filterstring = filter;
	m_internal_flt_ast = compiler.get_filter_ast();
}

std::string sinsp::get_filter() const {
	return m_filterstring;
}

bool sinsp::run_filters_on_evt(sinsp_evt* evt) const {
	//
	// First run the global filter, if there is one.
	//
	if(m_filter && m_filter->run(evt) == true) {
		return true;
	}

	return false;
}

const scap_machine_info* sinsp::get_machine_info() const {
	return m_machine_info;
}

const scap_agent_info* sinsp::get_agent_info() const {
	return m_agent_info;
}

std::unique_ptr<sinsp_filter_check> sinsp::new_generic_filtercheck() {
	return std::make_unique<sinsp_filter_check_gen_event>();
}

void sinsp::get_capture_stats(scap_stats* stats) const {
	/* On purpose ignoring failures to not interrupt in case of stats retrieval failure. */
	scap_get_stats(m_h, stats);
	stats->n_suppressed = m_suppress.get_num_suppressed_events();
	stats->n_tids_suppressed = m_suppress.get_num_suppressed_tids();
}

void sinsp::print_capture_stats(sinsp_logger::severity sev) const {
	scap_stats stats = {};
	get_capture_stats(&stats);

	libsinsp_logger()->format(
	        sev,
	        "\nn_evts:%" PRIu64 "\nn_drops:%" PRIu64 "\nn_drops_buffer:%" PRIu64
	        "\nn_drops_buffer_clone_fork_enter:%" PRIu64 "\nn_drops_buffer_clone_fork_exit:%" PRIu64
	        "\nn_drops_buffer_execve_enter:%" PRIu64 "\nn_drops_buffer_execve_exit:%" PRIu64
	        "\nn_drops_buffer_connect_enter:%" PRIu64 "\nn_drops_buffer_connect_exit:%" PRIu64
	        "\nn_drops_buffer_open_enter:%" PRIu64 "\nn_drops_buffer_open_exit:%" PRIu64
	        "\nn_drops_buffer_dir_file_enter:%" PRIu64 "\nn_drops_buffer_dir_file_exit:%" PRIu64
	        "\nn_drops_buffer_other_interest_enter:%" PRIu64
	        "\nn_drops_buffer_other_interest_exit:%" PRIu64 "\nn_drops_buffer_close_exit:%" PRIu64
	        "\nn_drops_buffer_proc_exit:%" PRIu64 "\nn_drops_scratch_map:%" PRIu64
	        "\nn_drops_pf:%" PRIu64 "\nn_drops_bug:%" PRIu64 "\n",
	        stats.n_evts,
	        stats.n_drops,
	        stats.n_drops_buffer,
	        stats.n_drops_buffer_clone_fork_enter,
	        stats.n_drops_buffer_clone_fork_exit,
	        stats.n_drops_buffer_execve_enter,
	        stats.n_drops_buffer_execve_exit,
	        stats.n_drops_buffer_connect_enter,
	        stats.n_drops_buffer_connect_exit,
	        stats.n_drops_buffer_open_enter,
	        stats.n_drops_buffer_open_exit,
	        stats.n_drops_buffer_dir_file_enter,
	        stats.n_drops_buffer_dir_file_exit,
	        stats.n_drops_buffer_other_interest_enter,
	        stats.n_drops_buffer_other_interest_exit,
	        stats.n_drops_buffer_close_exit,
	        stats.n_drops_buffer_proc_exit,
	        stats.n_drops_scratch_map,
	        stats.n_drops_pf,
	        stats.n_drops_bug);
}

const metrics_v2* sinsp::get_capture_stats_v2(uint32_t flags, uint32_t* nstats, int32_t* rc) const {
	/* On purpose ignoring failures to not interrupt in case of stats retrieval failure. */
	const metrics_v2* stats_v2 = scap_get_stats_v2(m_h, flags, nstats, rc);
	if(!stats_v2) {
		*nstats = 0;
		return nullptr;
	}
	return stats_v2;
}

void sinsp::set_log_callback(sinsp_logger_callback cb) {
	if(cb) {
		libsinsp_logger()->add_callback_log(cb);
	} else {
		libsinsp_logger()->remove_callback_log();
	}
}

void sinsp::set_log_file(const std::string& filename) {
	libsinsp_logger()->add_file_log(filename);
}

void sinsp::set_log_stderr() {
	libsinsp_logger()->add_stderr_log();
}

void sinsp::set_min_log_severity(sinsp_logger::severity sev) {
	libsinsp_logger()->set_severity(sev);
}

sinsp_evttables* sinsp::get_event_info_tables() {
	return &g_infotables;
}

void sinsp::set_buffer_format(sinsp_evt::param_fmt format) {
	m_buffer_format = format;
}

sinsp_evt::param_fmt sinsp::get_buffer_format() const {
	return m_buffer_format;
}

void sinsp::set_large_envs(bool enable) {
	m_large_envs_enabled = enable;
}

void sinsp::set_debug_mode(bool enable_debug) {
	m_isdebug_enabled = enable_debug;
}

void sinsp::set_fatfile_dump_mode(bool enable_fatfile) {
	m_isfatfile_enabled = enable_fatfile;
}

void sinsp::set_internal_events_mode(bool enable_internal_events) {
	m_isinternal_events_enabled = enable_internal_events;
}

void sinsp::set_hostname_and_port_resolution_mode(bool enable) {
	m_hostname_and_port_resolution_enabled = enable;
}

void sinsp::set_max_evt_output_len(uint32_t len) {
	m_max_evt_output_len = len;
}

double sinsp::get_read_progress_file() const {
	if(m_input_fd != 0) {
		// We can't get a reliable file size, so we can't get
		// any reliable progress
		return 0;
	}

	if(m_filesize == -1) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	ASSERT(m_filesize != 0);

	int64_t fpos = scap_get_readfile_offset(m_h);

	if(fpos == -1) {
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	return (double)fpos * 100 / m_filesize;
}

void sinsp::get_read_progress_plugin(double* nres, std::string* sres) const {
	ASSERT(nres != nullptr);
	ASSERT(sres != nullptr);
	if(!nres || !sres) {
		return;
	}

	if(!m_input_plugin) {
		*nres = -1;
		*sres = "No Input Plugin";

		return;
	}

	uint32_t nplg = 0;
	*sres = m_input_plugin->get_progress(nplg);

	*nres = ((double)nplg) / 100;
}

double sinsp::get_read_progress() const {
	if(is_plugin()) {
		double res = 0;
		get_read_progress_plugin(&res, nullptr);
		return res;
	} else {
		return get_read_progress_file();
	}
}

double sinsp::get_read_progress_with_str(std::string* progress_str) const {
	if(is_plugin()) {
		double res = 0;
		get_read_progress_plugin(&res, progress_str);
		return res;
	} else {
		*progress_str = "";
		return get_read_progress_file();
	}
}

bool sinsp::remove_inactive_threads() {
	return m_thread_manager->remove_inactive_threads();
}

void sinsp::set_thread_timeout_s(uint32_t val) {
	m_thread_timeout_ns = (uint64_t)val * ONE_SECOND_IN_NS;
}

void sinsp::set_proc_scan_timeout_ms(uint64_t val) {
	m_proc_scan_timeout_ms = val;
}

void sinsp::set_proc_scan_log_interval_ms(uint64_t val) {
	m_proc_scan_log_interval_ms = val;
}

///////////////////////////////////////////////////////////////////////////////
// Note: this is defined here so we can inline it in sinso::next
///////////////////////////////////////////////////////////////////////////////

/* Returns true when we scan the table */
bool sinsp_thread_manager::remove_inactive_threads() {
	const uint64_t last_event_ts = m_timestamper.get_cached_ts();

	if(m_last_flush_time_ns == 0) {
		// Set the first table scan for 30 seconds in, so that we can spot bugs in the logic without
		// having to wait for tens of minutes.
		if(m_threads_purging_scan_time_ns > 30 * ONE_SECOND_IN_NS) {
			m_last_flush_time_ns =
			        last_event_ts - m_threads_purging_scan_time_ns + 30 * ONE_SECOND_IN_NS;
		} else {
			m_last_flush_time_ns = last_event_ts - m_threads_purging_scan_time_ns;
		}
	}

	if(last_event_ts <= m_last_flush_time_ns + m_threads_purging_scan_time_ns) {
		return false;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "Flushing thread table");
	m_last_flush_time_ns = last_event_ts;

	// Here we loop over the table in search of threads to delete. We remove:
	// 1. Invalid threads.
	// 2. Threads that we are not using and that are no more alive in /proc.
	std::unordered_set<int64_t> to_delete;
	m_threadtable.loop([&](sinsp_threadinfo& tinfo) {
		if(tinfo.is_invalid() || (last_event_ts > tinfo.m_lastaccess_ts + m_thread_timeout_ns &&
		                          !scap_is_thread_alive(m_scap_platform,
		                                                tinfo.m_pid,
		                                                tinfo.m_tid,
		                                                tinfo.m_comm.c_str()))) {
			to_delete.insert(tinfo.m_tid);
		}
		return true;
	});

	for(const auto& tid_to_remove : to_delete) {
		remove_thread(tid_to_remove);
	}

	// Clean expired threads in the group and children.
	reset_child_dependencies();
	return true;
}

std::unique_ptr<sinsp_threadinfo> libsinsp::event_processor::build_threadinfo(
        const std::shared_ptr<sinsp_threadinfo_ctor_params>& params) {
	return std::make_unique<sinsp_threadinfo>(params);
}

std::unique_ptr<sinsp_fdinfo> libsinsp::event_processor::build_fdinfo(sinsp* inspector) {
	return sinsp_fdinfo_factory::create_unique_attorney::create(inspector->get_fdinfo_factory());
}

void sinsp::handle_async_event(std::unique_ptr<sinsp_evt> evt) {
	// see comments in handle_plugin_async_event
	ASSERT(!is_capture());
	evt->set_inspector(this);
	if(evt->get_scap_evt()->ts != (uint64_t)-1 &&
	   evt->get_scap_evt()->ts > sinsp_utils::get_current_time_ns() + ONE_SECOND_IN_NS * 10) {
		libsinsp_logger()->log("async event ts too far in future", sinsp_logger::SEV_WARNING);
		return;
	}

	if(!m_async_events_queue.push(std::move(evt))) {
		libsinsp_logger()->log("async event queue is full", sinsp_logger::SEV_WARNING);
	}
}

void sinsp::handle_plugin_async_event(const sinsp_plugin& p, std::unique_ptr<sinsp_evt> evt) {
	// Note: this function can be invoked from different plugin threads, so we need to make sure
	// that every variable we read is either constant during the lifetime of those threads, or that
	// it is atomic.

	// Note: we make sure that async events are dequeued, however they are considered only during
	// live captures, because offline captures will have the async events already encoded in the
	// event stream.
	if(is_capture()) {
		return;
	}

	// Note: async events are injected in the same event source as the currently open one. (Right
	// now we can have just one event source open per inspector). There are 2 cases:
	//
	// 1. If a source plugin is open the async events can only be injected in the plugin source.
	// 2. If no source plugins are loaded the async events can only be injected in the syscall
	// source.
	//
	// We need to check if the async plugin specified an event source compliant with the above
	// rules, in the `get_async_event_sources` API. We reject the event if that's not the case.
	//
	// todo(jasondellaluce): here we are assuming that the "syscall" event source is always at index
	//   0 in the inspector's event source list, change this code if this assumption ever stops
	//   being true.

	// Default: syscall source.
	size_t cur_evtsrc_idx = 0;
	uint32_t cur_plugin_id = 0;

	// If we have a source plugin, we search for its event source, and we update the current event
	// source. Otherwise, the current event source remains the syscall one.
	if(is_plugin()) {
		cur_plugin_id = m_input_plugin->id();
		if(cur_plugin_id != 0) {
			bool found = false;
			cur_evtsrc_idx = m_plugin_manager->source_idx_by_plugin_id(cur_plugin_id, found);
			if(!found) {
				throw sinsp_exception("can't find event source for plugin ID: " +
				                      std::to_string(cur_plugin_id));
			}
		}
	}
	ASSERT(cur_evtsrc_idx < m_event_sources.size());
	const auto& cur_evtsrc = m_event_sources[cur_evtsrc_idx];
	if(!sinsp_plugin::is_source_compatible(p.async_event_sources(), cur_evtsrc)) {
		throw sinsp_exception("async events of plugin '" + p.name() +
		                      "' are not compatible with open event source '" + cur_evtsrc + "'");
	}

	// If the async event is generated by a non-syscall event source, then async events must have no
	// thread associated.
	if(cur_plugin_id != 0 && evt->get_scap_evt()->tid != (uint64_t)-1) {
		throw sinsp_exception("async events of plugin '" + p.name() +
		                      "' can have no thread associated with open event source '" +
		                      cur_evtsrc + "'");
	}

	// Write plugin ID and timestamp in the event and kick it in the queue.
	auto plid = (uint32_t*)((uint8_t*)evt->get_scap_evt() + sizeof(scap_evt) + 4 + 4 + 4);
	memcpy(plid, &cur_plugin_id, sizeof(cur_plugin_id));
	handle_async_event(std::move(evt));
}

bool sinsp::get_track_connection_status() const {
	return m_parser->get_track_connection_status();
}

void sinsp::set_track_connection_status(const bool enabled) const {
	m_parser->set_track_connection_status(enabled);
}

std::shared_ptr<sinsp_thread_pool> sinsp::get_thread_pool() {
	return m_thread_pool;
}

bool sinsp::set_thread_pool(const std::shared_ptr<sinsp_thread_pool>& tpool) {
	if(m_thread_pool) {
		return false;
	}

	m_thread_pool = tpool;
	return true;
}
