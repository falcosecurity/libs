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

/*!
    \mainpage libsinsp documentation

    \section Introduction

    libsinsp is a system inspection library written in C++ and implementing high level
    functionality like:
    - live capture control (start/stop/pause...)
    - event capture from file or the live OS
    - OS state reconstruction. By parsing /proc and inspecting the live event stream,
    libsinsp is capable of mirroring the OS process state and putting context around
    key OS primitives like process IDs and file descriptors. That way, these primitives
    can be treated like programs, files, connections and users.
    - parsing of OS events and conversion of events into human-readable strings
    - event filtering

    This manual includes the following sections:
    - \ref inspector
    - \ref event
    - \ref dump
    - \ref filter
    - \ref state
*/

#pragma once

#include <libscap/scap.h>

#include <libsinsp/capture_stats_source.h>
#include <libsinsp/dumper.h>
#include <libsinsp/event.h>
#include <libsinsp/filter.h>
#include <libsinsp/ifinfo.h>
#include <libsinsp/eventformatter.h>
#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/filter/ast.h>
#include <libsinsp/filter/escaping.h>
#include <libsinsp/filter/parser.h>
#include <libsinsp/filter/ppm_codes.h>
#include <libsinsp/gvisor_config.h>
#include <libsinsp/logger.h>
#include <libsinsp/mpsc_priority_queue.h>
#include <libsinsp/plugin.h>
#include <libsinsp/plugin_parser.h>
#include <libsinsp/settings.h>
#include <libsinsp/sinsp_cycledumper.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/sinsp_external_processor.h>
#include <libsinsp/sinsp_inet.h>
#include <libsinsp/sinsp_public.h>
#include <libsinsp/sinsp_suppress.h>
#include <libsinsp/state/table_registry.h>
#include <libsinsp/metrics_collector.h>
#include <libsinsp/thread_manager.h>
#include <libsinsp/tuples.h>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_mode.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/sinsp_fdtable_factory.h>
#include <libsinsp/sinsp_threadinfo_factory.h>
#include <libsinsp/sinsp_thread_manager_factory.h>
#include <libsinsp/sinsp_parser_verdict.h>
#include <libsinsp/timestamper.h>

#include <list>
#include <map>
#include <memory>
#include <queue>
#include <string>
#include <unordered_set>
#include <vector>
#include <queue>

#define ONE_SECOND_IN_NS 1000000000LL

class sinsp_parser;
class sinsp_filter;
class sinsp_plugin;
class sinsp_plugin_manager;
class sinsp_observer;
class sinsp_usergroup_manager;

/*!
  \brief The user agent string to use for any libsinsp connection, can be changed at compile time
*/

#if !defined(LIBSINSP_USER_AGENT)
#define LIBSINSP_USER_AGENT "falcosecurity-libs"
#endif  // LIBSINSP_USER_AGENT

/*!
  \brief The default way an event is converted to string by the library
*/
#define DEFAULT_OUTPUT_STR \
	"*%evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args"

/**
 * @brief Possible platforms to use with plugins
 */
enum class sinsp_plugin_platform {
	SINSP_PLATFORM_GENERIC,   //!< generic platform, no system information collected
	SINSP_PLATFORM_HOSTINFO,  //!< basic host information collected, for non-syscall source plugins
	SINSP_PLATFORM_FULL,      //!< full system information collected, for syscall source plugins
};

/** @defgroup inspector Main library
 @{
*/

/*!
  \brief System inspector class.
  This is the library entry point class. The functionality it exports includes:
  - live capture control (start/stop/pause...)
  - trace file management
  - event retrieval
  - setting capture filters
*/
class SINSP_PUBLIC sinsp : public capture_stats_source {
public:
	sinsp(bool with_metrics = false);

	virtual ~sinsp() override;

	/* Wrappers to open a specific engine. */
	virtual void open_kmod(unsigned long driver_buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM,
	                       const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest = {});
	virtual void open_bpf(const std::string& bpf_path,
	                      unsigned long driver_buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM,
	                      const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest = {});
	virtual void open_nodriver(bool full_proc_scan = false);
	virtual void open_savefile(const std::string& filename, int fd = 0);
	virtual void open_plugin(const std::string& plugin_name,
	                         const std::string& plugin_open_params,
	                         sinsp_plugin_platform platform_type);
	virtual void open_gvisor(const std::string& config_path,
	                         const std::string& root_path,
	                         bool no_events = false,
	                         int epoll_timeout = -1);
	/*[EXPERIMENTAL] This API could change between releases, we are trying to find the right
	 * configuration to deploy the modern bpf probe: `cpus_for_each_buffer` and `online_only` are
	 * the 2 experimental params. The first one allows associating more than one CPU to a single
	 * ring buffer. The last one allows allocating ring buffers only for online CPUs and not for all
	 * system-available CPUs.
	 */
	virtual void open_modern_bpf(
	        unsigned long driver_buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM,
	        uint16_t cpus_for_each_buffer = DEFAULT_CPU_FOR_EACH_BUFFER,
	        bool online_only = true,
	        const libsinsp::events::set<ppm_sc_code>& ppm_sc_of_interest = {});
	virtual void open_test_input(scap_test_input_data* data, sinsp_mode_t mode = SINSP_MODE_TEST);

	void fseek(uint64_t filepos) { scap_fseek(m_h, filepos); }

	std::string generate_gvisor_config(const std::string& socket_path);

	/*!
	  \brief Ends a capture and release all resources.
	*/
	void close();

	/*!
	  \brief Get the next event from the open capture source

	  \param evt [out] a \ref sinsp_evt pointer that will be initialized to point to
	  the next available event.

	  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain
	   valid data. SCAP_TIMEOUT in case the read timeout expired and no event is
	   available. SCAP_EOF when the end of an offline capture is reached.
	   On Failure, SCAP_FAILURE is returned and getlasterr() can be used to
	   obtain the cause of the error.

	  \note: the returned event can be considered valid only until the next
	   call to \ref)
	*/
	virtual int32_t next(sinsp_evt** evt);

	/*!
	  \brief Get the maximum number of bytes currently in use by any CPU buffer
	 */
	uint64_t max_buf_used() const;

	/*!
	  \brief Get the number of events that have been captured and processed
	   since the call to \ref open()

	  \return the number of captured events.
	*/
	uint64_t get_num_events() const;

	/*!
	  \brief Set the capture snaplen, i.e. the maximum size an event
	  parameter can reach before the driver starts truncating it.

	  \param snaplen the snaplen for this capture instance, in bytes.

	  \note This function can only be called for live captures.
	  \note By default, the driver captures the first 80 bytes of the
	  buffers coming from events like read, write, send, recv, etc.
	  If you're not interested in payloads, smaller values will save
	  capture buffer space and make capture files smaller.
	  Conversely, big values should be used with care because they can
	  easily generate huge capture files.

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	void set_snaplen(uint32_t snaplen);

	/*!
	 * \brief (Un)Set the drop failed feature of the drivers.
	    When enabled, drivers will stop sending failed syscalls (exit) events.

	 * @param dropfailed whether to enable the feature
	 */
	void set_dropfailed(bool dropfailed);

	/*!
	  \brief Determine if this inspector is going to load user tables on
	  startup.

	  \param import_users if true, no user tables will be created for
	  this capture. This also means that no user or group info will be
	  written to the trace file by the -w flag. The user/group tables are
	  necessary to use filter fields like user.name or group.name. However,
	  creating them can increase the startup time. Moreover, they contain
	  information that could be privacy sensitive.

	  \note default behavior is import_users=true, user_details=true

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	void set_import_users(bool import_users);

	/*!
	  \brief temporarily pauses event capture.

	  \note This function can only be called for live captures.
	*/
	void stop_capture();

	/*!
	  \brief Restarts an event capture that had been paused with
	   \ref stop_capture().

	  \note This function can only be called for live captures.
	*/
	void start_capture();

	/*!
	  \brief Compiles and installs the given capture filter.

	  \param filter the filter string. Refer to the filtering language
	   section for information about the filtering
	   syntax.

	  @throws a sinsp_exception containing the error string is thrown in case
	   the filter is invalid.
	*/
	void set_filter(const std::string& filter);

	/*!
	  \brief Installs the given capture runtime filter object.

	  \param filter the runtime filter object
	*/
	void set_filter(std::unique_ptr<sinsp_filter> filter, const std::string& filterstring = "");

	/*!
	  \brief Return the filter set for this capture.

	  \return the filter previously set with \ref set_filter(), or an empty
	   string if no filter has been set yet.
	*/
	std::string get_filter() const;

	/*!
	  \brief Return the AST (wrapped in a shared pointer) for the filter set for this capture.

	  \return the AST (wrapped in a shared pointer) corresponding to the filter previously set with
	  \ref set_filter()..
	*/
	inline const std::shared_ptr<libsinsp::filter::ast::expr>& get_filter_ast() {
		return m_internal_flt_ast;
	}

	bool run_filters_on_evt(sinsp_evt* evt) const;

	/*!
	  \brief This method can be used to specify a function to collect the library
	   log messages.

	  \param cb the target function that will receive the log messages.
	*/
	void set_log_callback(sinsp_logger_callback cb);

	/*!
	  \brief Instruct sinsp to write its log messages to the given file.
	*/
	void set_log_file(const std::string& filename);

	/*!
	  \brief Instruct sinsp to write its log messages to stderr.
	*/
	void set_log_stderr();

	/*!
	  \brief Specify the minimum severity of the messages that go into the logs
	   emitted by the library.
	*/
	void set_min_log_severity(sinsp_logger::severity sev);

	/*!
	 * \brief Enables or disables an automatic routine that periodically purges
	 * thread infos from the internal state. If disabled, the client is
	 * responsible of manually-handling the lifetime of threads.
	 * When the routine is run, then the purge interval and thread timeout
	 * change defaults, but with no observable effect.
	 */
	void set_auto_threads_purging(bool enabled) { m_auto_threads_purging = enabled; }

	/*!
	 * \brief Sets the interval (in seconds) at which the automatic threads
	 * purging routine runs (if enabled).
	 */
	inline void set_auto_threads_purging_interval_s(uint32_t val) {
		m_threads_purging_scan_time_ns = (uint64_t)val * ONE_SECOND_IN_NS;
	}

	/*!
	 * \brief Enables or disables an automatic routine that periodically logs
	 * the current capture stats.
	 */
	inline void set_auto_stats_print(bool enabled) { m_auto_stats_print = enabled; }

	/*!
	 * \brief sets the amount of time after which a thread which has seen no events
	 *        can be purged. As the purging happens only every m_thread_purge_interval_s,
	 *        the max time a thread may linger is actually m_thread_purge_interval +
	 *        m_thread_timeout_s
	 */
	void set_thread_timeout_s(uint32_t val);

	/*!
	 * \brief sets the max amount of time that the initial scan of /proc should execute,
	 *        after which a so-far-successful scan should be stopped and success returned.
	 *        Value of SCAP_PROC_SCAN_TIMEOUT_NONE (default) means run to completion.
	 */
	void set_proc_scan_timeout_ms(uint64_t val);

	/*!
	 * \brief sets the interval for logging progress messages during initial scan of /proc.
	 *        Value of SCAP_PROC_SCAN_LOGUT_NONE (default) means no logging.
	 */
	void set_proc_scan_log_interval_ms(uint64_t val);

	/*!
	  \brief Returns a new instance of a filtercheck supporting fields for
	  a generic event source (e.g. evt.num, evt.time, evt.pluginname...)
	*/
	static std::unique_ptr<sinsp_filter_check> new_generic_filtercheck();

	/*!
	  \brief Return information about the machine generating the events.

	  \note this call works with file captures as well, because the machine
	   info is stored in the trace files. In that case, the returned
	   machine info is the one of the machine where the capture happened.
	*/
	const scap_machine_info* get_machine_info() const;

	inline void set_machine_info(const scap_machine_info* v) { m_machine_info = v; }

	/*!
	  \brief Return information about the agent based on start up conditions.

	  \note not for use in scap files.
	*/
	const scap_agent_info* get_agent_info() const;

	/*!
	  \brief Return sinsp stats v2 containing continually updated counters around thread and fd
	  state tables.

	*/
	inline const std::shared_ptr<sinsp_stats_v2>& get_sinsp_stats_v2() { return m_sinsp_stats_v2; }

	inline std::shared_ptr<const sinsp_stats_v2> get_sinsp_stats_v2() const {
		return m_sinsp_stats_v2;
	}

	/*!
	  \brief Fill the given structure with statistics about the currently
	   open capture.

	  \note sinsp stats may be refactored near-term, see also metrics_v2.
	*/
	void get_capture_stats(scap_stats* stats) const override;

	/*!
	  \brief Print a log with statistics about the currently
	   open capture. Use the severity specified as the first parameter.
	*/
	void print_capture_stats(sinsp_logger::severity sev) const override;

	/*!
	  \brief Get engine statistics (including counters and `bpftool prog show` like stats).

	  \note sinsp stats may be refactored near-term.

	  \return Pointer to a \ref metrics_v2 structure filled with the statistics.
	*/
	const struct metrics_v2* get_capture_stats_v2(uint32_t flags,
	                                              uint32_t* nstats,
	                                              int32_t* rc) const override;

	libsinsp::event_processor* m_external_event_processor;

	/*!
	  \brief registers external event processor.
	  After this, callbacks on libsinsp::event_processor will happen at
	  the appropriate times. This registration must happen before calling open.
	*/
	void register_external_event_processor(libsinsp::event_processor& processor) {
		m_external_event_processor = &processor;
	}

	libsinsp::event_processor* get_external_event_processor() const {
		return m_external_event_processor;
	}

	/*!
	  \brief Return the event and system call information tables.

	  This function exports the tables containing the information about the
	  events supported by the capture infrastructure and the available system calls.
	*/
	sinsp_evttables* get_event_info_tables();

	/*!
	  \brief get last library error.
	*/
	std::string getlasterr() const { return m_lasterr; }

	/*!
	  \brief Get the list of machine network interfaces.

	  \return Pointer to the interface list manager.
	*/
	const sinsp_network_interfaces& get_ifaddr_list() const;

	inline sinsp_network_interfaces& get_ifaddr_list() { return m_network_interfaces; }

	inline void set_ifaddr_list(const sinsp_network_interfaces& v) { m_network_interfaces = v; }

	/*!
	  \brief Set the format used to render event data
	   buffer arguments.
	*/
	void set_buffer_format(sinsp_evt::param_fmt format);

	/*!
	  \brief Get the format used to render event data
	   buffer arguments.
	*/
	sinsp_evt::param_fmt get_buffer_format() const;

	/*!
	  \brief Returns true if the current capture is happening from a scap file
	*/
	inline bool is_capture() const { return m_mode.is_capture(); }

	/*!
	  \brief Returns true if the current capture is offline
	*/
	inline bool is_offline() const { return m_mode.is_offline(); }

	/*!
	  \brief Returns true if the current capture is live
	*/
	inline bool is_live() const { return m_mode.is_live(); }

	/*!
	  \brief Returns true if the kernel module is not loaded
	*/
	inline bool is_nodriver() const { return m_mode.is_nodriver(); }

	/*!
	  \brief Returns true if the current capture has a plugin producing events.
	*/
	inline bool is_plugin() const { return m_mode.is_plugin() && m_input_plugin != nullptr; }

	/*!
	  \brief Returns true if the current capture has a plugin producing syscall events.
	*/
	inline bool is_syscall_plugin() const {
		return m_mode.is_plugin() && m_input_plugin->id() == 0;
	}

	/*!
	  \brief Returns the framework plugin api version as a string with static storage
	*/
	inline const char* get_plugin_api_version() const { return PLUGIN_API_VERSION_STR; }

	/*!
	  \brief Returns the API version supported by the driver
	*/
	inline uint64_t get_driver_api_version() const { return scap_get_driver_api_version(m_h); }

	/*!
	  \brief Returns the minimum API version required by the userspace library
	*/
	inline uint64_t get_scap_api_version() const { return SCAP_MINIMUM_DRIVER_API_VERSION; }

	/*!
	  \brief Returns the schema version supported by the driver
	*/
	inline uint64_t get_driver_schema_version() const {
		return scap_get_driver_schema_version(m_h);
	}

	/*!
	  \brief Returns the minimum schema version required by the userspace library
	*/
	inline uint64_t get_scap_schema_version() const { return SCAP_MINIMUM_DRIVER_SCHEMA_VERSION; }

	/*!
	  \brief Returns true if truncated environments should be loaded from /proc
	*/
	bool large_envs_enabled() const {
		return (is_live() || is_syscall_plugin()) && m_large_envs_enabled;
	}

	/*!
	  \brief Enable/disable large environment support

	  \param enable when it is true and the current capture is live
	  environments larger than SCAP_MAX_ENV_SIZE will be loaded
	  from /proc/<pid>/environ (if possible)
	*/
	void set_large_envs(bool enable);

	/*!
	  \brief Set the debugging mode of the inspector.

	  \param enable_debug when it is true and the current capture is live
	  the inspector filters out events about itself.
	*/
	void set_debug_mode(bool enable_debug);

	/*!
	  \brief Set the fatfile mode when writing events to file.

	  \note fatfile mode involves saving "hidden" events in the trace file
	   that make it possible to preserve full state even when filters that
	   would drop state packets are used during the capture.
	*/
	void set_fatfile_dump_mode(bool enable_fatfile);

	inline bool is_fatfile_enabled() const { return m_isfatfile_enabled; }

	/*!
	  \brief Set internal events mode.

	  \note By default, internal events, such as events that note
	            when new containers or orchestration entities have
	            been created, are not returned in sinsp::next(). (They
	            are always written to capture files, to ensure that
	            the full state can be reconstructed when capture files
	            are read). Enabling internal events mode will result
	            in these events being returned.
	*/
	void set_internal_events_mode(bool enable_internal_events);

	/*!
	  \brief Set whether to resolve hostnames and port protocols or not.

	  \note It can use the system library functions getservbyport and so to
	   resolve protocol names and domain names.

	  \param enable If set to false it will enable this function and use plain
	   numerical values.
	*/
	void set_hostname_and_port_resolution_mode(bool enable);

	inline bool is_hostname_and_port_resolution_enabled() const {
		return m_hostname_and_port_resolution_enabled;
	}

	/*!
	  \brief Set the runtime flag for resolving the timespan in a human
	   readable mode.

	  \param flag Can be 'h', 'a', 'r', 'd', 'D' as documented in the manual.
	*/
	inline void set_time_output_mode(char flag) { m_output_time_flag = flag; }

	inline char get_time_output_mode() const { return m_output_time_flag; }

	/*!
	  \brief Sets the max length of event argument strings.

	  \param len Max length after which an event argument string is truncated.
	   0 means no limit. Use this to reduce verbosity when printing event info
	   on screen.
	*/
	void set_max_evt_output_len(uint32_t len);

	inline uint32_t get_max_evt_output_len() const { return m_max_evt_output_len; }

	/*!
	  \brief Returns true if the debug mode is enabled.
	*/
	inline bool is_debug_enabled() const { return m_isdebug_enabled; }

	/*!
	  \brief If this is an offline capture, return the name of the file that is
	   being read, otherwise return an empty string.
	*/
	std::string get_input_filename() const { return m_input_filename; }

	/*!
	  \brief When reading events from a trace file or a plugin, this function
	   returns the read progress as a number between 0 and 100.
	*/
	double get_read_progress() const;

	/*!
	  \brief When reading events from a trace file or a plugin, this function
	   returns the read progress as a number and as a string, giving the plugins
	   flexibility on the format.

	  \param progress_str [out] a string representation of progress for plugins
	*/
	double get_read_progress_with_str(std::string* progress_str) const;

	/*!
	  \brief Make the amount of data gathered for a syscall to be
	  determined by the number of parameters.
	*/
	virtual int /*SCAP_X*/ dynamic_snaplen(bool enable) {
		if(enable) {
			return scap_enable_dynamic_snaplen(m_h);
		} else {
			return scap_disable_dynamic_snaplen(m_h);
		}
	}

	//
	// Misc internal stuff
	//
	void stop_dropping_mode();
	void start_dropping_mode(uint32_t sampling_ratio);
	void on_proc_table_refresh_start();
	void on_proc_table_refresh_end();
	void on_new_entry_from_proc(void* context,
	                            int64_t tid,
	                            scap_threadinfo* tinfo,
	                            scap_fdinfo* fdinfo);
	void set_get_procs_cpu_from_driver(bool get_procs_cpu_from_driver) {
		m_get_procs_cpu_from_driver = get_procs_cpu_from_driver;
	}

	inline sinsp_parser* get_parser() { return m_parser.get(); }

	inline const sinsp_parser* get_parser() const { return m_parser.get(); }

	/*=============================== PPM_SC set related (ppm_sc.cpp)
	 * ===============================*/

	/*!
	    \brief Mark desired scap code as (un)interesting, enabling or disabling its collection.
	    Note that the same ppm_code can match multiple system syscalls or tracepoints.

	    Please note that this method must be called when the inspector is already open to
	    modify at runtime the interesting syscall set.

	    WARNING: playing with this API could break `libsinsp` state collection, this is only
	    useful in advanced cases where the client needs to know what it is doing!
	*/
	void mark_ppm_sc_of_interest(ppm_sc_code ppm_sc, bool enabled = true);

	/*=============================== PPM_SC set related (ppm_sc.cpp)
	 * ===============================*/

	/*=============================== Engine related ===============================*/

	/**
	 * @brief Check if the current engine is the one passed as parameter.
	 *
	 * @param engine_name engine that we want to check.
	 * @return true if the passed engine is the active one otherwise false.
	 */
	bool check_current_engine(const std::string& engine_name) const;

	/*=============================== Engine related ===============================*/

	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);

	uint64_t get_bytes_read() const { return scap_ftell(m_h); }
	void refresh_ifaddr_list();
	void refresh_proc_list() { scap_refresh_proc_table(get_scap_platform()); }

	std::vector<long> get_n_tracepoint_hit() const;

	static unsigned num_possible_cpus();

	// Add comm to the list of comms for which the inspector
	// should not return events.
	bool suppress_events_comm(const std::string& comm);

	bool suppress_events_tid(int64_t tid);

	void clear_suppress_events_comm();

	void clear_suppress_events_tid();

	bool check_suppressed(int64_t tid) const;

	void set_fullcapture_port_range(uint16_t range_start, uint16_t range_end);

	void set_statsd_port(uint16_t port);

	// Create and register a plugin from a shared library pointed
	// to by filepath, and add it to the inspector.
	// The created sinsp_plugin is returned.
	std::shared_ptr<sinsp_plugin> register_plugin(const std::string& filepath);

	// Create and register a plugin given a custom API vtable.
	// The passed-in api pointer will not be retained, its values will be copied
	// internally.
	std::shared_ptr<sinsp_plugin> register_plugin(const plugin_api* api);

	inline std::shared_ptr<const sinsp_plugin_manager> get_plugin_manager() const {
		return m_plugin_manager;
	}

	void handle_async_event(std::unique_ptr<sinsp_evt> evt);
	void handle_plugin_async_event(const sinsp_plugin& p, std::unique_ptr<sinsp_evt> evt);

	inline const std::vector<std::string>& event_sources() const { return m_event_sources; }

	inline const std::shared_ptr<libsinsp::state::table_registry>& get_table_registry() const {
		return m_table_registry;
	}

	uint64_t get_lastevent_ts() const { return m_timestamper.get_cached_ts(); }
	void set_lastevent_ts(const uint64_t v) { m_timestamper.set_cached_ts(v); }

	inline const std::string& get_host_root() const { return m_host_root; }
	inline void set_host_root(const std::string& s) { m_host_root = s; }

	inline const int32_t& get_quantization_interval() const { return m_quantization_interval; }
	inline void set_quantization_interval(const int32_t& v) { m_quantization_interval = v; }

	inline void set_observer(sinsp_observer* observer) { m_observer = observer; }
	inline sinsp_observer* get_observer() const { return m_observer; }

	bool get_track_connection_status() const;
	inline void set_track_connection_status(bool enabled) const;

	std::shared_ptr<sinsp_thread_pool> get_thread_pool();
	bool set_thread_pool(const std::shared_ptr<sinsp_thread_pool>& tpool);

	/**
	 * \brief Get a new timestamp.
	 *
	 * \return The current time in nanoseconds if the last event timestamp is 0,
	 * otherwise, the last event timestamp.
	 */
	uint64_t get_new_ts() const { return m_timestamper.get_new_ts(); }

	bool remove_inactive_threads();

	void set_mode(sinsp_mode_t value) { m_mode = value; }

	inline const struct scap_platform* get_scap_platform() const { return m_platform; }

	inline struct scap_platform* get_scap_platform() { return m_platform; }

	inline const scap_t* get_scap_handle() const { return m_h; }

	inline scap_t* get_scap_handle() { return m_h; }

	inline int64_t get_tid_to_remove() const { return m_parser_verdict.get_tid_to_remove(); }

	inline bool is_dumping() const { return m_is_dumping; }

	inline void set_dumping(bool v) { m_is_dumping = v; }

	inline uint32_t get_num_cpus() const { return m_num_cpus; }

private:
	void set_input_plugin(const std::string& name, const std::string& params);
	void open_common(scap_open_args* oargs,
	                 const struct scap_vtable* vtable,
	                 struct scap_platform* platform,
	                 sinsp_mode_t mode);
	void init();
	void set_thread_manager_foreign_accessors_and_tables() const;
	void deinit_state();
	void consume_initialstate_events();
	static bool is_initialstate_event(const scap_evt& pevent);
	void import_ifaddr_list();
	void import_user_list();
	int32_t fetch_next_event(sinsp_evt*& evt);

	//
	// Note: lookup_only should be used when the query for the thread is made
	//       not as a consequence of an event for that thread arriving, but
	//       just for lookup reason. In that case, m_lastaccess_ts is not updated
	//       and m_last_tinfo is not set.
	//
	inline const threadinfo_map_t::ptr_t& find_thread(int64_t tid, bool lookup_only) {
		return m_thread_manager->find_thread(tid, lookup_only);
	}

	static int64_t get_file_size(const std::string& fname, char* error);
	static std::string get_error_desc(const std::string& msg = "");

	void restart_capture();

	bool increased_snaplen_port_range_set() const {
		return m_increased_snaplen_port_range.range_start > 0 &&
		       m_increased_snaplen_port_range.range_end > 0;
	}

	double get_read_progress_file() const;
	void get_read_progress_plugin(double* nres, std::string* sres) const;

	void get_procs_cpu_from_driver(uint64_t ts);

	// regulates the logic behind event timestamp ordering.
	// returns true if left "comes first" than right, and false otherwise.
	// UINT64_MAX stands for max time priority -- as early as possible.
	static inline bool compare_evt_timestamps(uint64_t left, uint64_t right) {
		return left == static_cast<uint64_t>(-1) || left <= right;
	}

	bool must_notify_thread_user_update() const { return m_mode.is_live() || is_syscall_plugin(); }

	bool must_notify_thread_group_update() const { return m_mode.is_live() || is_syscall_plugin(); }

	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_t* m_h;
	struct scap_platform* m_platform{};
	char m_platform_lasterr[SCAP_LASTERR_SIZE];
	uint64_t m_nevts;
	int64_t m_filesize;
	sinsp_mode m_mode = SINSP_MODE_NONE;

	// If non-zero, reading from this fd and m_input_filename contains "fd
	// <m_input_fd>". Otherwise, reading from m_input_filename.
	int m_input_fd;
	std::string m_input_filename;
	bool m_isdebug_enabled;
	bool m_isfatfile_enabled;
	bool m_isinternal_events_enabled;
	bool m_hostname_and_port_resolution_enabled;
	char m_output_time_flag;
	uint32_t m_max_evt_output_len;
	sinsp_evt m_evt;
	std::string m_lasterr;
	sinsp_parser_verdict m_parser_verdict;
	timestamper m_timestamper;
	// the parsing engine
	std::unique_ptr<sinsp_parser> m_parser;
	// temporary storage for the parser event to avoid memory allocation
	sinsp_evt m_parser_tmp_evt;
	// the statistics analysis engine
	std::unique_ptr<sinsp_dumper> m_dumper;
	bool m_is_dumping;
	const scap_machine_info* m_machine_info;
	const scap_agent_info* m_agent_info;
	uint32_t m_num_cpus;
	bool m_large_envs_enabled;

	sinsp_network_interfaces m_network_interfaces{};

	std::string m_host_root;

	int32_t m_quantization_interval = -1;

	std::shared_ptr<sinsp_thread_pool> m_thread_pool;

	//
	// The ID of the plugin to use as event input, or zero
	// if no source plugin should be used as source
	//
	std::shared_ptr<sinsp_plugin> m_input_plugin;
	//
	// String with the parameters for the plugin to be used as input.
	// These parameters will be passed to the open function of the plugin.
	//
	std::string m_input_plugin_open_params;

	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos> m_thread_manager_dyn_fields;
	const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos> m_fdtable_dyn_fields;
	const sinsp_fdinfo_factory m_fdinfo_factory;
	// Parameter shared with each single sinsp_fdtable instance.
	const std::shared_ptr<sinsp_fdtable::ctor_params> m_fdtable_ctor_params;
	const sinsp_fdtable_factory m_fdtable_factory;
	// Parameter shared with each single sinsp_threadinfo instance.
	const std::shared_ptr<sinsp_threadinfo::ctor_params> m_threadinfo_ctor_params;
	const sinsp_threadinfo_factory m_threadinfo_factory;
	const sinsp_thread_manager_factory m_thread_manager_factory;
	// A registry that manages the state tables of this inspector.
	std::shared_ptr<libsinsp::state::table_registry> m_table_registry;

public:
	const sinsp_fdinfo_factory& get_fdinfo_factory() const { return m_fdinfo_factory; }
	const sinsp_threadinfo_factory& get_threadinfo_factory() const { return m_threadinfo_factory; }
	const sinsp_thread_manager_factory& get_thread_manager_factory() const {
		return m_thread_manager_factory;
	}

	std::shared_ptr<sinsp_thread_manager> m_thread_manager;
	std::shared_ptr<sinsp_usergroup_manager> m_usergroup_manager;

	uint64_t m_firstevent_ts;
	std::unique_ptr<sinsp_filter> m_filter;
	std::string m_filterstring;
	std::shared_ptr<libsinsp::filter::ast::expr> m_internal_flt_ast;

	//
	// Saved snaplen
	//
	uint32_t m_snaplen;

	//
	// Saved increased capture range
	//
	struct {
		uint16_t range_start;
		uint16_t range_end;
	} m_increased_snaplen_port_range;

	int32_t m_statsd_port;

	//
	// Some thread table limits
	//
	static constexpr uint32_t s_max_fdtable_size = MAX_FD_TABLE_SIZE;
	bool m_auto_threads_purging = true;
	uint64_t m_thread_timeout_ns = (uint64_t)1800 * ONE_SECOND_IN_NS;
	uint64_t m_threads_purging_scan_time_ns = (uint64_t)1200 * ONE_SECOND_IN_NS;

	//
	// How to render the data buffers
	//
	sinsp_evt::param_fmt m_buffer_format;

	// A queue of pending internal state events:
	// *	user added/removed events
	// * 	group added/removed events
	// *    async events produced by sinsp or plugins

	// m_injected_evts comparator
	using sinsp_evt_ptr = std::unique_ptr<sinsp_evt>;
	struct state_evts_less {
		bool operator()(const sinsp_evt& l, const sinsp_evt& r) {
			// order events in reverse-order as the lowest timestamp
			// has the highest priority
			return !compare_evt_timestamps(l.get_ts(), r.get_ts());
		}
	};

	// priority queue to hold injected events
	mpsc_priority_queue<sinsp_evt_ptr, state_evts_less> m_async_events_queue;

	// predicate struct for checking the head of the async events queue.
	// keeping a struct in the internal state makes sure that we don't do
	// any extra allocation by creating a lambda and its closure
	struct {
		uint64_t ts{0};

		bool operator()(const sinsp_evt& evt) const {
			return compare_evt_timestamps(evt.get_scap_evt()->ts, ts);
		};
	} m_async_events_checker;

	// Holds an event dequeued from the above queue
	sinsp_evt_ptr m_async_evt;

	// temp storage for scap_next
	// stores top scap_evt while qualified events from m_async_events_queue are being processed
	struct {
		inline auto next(scap_t* h) {
			auto res = scap_next(h, &m_pevt, &m_cpuid, &m_dump_flags);
			if(res != SCAP_SUCCESS) {
				clear();
			}
			return res;
		}
		inline void move(sinsp_evt* evt) {
			evt->set_scap_evt(m_pevt);
			evt->set_cpuid(m_cpuid);
			evt->set_dump_flags(m_dump_flags);
			clear();
		}
		inline bool empty() const { return m_pevt == nullptr; }
		inline void clear() {
			m_pevt = nullptr;
			m_cpuid = 0;
			m_dump_flags = 0;
		}

		scap_evt* m_pevt{nullptr};
		uint16_t m_cpuid{0};
		uint32_t m_dump_flags;
	} m_delayed_scap_evt;

	//
	// Used for collecting process CPU and res usage info from the kernel
	//
	bool m_get_procs_cpu_from_driver;
	uint64_t m_next_flush_time_ns;
	uint64_t m_last_procrequest_tod;

	//
	// End of second housekeeping
	//
	bool m_auto_stats_print = true;
	uint64_t m_next_stats_print_time_ns;

	static unsigned int m_num_possible_cpus;

	int64_t m_self_pid;

	//
	// /proc scan parameters
	//
	uint64_t m_proc_scan_timeout_ms;
	uint64_t m_proc_scan_log_interval_ms;

	libsinsp::sinsp_suppress m_suppress;

	//
	// Internal manager for plugins
	//
	std::shared_ptr<sinsp_plugin_manager> m_plugin_manager;
	//
	// Subset of loaded plugins that are used for event parsing.
	std::vector<sinsp_plugin_parser> m_plugin_parsers;
	//
	//
	// The event sources available in the inspector
	std::vector<std::string> m_event_sources;
	//
	// An instance of scap_evt to be used during the next call to sinsp::next().
	// If non-null, sinsp::next will use this pointer instead of invoking scap_next().
	// After using this event, sinsp::next() will set this back to nullptr.
	// This is used internally during the state initialization phase.
	scap_evt* m_replay_scap_evt;
	//
	// This is related to m_replay_scap_evt, and is used to store the additional cpuid
	// information of the replayed scap event.
	uint16_t m_replay_scap_cpuid;
	uint32_t m_replay_scap_flags;

	sinsp_observer* m_observer{nullptr};

	bool m_inited;
	static std::atomic<int> instance_count;
};

/*@}*/
