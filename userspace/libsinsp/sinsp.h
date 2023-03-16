/*
Copyright (C) 2022 The Falco Authors.

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

#include "capture_stats_source.h"

#ifdef _WIN32
#pragma warning(disable: 4251 4200 4221 4190)
#else
#include "tbb/concurrent_queue.h"
#endif

#include "sinsp_inet.h"
#include "sinsp_public.h"
#include "sinsp_exception.h"

#include <string>
#include <map>
#include <queue>
#include <vector>
#include <unordered_set>
#include <list>
#include <memory>

using namespace std;

#include <scap.h>
#include "settings.h"
#include "logger.h"
#include "event.h"
#include "filter.h"
#include "dumper.h"
#include "stats.h"
#include "ifinfo.h"
#include "container.h"
#include "user.h"
#include "utils.h"

#ifndef VISIBILITY_PRIVATE
// Some code defines VISIBILITY_PRIVATE to nothing to get private access to sinsp
#define VISIBILITY_PRIVATE private:
#define VISIBILITY_PROTECTED protected:
#else
#define VISIBILITY_PROTECTED
#endif

#define ONE_SECOND_IN_NS 1000000000LL

#ifdef _WIN32
#define NOCURSESUI
#endif

#include "tuples.h"
#include "fdinfo.h"
#include "threadinfo.h"
#include "ifinfo.h"
#include "eventformatter.h"
#include "sinsp_pd_callback_type.h"

#include "include/sinsp_external_processor.h"
#include "plugin.h"
#include "gvisor_config.h"
class sinsp_partial_transaction;
class sinsp_parser;
class sinsp_analyzer;
class sinsp_filter;
class cycle_writer;
class sinsp_protodecoder;
#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
class k8s;
#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
class sinsp_partial_tracer;
class mesos;
class sinsp_plugin;
class sinsp_plugin_manager;

#if defined(HAS_CAPTURE) && !defined(_WIN32)
class sinsp_ssl;
class sinsp_bearer_token;
template <class T> class socket_data_handler;
template <class T> class socket_collector;
class k8s_handler;
class k8s_api_handler;
#endif // HAS_CAPTURE

std::vector<std::string> sinsp_split(const std::string &s, char delim);

/*!
  \brief Information about a group of filter/formatting fields.
*/
class filter_check_info
{
public:
	enum flags
	{
		FL_NONE =   0,
		FL_WORKS_ON_THREAD_TABLE = (1 << 0),	///< This filter check class supports filtering incomplete events that contain only valid thread info and FD info.
		FL_HIDDEN = (1 << 1),	///< This filter check class won't be shown by fields/filter listings.
	};

	filter_check_info()
	{
		m_flags = 0;
	}

	string m_name; ///< Field class name.
	string m_shortdesc; ///< short (< 10 words) description of this filtercheck. Can be blank.
	string m_desc; ///< Field class description.
	int32_t m_nfields; ///< Number of fields in this field group.
	const filtercheck_field_info* m_fields; ///< Array containing m_nfields field descriptions.
	uint32_t m_flags;
};

/*!
  \brief Parameters to configure the download behavior when connected to an
  orchestrator like Kubernetes or mesos.
*/
class metadata_download_params
{
public:
	uint32_t m_data_max_b = K8S_DATA_MAX_B;
	uint32_t m_data_chunk_wait_us = K8S_DATA_CHUNK_WAIT_US;
	uint32_t m_data_watch_freq_sec = METADATA_DATA_WATCH_FREQ_SEC;
};

/*!
  \brief The user agent string to use for any libsinsp connection, can be changed at compile time
*/

#if !defined(LIBSINSP_USER_AGENT)
#define LIBSINSP_USER_AGENT "falcosecurity-libs"
#endif // LIBSINSP_USER_AGENT

/*!
  \brief The default way an event is converted to string by the library
*/
#define DEFAULT_OUTPUT_STR "*%evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args"

//
// Internal stuff for meta event management
//
typedef void (*meta_event_callback)(sinsp*, void* data);
class sinsp_proc_metainfo
{
public:
	sinsp_evt m_pievt;
	scap_evt* m_piscapevt;
	uint64_t* m_piscapevt_vals;
	uint64_t m_n_procinfo_evts;
	int64_t m_cur_procinfo_evt;
	ppm_proclist_info* m_pli;
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
class SINSP_PUBLIC sinsp : public capture_stats_source
{
public:
	typedef std::shared_ptr<sinsp> ptr;
	typedef std::set<std::string> k8s_ext_list_t;
	typedef std::shared_ptr<k8s_ext_list_t> k8s_ext_list_ptr_t;

	sinsp(bool static_container = false,
		  const std::string &static_id = "",
		  const std::string &static_name = "",
		  const std::string &static_image = "");

	~sinsp() override;


	/* Wrappers to open a specific engine. */
	virtual void open_kmod(unsigned long driver_buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM, const std::unordered_set<uint32_t> &ppm_sc_of_interest = {}, const std::unordered_set<uint32_t> &tp_of_interest = {});
	virtual void open_bpf(const std::string &bpf_path, unsigned long driver_buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM, const std::unordered_set<uint32_t> &ppm_sc_of_interest = {}, const std::unordered_set<uint32_t> &tp_of_interest = {});
	virtual void open_udig();
	virtual void open_nodriver();
	virtual void open_savefile(const std::string &filename, int fd = 0);
	virtual void open_plugin(const std::string &plugin_name, const std::string &plugin_open_params);
	virtual void open_gvisor(const std::string &config_path, const std::string &root_path);
	/*[EXPERIMENTAL] This API could change between releases, we are trying to find the right configuration to deploy the modern bpf probe:
	 * `cpus_for_each_buffer` and `online_only` are the 2 experimental params. The first one allows associating more than one CPU to a single ring buffer.
	 * The last one allows allocating ring buffers only for online CPUs and not for all system-available CPUs.
	 */
	virtual void open_modern_bpf(unsigned long driver_buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM, uint16_t cpus_for_each_buffer = DEFAULT_CPU_FOR_EACH_BUFFER, bool online_only = true, const std::unordered_set<uint32_t> &ppm_sc_of_interest = {}, const std::unordered_set<uint32_t> &tp_of_interest = {});
	virtual void open_test_input(scap_test_input_data *data);

	scap_open_args factory_open_args(const char* engine_name, scap_mode_t scap_mode);

	std::string generate_gvisor_config(std::string socket_path);


	/*!
	  \brief Ends a capture and release all resources.
	*/
	void close();

	/*!
	  \brief Get the next event from the open capture source

	  \param evt a \ref sinsp_evt pointer that will be initialized to point to
	  the next available event.

	  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain
	   valid data. SCAP_TIMEOUT in case the read timeout expired and no event is
	   available. SCAP_EOF when the end of an offline capture is reached.
	   On Failure, SCAP_FAILURE is returned and getlasterr() can be used to
	   obtain the cause of the error.

	  \note: the returned event can be considered valid only until the next
	   call to \ref)
	*/
	virtual int32_t next(OUT sinsp_evt **evt);

	/*!
	  \brief Get the maximum number of bytes currently in use by any CPU buffer
     */
	uint64_t max_buf_used();

	/*!
	  \brief Get the number of events that have been captured and processed
	   since the call to \ref open()

	  \return the number of captured events.
	*/
	uint64_t get_num_events();

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
	  \brief Determine if this inspector is going to load user tables on
	  startup.

	  \param import_users if true, no user tables will be created for
	  this capture. This also means that no user or group info will be
	  written to the trace file by the -w flag. The user/group tables are
	  necessary to use filter fields like user.name or group.name. However,
	  creating them can increase the startup time. Moreover, they contain
	  information that could be privacy sensitive.

	  \note default behavior is import_users=true.

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
	void set_filter(const string& filter);

	/*!
	  \brief Installs the given capture runtime filter object.

	  \param filter the runtime filter object
	*/
	void set_filter(sinsp_filter* filter);

	/*!
	  \brief Return the filter set for this capture.

	  \return the filter previously set with \ref set_filter(), or an empty
	   string if no filter has been set yet.
	*/
	const string get_filter();

	bool run_filters_on_evt(sinsp_evt *evt);

	/*!
	  \brief This method can be used to specify a function to collect the library
	   log messages.

	  \param cb the target function that will receive the log messages.
	*/
	void set_log_callback(sinsp_logger_callback cb);

	/*!
	  \brief Instruct sinsp to write its log messages to the given file.
	*/
	void set_log_file(string filename);

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
	 * \brief set whether the library will automatically purge the threadtable
	 *        at specific times. If not, client is responsible for thread lifetime
	 *        management. If invoked, then the purge interval and thread timeout change
	 *        defaults, but have no observable effect.
	 */
	void disable_automatic_threadtable_purging();

	/*!
	 * \brief sets the interval at which the thread purge code runs. This does
	 *        not run every event as it's mildly expensive if there are lots of threads
	 */
	void set_thread_purge_interval_s(uint32_t val);

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
	  \brief Start writing the captured events to file.

	  \param dump_filename the destination trace file.

	  \param compress true to save the trace file in a compressed format.

	  \note only the events that pass the capture filter set with \ref set_filter()
	   will be saved to disk.
	  \note this simplified dump interface allows only one dump per capture.
	   For more flexibility, refer to the \ref sinsp_dumper class, that can
	   also be combined with \ref sinsp_filter to filter what will go into
	   the file.

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	void autodump_start(const string& dump_filename, bool compress);

 	/*!
	  \brief Cycles the file pointer to a new capture file
	*/
	void autodump_next_file();

	/*!
	  \brief Stops an event dump that was started with \ref autodump_start().

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	void autodump_stop();

	/*!
	  \brief Populate the given vector with the full list of filter check fields
	   that this version of the library supports.
	*/
	static void get_filtercheck_fields_info(std::vector<const filter_check_info*>& list);

	/*!
	  \brief Returns a new instance of a filtercheck supporting fields for
	  a generic event source (e.g. evt.num, evt.time, evt.pluginname...)
	*/
	static sinsp_filter_check* new_generic_filtercheck();

	bool has_metrics();

	/*!
	  \brief Return information about the machine generating the events.

	  \note this call works with file captures as well, because the machine
	   info is stored in the trace files. In that case, the returned
	   machine info is the one of the machine where the capture happened.
	*/
	const scap_machine_info* get_machine_info();

	/*!
	  \brief Look up a thread given its tid and return its information,
	   and optionally go dig into proc if the thread is not in the thread table.

	  \param tid the ID of the thread. In case of multi-thread processes,
	   this corresponds to the PID.
	  \param query_os_if_not_found if true, the library will search for this
	   thread's information in proc, use the result to create a new thread
	   entry, and return the new entry.

	  \return the \ref sinsp_threadinfo object containing full thread information
	   and state.

	  \note if you are interested in a process' information, just give this
	  function with the PID of the process.

	  @throws a sinsp_exception containing the error string is thrown in case
	   of failure.
	*/
	threadinfo_map_t::ptr_t get_thread_ref(int64_t tid, bool query_os_if_not_found = false, bool lookup_only = true, bool main_thread = false);

	/*!
	  \brief Fill the given structure with statistics about the currently
	   open capture.

	  \note this call won't work on file captures.
	*/
	void get_capture_stats(scap_stats* stats) const override;

#ifdef GATHER_INTERNAL_STATS
	sinsp_stats get_stats();
#endif

	libsinsp::event_processor* m_external_event_processor;

	sinsp_threadinfo* build_threadinfo()
    {
        return m_external_event_processor ? m_external_event_processor->build_threadinfo(this)
                                          : new sinsp_threadinfo(this);
    }

	/*!
	  \brief registers external event processor.
	  After this, callbacks on libsinsp::event_processor will happen at
	  the appropriate times. This registration must happen before calling open.
	*/
	void register_external_event_processor(libsinsp::event_processor& processor)
	{
		m_external_event_processor = &processor;
	}

	libsinsp::event_processor* get_external_event_processor() const
	{
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
	string getlasterr()
	{
		return m_lasterr;
	}

	/*!
	  \brief Get the list of machine network interfaces.

	  \return Pointer to the interface list manager.
	*/
	sinsp_network_interfaces* get_ifaddr_list();

	/*!
	  \brief Set the format used to render event data
	   buffer arguments.
	*/
	void set_buffer_format(sinsp_evt::param_fmt format);

	/*!
	  \brief Get the format used to render event data
	   buffer arguments.
	*/
	sinsp_evt::param_fmt get_buffer_format();

	/*!
	  \brief Set event flags for which matching events should be dropped pre-filtering
	*/
	void set_drop_event_flags(ppm_event_flags flags);

	/*!
	  \brief Returns true if the current capture is offline
	*/
	inline bool is_capture()
	{
		return m_mode == SCAP_MODE_CAPTURE;
	}

	/*!
	  \brief Returns true if the current capture is live
	*/
	inline bool is_live()
	{
		return m_mode == SCAP_MODE_LIVE;
	}

	/*!
	  \brief Returns true if the kernel module is not loaded
	*/
	inline bool is_nodriver()
	{
		return m_mode == SCAP_MODE_NODRIVER;
	}

	/*!
	  \brief Returns true if the current capture has a plugin producing events
	*/
	inline bool is_plugin()
	{
		return m_mode == SCAP_MODE_PLUGIN;
	}

	/*!
	  \brief Returns the framework plugin api version as a string with static storage
	*/
	inline const char *get_plugin_api_version() const
	{
		return PLUGIN_API_VERSION_STR;
	}

	/*!
	  \brief Returns the API version supported by the driver
	*/
	inline uint64_t get_driver_api_version() const
	{
		return scap_get_driver_api_version(m_h);
	}

	/*!
	  \brief Returns the minimum API version required by the userspace library
	*/
	inline uint64_t get_scap_api_version() const
	{
		return SCAP_MINIMUM_DRIVER_API_VERSION;
	}

	/*!
	  \brief Returns the schema version supported by the driver
	*/
	inline uint64_t get_driver_schema_version() const
	{
		return scap_get_driver_schema_version(m_h);
	}

	/*!
	  \brief Returns the minimum schema version required by the userspace library
	*/
	inline uint64_t get_scap_schema_version() const
	{
		return SCAP_MINIMUM_DRIVER_SCHEMA_VERSION;
	}

	/*!
	  \brief Returns true if truncated environments should be loaded from /proc
	*/
	inline bool large_envs_enabled()
	{
		return is_live() && m_large_envs_enabled;
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

	/*!
	  \brief Set the runtime flag for resolving the timespan in a human
	   readable mode.

	  \param flag Can be 'h', 'a', 'r', 'd', 'D' as documented in the manual.
	*/
	inline void set_time_output_mode(char flag)
	{
		m_output_time_flag = flag;
	}

	/*!
	  \brief Sets the max length of event argument strings.

	  \param len Max length after which an event argument string is truncated.
	   0 means no limit. Use this to reduce verbosity when printing event info
	   on screen.
	*/
	void set_max_evt_output_len(uint32_t len);

	/*!
	  \brief Returns true if the debug mode is enabled.
	*/
	inline bool is_debug_enabled()
	{
		return m_isdebug_enabled;
	}

	/*!
	  \brief Set a flag indicating if the command line requested to show container information.

	  \param set true if the command line argument is set to show container information
	*/
	void set_print_container_data(bool print_container_data);


	/*!
	  \brief Returns true if the command line argument is set to show container information.
	*/
	inline bool is_print_container_data()
	{
		return m_print_container_data;
	}

	/*!
	  \brief Lets a filter plugin request a protocol decoder.

	  \param the name of the required decoder
	*/
	sinsp_protodecoder* require_protodecoder(std::string decoder_name);

	/*!
	  \brief Lets a filter plugin request a protocol decoder.

	  \param the name of the required decoder
	*/
	void protodecoder_register_reset(sinsp_protodecoder* dec);

	/*!
	  \brief If this is an offline capture, return the name of the file that is
	   being read, otherwise return an empty string.
	*/
	std::string get_input_filename()
	{
		return m_input_filename;
	}

	/*!
	  \brief When reading events from a trace file or a plugin, this function
	   returns the read progress as a number between 0 and 100.
	*/
	double get_read_progress();

	/*!
	  \brief When reading events from a trace file or a plugin, this function
	   returns the read progress as a number and as a string, giving the plugins
	   flexibility on the format.
	*/
	double get_read_progress_with_str(OUT string* progress_str);

	/*!
	  \brief Make the amount of data gathered for a syscall to be
	  determined by the number of parameters.
	*/
	virtual int /*SCAP_X*/ dynamic_snaplen(bool enable)
	{
		if(enable)
		{
			return scap_enable_dynamic_snaplen(m_h);
		}
		else
		{
			return scap_disable_dynamic_snaplen(m_h);
		}
	}

	/*!
	  \brief Set the parameters that control metadata fetching from orchestrators
	  like Kuberneted and mesos.
	*/
	void set_metadata_download_params(uint32_t data_max_b,
		uint32_t data_chunk_wait_us,
		uint32_t data_watch_freq_sec);


#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	void init_k8s_ssl(const std::string *ssl_cert);

	/*!
	  \brief Initialize the Kubernetes client.
	  \param api_server Kubernetes API server URI
	  \param ssl_cert use the provided file name to authenticate with the Kubernetes API server
	  \param node_name the node name is used as a filter when requesting metadata of pods 
	  to the API server; if empty, no filter is set
	*/
	void init_k8s_client(std::string* api_server, std::string* ssl_cert, std::string *node_name, bool verbose = false);
	void make_k8s_client();
	k8s* get_k8s_client() const { return m_k8s_client; }
	void validate_k8s_node_name();

	void init_mesos_client(std::string* api_server, bool verbose = false);
	mesos* get_mesos_client() const { return m_mesos_client; }
#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)

	//
	// Misc internal stuff
	//
	void stop_dropping_mode();
	void start_dropping_mode(uint32_t sampling_ratio);
	void on_new_entry_from_proc(void* context, scap_t* handle, int64_t tid, scap_threadinfo* tinfo,
		scap_fdinfo* fdinfo);
	void set_get_procs_cpu_from_driver(bool get_procs_cpu_from_driver)
	{
		m_get_procs_cpu_from_driver = get_procs_cpu_from_driver;
	}

	//
	// Used by filters to enable app event state tracking, which is disabled
	// by default for performance reasons
	//
	void request_tracer_state_tracking()
	{
		m_track_tracers_state = true;
	}

	//
	// Allocates private state in the thread info class.
	// Returns the ID to use when retrieving the memory area.
	// Will fail if called after the capture starts.
	//
	uint32_t reserve_thread_memory(uint32_t size);

	sinsp_parser* get_parser();

	/*=============================== PPM_SC set related (ppm_sc.cpp) ===============================*/

	/*!
		\brief Mark desired syscall as (un)interesting, enabling or disabling its collection.
		This method receives a `ppm_sc` code, not a syscall system code, the same ppm_code
		can match more than one system syscall. You can find the available
		`enum ppm_syscall_code` in `driver/ppm_events_public.h`.
		Please note that this method must be called when the inspector is already open to 
		modify at runtime the interesting syscall set.

		WARNING: playing with this API could break `libsinsp` state collection, this is only
		useful in advanced cases where the client needs to know what it is doing!
	*/
	void mark_ppm_sc_of_interest(uint32_t ppm_sc, bool enabled = true);

	/*!
		\brief Provide the minimum set of syscalls required by `libsinsp` state collection.
		If you call it without arguments it returns a new set with just these syscalls
		otherwise, it merges the minimum set of syscalls with the one you provided.

		WARNING: without using this method, we cannot guarantee that `libsinsp` state
		will always be up to date, or even work at all.
	*/
	std::unordered_set<uint32_t> enforce_sinsp_state_ppm_sc(std::unordered_set<uint32_t> ppm_sc_of_interest = {});

	/*!
	  \brief Enforce simple set of syscalls with all the security-valuable syscalls.
	  It has same effect of old `simple_consumer` mode.
	  Does enforce minimum sinsp state set.
	*/
	std::unordered_set<uint32_t> enforce_simple_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set = {});

	/*!
	  \brief Enforce passed set of syscalls with the ones
	  valuable for IO.
	  Does not enforce minimum sinsp state set.
	*/
	std::unordered_set<uint32_t> enforce_io_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set = {});

	/*!
	  \brief Enforce passed set of syscalls with the ones
	  valuable for networking.
	  Does not enforce minimum sinsp state set.
	*/
	std::unordered_set<uint32_t> enforce_net_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set = {});

	/*!
	  \brief Enforce passed set of syscalls with the ones
	  valuable for process state tracking.
	  Does not enforce minimum sinsp state set.
	*/
	std::unordered_set<uint32_t> enforce_proc_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set = {});

	/*!
	  \brief Enforce passed set of syscalls with the ones
	  valuable for system state tracking (signals, memory...)
	  Does not enforce minimum sinsp state set.
	*/
	std::unordered_set<uint32_t> enforce_sys_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set = {});

	/*!
	  \brief Get all the available ppm_sc.
	  Does enforce minimum sinsp state set.
	*/
	std::unordered_set<uint32_t> get_all_ppm_sc();

	/*!
	  \brief Get the name of all the ppm_sc provided in the set.
	*/
	std::unordered_set<std::string> get_syscalls_names(const std::unordered_set<uint32_t>& ppm_sc_set);

	/*!
	  \brief Get the name of all the events provided in the set.
	*/
	std::unordered_set<std::string> get_events_names(const std::unordered_set<uint32_t>& events_set);

	/**
	 * @brief When you want to retrieve the events associated with a particular `ppm_sc` you have to
	 * pass a single-element set, with just the specific `ppm_sc`. On the other side, you want all the events
	 * associated with a set of `ppm_sc` you have to pass the entire set of `ppm_sc`.
	 * 
	 * @param ppm_sc_set set of `ppm_sc` from which you want to obtain information
	 * @return set of events associated with the provided `ppm_sc` set.
	 */
	std::unordered_set<uint32_t> get_event_set_from_ppm_sc_set(const std::unordered_set<uint32_t> &ppm_sc_of_interest);

	/*=============================== PPM_SC set related (ppm_sc.cpp) ===============================*/

	/*=============================== Tracepoint set related ===============================*/

	/*!
		\brief Mark desired tracepoint as (un)interesting, attaching or detaching it.
		This method receives a `tp` code. You can find the available
		`enum tp_values` in `driver/ppm_tp.h`.
		Please note that this method must be called when the inspector is already open to
		modify at runtime the interesting tracepoint set.

		WARNING: playing with this API could break `libsinsp` state collection, this is only
		useful in advanced cases where the client needs to know what it is doing!
	*/
	void mark_tp_of_interest(uint32_t tp, bool enabled = true);

	/*!
	  \brief Get all the available tracepoints.
	*/
	std::unordered_set<uint32_t> get_all_tp();

	/*!
	  \brief Get the name of all the ppm_sc provided in the set.
	*/
	std::unordered_set<std::string> get_tp_names(const std::unordered_set<uint32_t>& tp_set);

	/*!
		\brief Provide the minimum set of tracepoints required by `libsinsp` state collection.
		If you call it without arguments it returns a new set with just these tracepoints
		otherwise, it merges the minimum set of tracepoints with the one you provided.

		WARNING: without using this method, we cannot guarantee that `libsinsp` state
		will always be up to date, or even work at all.
	*/
	std::unordered_set<uint32_t> enforce_sinsp_state_tp(std::unordered_set<uint32_t> tp_of_interest = {});

	/*=============================== Tracepoint set related ===============================*/

	/*=============================== Engine related ===============================*/

	/**
	 * @brief Check if the current engine is the one passed as parameter.
	 * 
	 * @param engine_name engine that we want to check.
	 * @return true if the passed engine is the active one otherwise false.
	 */
	bool check_current_engine(const std::string& engine_name);

	/*=============================== Engine related ===============================*/

	/*=============================== Events related ===============================*/

	/**
	 * @brief If the event type has one of the following flags return true:
	 * - `EF_UNUSED`
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has at least one of these flags.
	 */
	static inline bool is_unused_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_flags flags = g_infotables.m_event_info[event_type].flags;
		return (flags & EF_UNUSED);
	}

	/**
	 * @brief If the event type has one of the following flags return true:
	 * - `EF_SKIPPARSERESET`
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has at least one of these flags.
	 */
	static inline bool is_skip_parse_reset_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_flags flags = g_infotables.m_event_info[event_type].flags;
		return (flags & EF_SKIPPARSERESET);
	}

	/**
	 * @brief Return true if the event has the `EF_OLD_VERSION` flag
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EF_OLD_VERSION` flag.
	 */
	static inline bool is_old_version_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_flags flags = g_infotables.m_event_info[event_type].flags;
		return (flags & EF_OLD_VERSION);
	}

	/**
	 * @brief Return true if the event belongs to the `EC_SYSCALL` category
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_SYSCALL` category.
	 */
	static inline bool is_syscall_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
		return (category & EC_SYSCALL);
	}

	/**
	 * @brief Return true if the event belongs to the `EC_TRACEPOINT` category
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_TRACEPOINT` category.
	 */
	static inline bool is_tracepoint_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
		return (category & EC_TRACEPOINT);
	}

	/**
	 * @brief Return true if the event belongs to the `EC_METAEVENT` category
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_METAEVENT` category.
	 */
	static inline bool is_metaevent(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
		return (category & EC_METAEVENT);
	}

	/**
	 * @brief Return true if the event belongs to the `EC_UNKNOWN` category
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_UNKNOWN` category.
	 */
	static inline bool is_unknown_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
		/* Please note this is not an `&` but an `==` if one event has 
		 * the `EC_UNKNOWN` category, it must have only this category!
		 */
		return (category == EC_UNKNOWN);
	}

	/**
	 * @brief Return true if the event belongs to the `EC_PLUGIN` category
	 * 
	 * @param event_type type of event we want to check (must be less than `PPM_EVENT_MAX`)
	 * @return true if the event type has the `EC_PLUGIN` category.
	 */
	static inline bool is_plugin_event(uint16_t event_type)
	{
		ASSERT(event_type < PPM_EVENT_MAX);
		enum ppm_event_category category = g_infotables.m_event_info[event_type].category;
		return (category & EC_PLUGIN);
	}

	/*=============================== Events related ===============================*/

	bool setup_cycle_writer(std::string base_file_name, int rollover_mb, int duration_seconds, int file_limit, unsigned long event_limit, bool compress);
	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);
	void add_meta_event(sinsp_evt *metaevt);
	void add_meta_event_callback(meta_event_callback cback, void* data);
	void remove_meta_event_callback();
	void filter_proc_table_when_saving(bool filter);
	void enable_tracers_capture();
	uint64_t get_bytes_read()
	{
		return scap_ftell(m_h);
	}
	void refresh_ifaddr_list();
	void refresh_proc_list() {
		scap_refresh_proc_table(m_h);
	}

	std::vector<long> get_n_tracepoint_hit();

	static unsigned num_possible_cpus();

#if defined(HAS_CAPTURE) && !defined(_WIN32)
	static std::shared_ptr<std::string> lookup_cgroup_dir(const std::string& subsys);
#endif

	// Add comm to the list of comms for which the inspector
	// should not return events.
	bool suppress_events_comm(const std::string &comm);

	bool check_suppressed(int64_t tid);

	void set_docker_socket_path(std::string socket_path);
	void set_query_docker_image_info(bool query_image_info);

	void set_cri_extra_queries(bool extra_queries);

	void set_fullcapture_port_range(uint16_t range_start, uint16_t range_end);

	void set_statsd_port(uint16_t port);

	/*!
	  \brief Reset list of crio socket paths currently stored, and set path as the only path.
	*/
	void set_cri_socket_path(const std::string& path);
	/*!
	  \brief Pushed a new path to the list of crio socket paths
	*/
	void add_cri_socket_path(const std::string &path);
	void set_cri_timeout(int64_t timeout_ms);
	void set_cri_async(bool async);

	// TODO DEPRECATED: drop this method after a release or two
	void set_cri_delay(uint64_t delay_ms);

	void set_container_labels_max_len(uint32_t max_label_len);

	// Create and register a plugin from a shared library pointed
	// to by filepath, and add it to the inspector.
	// The created sinsp_plugin is returned.
	std::shared_ptr<sinsp_plugin> register_plugin(const std::string& filepath);
	const sinsp_plugin_manager* get_plugin_manager();

	uint64_t get_lastevent_ts() const { return m_lastevent_ts; }

	const std::string& get_host_root() const { return m_host_root; }
	void set_host_root(const std::string& s) { m_host_root = s; }

VISIBILITY_PROTECTED
	bool add_thread(const sinsp_threadinfo *ptinfo);
	void set_mode(scap_mode_t value)
	{
		m_mode = value;
	}

VISIBILITY_PRIVATE

// Doxygen doesn't understand VISIBILITY_PRIVATE
#ifdef _DOXYGEN
private:
#endif

	void set_input_plugin(const string& name, const string& params);
	void open_common(scap_open_args* oargs);
	void init();
	void deinit_state();
	void consume_initialstate_events();
	bool is_initialstate_event(scap_evt* pevent);
	void import_thread_table();
	void import_ifaddr_list();
	void import_user_list();
	void add_protodecoders();
	void remove_thread(int64_t tid, bool force);

	void fill_ppm_sc_of_interest(scap_open_args *oargs, const std::unordered_set<uint32_t> &ppm_sc_of_interest);
	void fill_tp_of_interest(scap_open_args *oargs, const std::unordered_set<uint32_t> &tp_of_interest);

	//
	// Note: lookup_only should be used when the query for the thread is made
	//       not as a consequence of an event for that thread arriving, but
	//       just for lookup reason. In that case, m_lastaccess_ts is not updated
	//       and m_last_tinfo is not set.
	//
	inline threadinfo_map_t::ptr_t find_thread(int64_t tid, bool lookup_only)
	{
		return m_thread_manager->find_thread(tid, lookup_only);
	}

	// this is here for testing purposes only
	sinsp_threadinfo* find_thread_test(int64_t tid, bool lookup_only);
	bool remove_inactive_threads();

#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	void k8s_discover_ext();
	void collect_k8s();
	void update_k8s_state();
	void update_mesos_state();
	bool get_mesos_data();
#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)

	static int64_t get_file_size(const std::string& fname, char *error);
	static std::string get_error_desc(const std::string& msg = "");

	void restart_capture();

	void fseek(uint64_t filepos)
	{
		scap_fseek(m_h, filepos);
	}

	void add_suppressed_comms(scap_open_args *oargs);

	bool increased_snaplen_port_range_set() const
	{
		return m_increased_snaplen_port_range.range_start > 0 &&
		       m_increased_snaplen_port_range.range_end > 0;
	}

	double get_read_progress_file();
	void get_read_progress_plugin(OUT double* nres, string* sres);

	void get_procs_cpu_from_driver(uint64_t ts);

	scap_t* m_h;
	uint64_t m_nevts;
	int64_t m_filesize;
	scap_mode_t m_mode = SCAP_MODE_NONE;

	// If non-zero, reading from this fd and m_input_filename contains "fd
	// <m_input_fd>". Otherwise, reading from m_input_filename.
	int m_input_fd;
	std::string m_input_filename;
	bool m_is_windows;
	bool m_isdebug_enabled;
	bool m_isfatfile_enabled;
	bool m_isinternal_events_enabled;
	bool m_hostname_and_port_resolution_enabled;
	char m_output_time_flag;
	uint32_t m_max_evt_output_len;
	bool m_compress;
	sinsp_evt m_evt;
	std::string m_lasterr;
	int64_t m_tid_to_remove;
	int64_t m_tid_of_fd_to_remove;
	std::vector<int64_t>* m_fds_to_remove;
	uint64_t m_lastevent_ts;
	// the parsing engine
	sinsp_parser* m_parser;
	// the statistics analysis engine
	scap_dumper_t* m_dumper;
	bool m_is_dumping;
	bool m_filter_proc_table_when_saving;
	const scap_machine_info* m_machine_info;
	uint32_t m_num_cpus;
	sinsp_thread_privatestate_manager m_thread_privatestate_manager;
	bool m_is_tracers_capture_enabled;
	bool m_flush_memory_dump;
	bool m_large_envs_enabled;
	scap_test_input_data *m_test_input_data = nullptr;

	sinsp_network_interfaces* m_network_interfaces;

	std::string m_host_root;

public:
	sinsp_thread_manager* m_thread_manager;

	sinsp_container_manager m_container_manager;

	sinsp_usergroup_manager m_usergroup_manager;

	metadata_download_params m_metadata_download_params;

	//
	// Kubernetes
	//
#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	std::string* m_k8s_api_server;
	std::string* m_k8s_api_cert;
	std::string* m_k8s_node_name;
	bool m_k8s_node_name_validated = false;
#ifdef HAS_CAPTURE
	std::shared_ptr<sinsp_ssl> m_k8s_ssl;
	std::shared_ptr<sinsp_bearer_token> m_k8s_bt;
	unique_ptr<k8s_api_handler> m_k8s_api_handler;
	shared_ptr<socket_collector<socket_data_handler<k8s_handler>>> m_k8s_collector;
	bool m_k8s_api_detected = false;
	unique_ptr<k8s_api_handler> m_k8s_ext_handler;
	k8s_ext_list_ptr_t m_ext_list_ptr;
	k8s_ext_list_t m_k8s_allowed_ext = {
		// "daemonsets", // not enabled by default because not fully implemented (no state/cache, no filters) 
		"deployments",
		"replicasets"
	};
	bool m_k8s_ext_detect_done = false;
#endif // HAS_CAPTURE
	k8s* m_k8s_client;
	uint64_t m_k8s_last_watch_time_ns;
#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)

	//
	// Mesos/Marathon
	//
	std::string m_mesos_api_server;
	std::vector<std::string> m_marathon_api_server;
	mesos* m_mesos_client;
	uint64_t m_mesos_last_watch_time_ns;

	//
	// True when ran with -v.
	// Used by mesos and k8s objects.
	//
	bool m_verbose_json = false;

	//
	// True if the command line argument is set to show container information
	// The default is false set within the constructor
	//
	bool m_print_container_data;

	uint64_t m_firstevent_ts;
	sinsp_filter* m_filter;
	std::string m_filterstring;
	//
	// Internal stats
	//
#ifdef GATHER_INTERNAL_STATS
	sinsp_stats m_stats;
#endif
#ifdef HAS_ANALYZER
	std::vector<uint64_t> m_tid_collisions;
#endif

	//
	// Saved snaplen
	//
	uint32_t m_snaplen;

	//
	// Saved increased capture range
	//
	struct
	{
		uint16_t range_start;
		uint16_t range_end;
	} m_increased_snaplen_port_range;

	int32_t m_statsd_port;

	//
	// Some thread table limits
	//
	uint32_t m_max_fdtable_size;
	bool m_automatic_threadtable_purging = true;
	uint64_t m_thread_timeout_ns = (uint64_t)1800 * ONE_SECOND_IN_NS;
	uint64_t m_inactive_thread_scan_time_ns = (uint64_t)1200 * ONE_SECOND_IN_NS;

	//
	// Container limits
	//
	uint64_t m_inactive_container_scan_time_ns;

	//
	// Users/groups limits
	//
	uint64_t m_deleted_users_groups_scan_time_ns;

	//
	// How to render the data buffers
	//
	sinsp_evt::param_fmt m_buffer_format;

	//
	// The cycle-writer for files
	//
	cycle_writer* m_cycle_writer;
	bool m_write_cycling;

#ifdef SIMULATE_DROP_MODE
	//
	// Some dropping infrastructure
	//
	bool m_isdropping;
#endif

	//
	// App events
	//
	bool m_track_tracers_state;
	list<sinsp_partial_tracer*> m_partial_tracers_list;
	simple_lifo_queue<sinsp_partial_tracer>* m_partial_tracers_pool;

	//
	// Protocol decoding state
	//
	std::vector<sinsp_protodecoder*> m_decoders_reset_list;

	//
	// meta event management for other sources like k8s, mesos.
	//
	sinsp_evt* m_metaevt;
	meta_event_callback m_meta_event_callback;
	void* m_meta_event_callback_data;

	// A queue of pending internal state events:
	// * 	container events. Written from async
	// 	callbacks that occur after looking up container
	// 	information, read from sinsp::next().
	// *	user added/removed events
	// * 	group added/removed events
#ifndef _WIN32
	tbb::concurrent_queue<shared_ptr<sinsp_evt>> m_pending_state_evts;
#endif

	// Holds an event dequeued from the above queue
	std::shared_ptr<sinsp_evt> m_state_evt;

	//
	// End of second housekeeping
	//
	bool m_get_procs_cpu_from_driver;
	uint64_t m_next_flush_time_ns;
	uint64_t m_last_procrequest_tod;
	sinsp_proc_metainfo m_meinfo;
	uint64_t m_next_stats_print_time_ns;

	static unsigned int m_num_possible_cpus;
#if defined(HAS_CAPTURE)
	int64_t m_self_pid;
#endif

	//
	// /proc scan parameters
	//
	uint64_t m_proc_scan_timeout_ms;
	uint64_t m_proc_scan_log_interval_ms;

	// Any thread with a comm in this set will not have its events
	// returned in sinsp::next()
	std::set<std::string> m_suppressed_comms;
	//
	// Internal manager for plugins
	//
	sinsp_plugin_manager* m_plugin_manager;
	//
	// The ID of the plugin to use as event input, or zero
	// if no source plugin should be used as source
	//
	std::shared_ptr<sinsp_plugin_cap_sourcing> m_input_plugin;
	//
	// String with the parameters for the plugin to be used as input.
	// These parameters will be passed to the open function of the plugin.
	//
	string m_input_plugin_open_params;
	//
	// An instance of scap_evt to be used during the next call to sinsp::next().
	// If non-null, sinsp::next will use this pointer instead of invoking scap_next().
	// After using this event, sinsp::next() will set this back to NULL.
	// This is used internally during the state initialization phase.
	scap_evt *m_replay_scap_evt;
	//
	// This is related to m_replay_scap_evt, and is used to store the additional cpuid
	// information of the replayed scap event.
	uint16_t m_replay_scap_cpuid;

	bool m_inited;
	static std::atomic<int> instance_count;

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_analyzer_parsers;
	friend class sinsp_evt;
	friend class sinsp_threadinfo;
	friend class sinsp_fdtable;
	friend class sinsp_thread_manager;
	friend class sinsp_container_manager;
	friend class sinsp_dumper;
	friend class sinsp_analyzer_fd_listener;
	friend class sinsp_chisel;
	friend class sinsp_tracerparser;
	friend class sinsp_filter_check_event;
	friend class sinsp_protodecoder;
	friend class lua_cbacks;
	friend class sinsp_filter_check_container;
	friend class sinsp_worker;
	friend class curses_textbox;
	friend class sinsp_filter_check_fd;
	friend class sinsp_filter_check_k8s;
	friend class sinsp_filter_check_mesos;
	friend class sinsp_filter_check_evtin;
	friend class sinsp_baseliner;
	friend class sinsp_memory_dumper;
	friend class sinsp_network_interfaces;
	friend class test_helper;
	friend class sinsp_usergroup_manager;

	template<class TKey,class THash,class TCompare> friend class sinsp_connection_manager;

#ifdef SYSDIG_TEST
protected:
	void inject_machine_info(const scap_machine_info *value)
	{
		m_machine_info = value;
	}
	void inject_network_interfaces(sinsp_network_interfaces *value)
	{
		m_network_interfaces = value;
	}
#endif // SYSDIG_TEST
};

/*@}*/
