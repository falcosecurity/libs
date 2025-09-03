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

#include <optional>
#include <unordered_map>
#include <string_view>
#include <memory>

#include <json/json.h>

#include <libsinsp/sinsp_inet.h>
#include <libsinsp/sinsp_public.h>
#include <libsinsp/sinsp_event_source.h>
#include <libscap/scap.h>
#include <libsinsp/settings.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/fdinfo.h>
#include <libsinsp/utils.h>

class sinsp;
class sinsp_threadinfo;
class sinsp_evt;

///////////////////////////////////////////////////////////////////////////////
// Event arguments
///////////////////////////////////////////////////////////////////////////////

#define MAX_EVENTINFO_SIZE 1024

/** @defgroup event Event manipulation
 * Classes to manipulate events, extract their content and convert them into strings.
 *  @{
 */

/*!
  \brief Wrapper that exports the libscap event tables.
*/
class SINSP_PUBLIC sinsp_evttables {
public:
	struct ppm_event_info
	        m_event_info[MAX_EVENTINFO_SIZE];  ///< List of events supported by the capture and
	                                           ///< analysis subsystems. Each entry fully documents
	                                           ///< an event and its parameters.
	size_t m_event_size;                       ///< Number of events in the event table.
};

template<class T>
inline T get_event_param_as(const class sinsp_evt_param& param);

/*!
  \brief Event parameter wrapper.
  This class describes an event parameter coming from the driver.
*/
class SINSP_PUBLIC sinsp_evt_param {
	const char* m_data;  ///< Pointer to the event parameter data.
	uint32_t m_len;      ///< Length of the parameter pointed by m_data_bufm_data.

public:
	const char* data() const { return m_data; }

	uint32_t len() const { return m_len; }

	/*!
	 * @return true if the length is equal to zero.
	 */
	bool empty() const { return len() == 0; }

	/*!
	 *  @return a boolean indicating if, for this specific parameter "null" configuration (data and
	 *  len configuration), the legacy null encoding ('<NA>') was used.
	 *
	 * Some specific types of parameter used a legacy encoding in specific scenarios. Specifically,
	 * in the past, the parameters having the following types could be `<NA>` or `(NULL)` or empty:
	 *
	 *    - PT_CHARBUF
	 *    - PT_FSRELPATH
	 *    - PT_FSPATH
	 *
	 * Now they can be only empty (data: nullptr, len: 0)!
	 *
	 * The problem is that userspace is not able to manage `NULL` pointers... but it manages `<NA>`,
	 * so we convert all these cases to `<NA>` when they are empty!
	 *
	 * If we read scap-files we could face `(NULL)` params, so also inthis case we convert them to
	 *`<NA>`.
	 *
	 * To be honest there could be other corner cases, but right now we don't have to manage it:
	 *
	 *    - PT_SOCKADDR
	 *    - PT_SOCKTUPLE
	 *    - PT_FDLIST
	 *
	 * Could be empty, so we will have:
	 * 	data = "pointer to the next param";
	 *	len = 0;
	 *
	 * However, as we said in the previous case, the ideal outcome would be (data: nullptr, len: 0).
	 *
	 * The difference with the previous case is that the userspace can manage these params when they
	 * have `len == 0`, so we don't have to use the `<NA>` workaround! We could also introduce the
	 *`NULL` and so put in place the ideal solution for this parameter, but before doing this we
	 * need to be sure that the userspace never tries to deference the pointer otherwise it will
	 * trigger a segmentation fault at run-time. So as a first step we would keep them as they are.
	 */
	bool used_legacy_null_encoding() const {
		switch(get_info()->type) {
		case PT_CHARBUF:
		case PT_FSRELPATH:
		case PT_FSPATH: {
			if(m_len == 0 || (m_len == 7 && strncmp(m_data, "(NULL)", 7) == 0)) {
				return true;
			}
			return false;
		}
		default:
			return false;
		}
	}

	/*!
	 * \brief A simple helper returning the untouched parameter data and len or a null-encoded
	 * version of them depending on their values.
	 */
	std::pair<const char*, uint32_t> data_and_len_with_legacy_null_encoding() const {
		if(!used_legacy_null_encoding()) {
			return std::make_pair(m_data, m_len);
		}
		return {"<NA>", 5};
	}

	const sinsp_evt* m_evt;  ///< Pointer to the event that contains this param
	uint32_t m_idx;          ///< Index of the parameter within the event

	sinsp_evt_param(const sinsp_evt* evt, const uint32_t idx, const char* data, const uint32_t len):
	        m_data(data),
	        m_len(len),
	        m_evt(evt),
	        m_idx(idx) {}

	/*!
	  \brief Interpret the parameter as a specific type, like:
	    - Fixed size values (uint32_t, int8_t ..., e.g. param->as<uint32_t>())
	    - String-like types (NUL-terminated strings) with either:
	      - std::string_view (e.g. param->as<std::string_view>()) to access the original string
	  bytes or a NULL string
	      - std::string (e.g. param->as<std::string>()) to obtain a copy of the string or an empty
	  string if the parameter was NULL
	    - NUL-separated arrays of strings (e.g. "first\0second\0third\0") with
	  std::vector<std::string>
	*/
	template<class T>
	inline T as() const {
		return get_event_param_as<T>(*this);
	}

	const struct ppm_param_info* get_info() const;

	// Throws a sinsp_exception detailing why the requested_len is incorrect.
	// This is only meant to be called by get_event_param_as. This way, this function will not be
	// inlined while get_event_param_as will be inlined.
	[[gnu::cold]]
	void throw_invalid_len_error(size_t requested_len) const;
};

/*!
  \brief Get the value of a parameter, interpreted with the type specified in the template argument.
  \param param The parameter.
*/
template<class T>
inline T get_event_param_as(const sinsp_evt_param& param) {
	static_assert(std::is_fundamental_v<T>,
	              "event parameter cast (e.g. evt->get_param(N)->as<T>()) unsupported for this "
	              "type. Implement it or see the available definitions in " __FILE__);

	T ret;

	const auto [param_data, param_len] = param.data_and_len_with_legacy_null_encoding();
	if(param_len != sizeof(T)) {
		// By moving this error string building operation to a separate function
		// the compiler is more likely to inline this entire function.
		param.throw_invalid_len_error(sizeof(T));
	}

	memcpy(&ret, param_data, sizeof(T));

	return ret;
}

template<>
inline std::string_view get_event_param_as<std::string_view>(const sinsp_evt_param& param) {
	const auto [param_data, param_len] = param.data_and_len_with_legacy_null_encoding();
	if(param_len == 0) {
		return {};
	}

	size_t string_len = strnlen(param_data, param_len);
	// We expect the parameter to be exactly one null-terminated string
	if(param_len != string_len + 1) {
		// By moving this error string building operation to a separate function
		// the compiler is more likely to inline this entire function.
		param.throw_invalid_len_error(string_len + 1);
	}

	return {param_data, string_len};
}

template<>
inline std::string get_event_param_as<std::string>(const sinsp_evt_param& param) {
	const auto [param_data, param_len] = param.data_and_len_with_legacy_null_encoding();
	if(param_len == 0) {
		return "";
	}

	size_t string_len = strnlen(param_data, param_len);
	// We expect the parameter to be exactly one null-terminated string
	if(param_len != string_len + 1) {
		// By moving this error string building operation to a separate function
		// the compiler is more likely to inline this entire function.
		param.throw_invalid_len_error(string_len + 1);
	}

	return std::string(param_data);
}

template<>
inline std::vector<std::string> get_event_param_as<std::vector<std::string>>(
        const sinsp_evt_param& param) {
	// vector string parameters coming from the driver may be NUL-terminated or not. Either way,
	// remove the NUL terminator
	const auto [param_data, param_len] = param.data_and_len_with_legacy_null_encoding();
	uint32_t len = param_len;
	if(len > 0 && param_data[param_len - 1] == '\0') {
		len--;
	}

	return sinsp_split({param_data, static_cast<std::string_view::size_type>(len)}, '\0');
}

template<>
inline std::vector<uint8_t> get_event_param_as<std::vector<uint8_t>>(const sinsp_evt_param& param) {
	const auto [param_data, param_len] = param.data_and_len_with_legacy_null_encoding();

	// copy content of the event parameter to a new vector
	std::vector<uint8_t> res;
	for(size_t i = 0; i < param_len; ++i) {
		res.push_back(uint8_t(param_data[i]));
	}

	return res;
}

/*!
  \brief Event class.
  This class is returned by \ref sinsp::next() and encapsulates the state
  related to a captured event, and includes a bunch of members to manipulate
  events and their parameters, including parsing, formatting and extracting
  state like the event process or FD.
*/
class SINSP_PUBLIC sinsp_evt {
public:
	/*!
	  \brief How to render an event parameter to string.
	*/
	enum param_fmt {
		PF_NORMAL = (1 << 0),    ///< Normal screen output
		PF_JSON = (1 << 1),      ///< Json formatting with data in normal screen format
		PF_SIMPLE = (1 << 2),    ///< Reduced output, e.g. not type character for FDs
		PF_HEX = (1 << 3),       ///< Hexadecimal output
		PF_HEXASCII = (1 << 4),  ///< Hexadecimal + ASCII output
		PF_EOLS = (1 << 5),      ///< Normal + end of lines
		PF_EOLS_COMPACT =
		        (1 << 6),        ///< Normal + end of lines but with no force EOL at the beginning
		PF_BASE64 = (1 << 7),    ///< Base64 output
		PF_JSONEOLS = (1 << 8),  ///< Json formatting with data in hexadecimal format
		PF_JSONHEX = (1 << 9),   ///< Json formatting with data in hexadecimal format
		PF_JSONHEXASCII = (1 << 10),  ///< Json formatting with data in hexadecimal + ASCII format
		PF_JSONBASE64 = (1 << 11),    ///< Json formatting with data in base64 format
	};

	/*!
	  \brief Event subcategory specialization based on the fd type.
	*/
	enum subcategory {
		SC_UNKNOWN = 0,
		SC_NONE = 1,
		SC_OTHER = 2,
		SC_FILE = 3,
		SC_NET = 4,
		SC_IPC = 5,
	};

	enum fd_number_type { INVALID_FD_NUM = -100000 };

	/*!
	  \brief Information regarding an event category, enriched with fd state.
	*/
	struct category {
		ppm_event_category m_category;  ///< Event category from the driver
		subcategory m_subcategory;      ///< Domain for IO and wait events
	};

	enum flags {
		SINSP_EF_NONE = 0,
		SINSP_EF_PARAMS_LOADED = 1,
		// SINSP_EF_IS_TRACER = (1 << 1), // note: deprecated
	};

	sinsp_evt();
	sinsp_evt(sinsp* inspector);
	virtual ~sinsp_evt();

	/*!
	  \brief Set the inspector.
	*/
	inline void set_inspector(sinsp* value) { m_inspector = value; }

	inline sinsp* get_inspector() { return m_inspector; }

	inline const sinsp* get_inspector() const { return m_inspector; }

	/*!
	  \brief Get the incremental number of this event.
	*/
	inline uint64_t get_num() const { return m_evtnum; }

	/*!
	  \brief Set the number of this event.
	*/
	inline void set_num(uint64_t evtnum) { m_evtnum = evtnum; }

	/*!
	  \brief Get the number of the CPU where this event was captured.
	*/
	inline uint16_t get_cpuid() const { return m_cpuid; }

	inline void set_cpuid(uint16_t v) { m_cpuid = v; }

	/*!
	  \brief Get the event type.

	  \note For a list of event types, refer to \ref etypes.
	*/
	virtual inline uint16_t get_type() const { return m_pevt->type; }

	/*!
	  \brief Get the event source index, as in the positional order of
	  used by the event's inspector event sources.
	  Returns sinsp_no_event_source_idx if the event source is unknown.
	*/
	inline size_t get_source_idx() const { return m_source_idx; }

	inline void set_source_idx(size_t v) { m_source_idx = v; }

	/*!
	  \brief Get the event source name, as in the event's inspector
	  event sources. Returns sinsp_no_event_source_name if
	  the event source is unknown.
	*/
	inline const char* get_source_name() const { return m_source_name; }

	inline void set_source_name(const char* v) { m_source_name = v; }

	/*!
	  \brief Get the event info
	*/
	inline const ppm_event_info* get_info() const { return m_info; }

	inline void set_info(const ppm_event_info* v) { m_info = v; }

	/*!
	  \brief Get the event's flags.
	*/
	inline ppm_event_flags get_info_flags() const { return m_info->flags; }

	/*!
	  \brief Return the event direction: in or out.
	*/
	event_direction get_direction() const;

	/*!
	  \brief Get the event timestamp.

	  \return The event timestamp, in nanoseconds from epoch
	*/
	virtual inline uint64_t get_ts() const { return m_pevt->ts; }

	/*!
	  \brief Return the event name string, e.g. 'open' or 'socket'.
	*/
	const char* get_name() const;

	/*!
	  \brief Return the event category.
	*/
	/// TODO: in the next future we need to rename this into `get_syscall_category_from_event`
	inline ppm_event_category get_category() const {
		/* Every event category is composed of 2 parts:
		 * 1. The highest bits represent the event category:
		 *   - `EC_SYSCALL`
		 *   - `EC_TRACEPOINT
		 *   - `EC_PLUGIN`
		 *   - `EC_METAEVENT`
		 *
		 * 2. The lowest bits represent the syscall category
		 * to which the specific event belongs.
		 *
		 * This function removes the highest bits, so we consider only the syscall category.
		 */
		const int bitmask = EC_SYSCALL - 1;
		return static_cast<ppm_event_category>(m_info->category & bitmask);
	}

	/*!
	  \brief Get the ID of the thread that generated the event.
	*/
	int64_t get_tid() const;

	/*!
	  \brief Return the information about the thread that generated the event.

	  \param query_os_if_not_found if this is a live a capture and this flag is
	   set to true, scan the /proc file system to find process information in
	   case the thread is not in the table.
	*/
	sinsp_threadinfo* get_thread_info(bool query_os_if_not_found = false);

	/*!
	  \brief Return the information about the FD on which this event operated.

	  \note For events that are not I/O related, get_fd_info() returns NULL.
	*/
	inline const sinsp_fdinfo* get_fd_info() const { return m_fdinfo; }

	inline sinsp_fdinfo* get_fd_info() { return m_fdinfo; }

	inline void set_fd_info(sinsp_fdinfo* v) { m_fdinfo = v; }

	inline bool fdinfo_name_changed() const { return m_fdinfo_name_changed; }

	inline void set_fdinfo_name_changed(bool changed) { m_fdinfo_name_changed = changed; }

	/*!
	  \brief Return the number of the FD associated with this event.

	  \note For events that are not I/O related, get_fd_num() returns sinsp_evt::INVALID_FD_NUM.
	*/
	int64_t get_fd_num() const;

	/*!
	  \brief Return the number of parameters that this event has.
	*/
	uint32_t get_num_params();

	/*!
	  \brief Get the name of one of the event parameters, e.g. 'fd' or 'addr'.

	  \param id The parameter number.
	*/
	const char* get_param_name(uint32_t id);

	/*!
	  \brief Get the metadata that describes one of this event's parameters.

	  \param id The parameter number.

	  \note Refer to the g_event_info structure in driver/event_table.c for
	   a list of event descriptions.
	*/
	const struct ppm_param_info* get_param_info(uint32_t id);

	/*!
	  \brief Get a parameter in raw format by position.

	  \param id The parameter number.
	*/
	const sinsp_evt_param* get_param(uint32_t id);

	/*!
	  \brief Get a parameter in raw format by name.

	  \param name The parameter name.
	*/
	const sinsp_evt_param* get_param_by_name(const char* name);

	/*!
	  \brief Get a parameter as a C++ string.

	  \param name The parameter name.
	  \param resolved If true, the library will try to resolve the parameter
	   before returning it. For example, and FD number will be converted into
	   the correspondent file, TCP tuple, etc.
	*/
	std::string get_param_value_str(std::string_view name, bool resolved = true);

	/*!
	  \brief Return the event's category, based on the event type and the FD on
	   which the event operates.

	  \param cat [out] the category for the event
	*/
	void get_category(sinsp_evt::category* cat) const;

	/*!
	  \brief Return true if the event has been rejected by the filtering system.
	*/
	bool is_filtered_out() const;

	/*!
	  \param should_drop [out] flag indicating if the event should be dropped
	*/
	scap_dump_flags get_dump_flags(bool* should_drop) const;

	/*!
	  \brief Returns true if this event represents a system call error,
	         false otherwise.
	*/
	bool is_syscall_error() const;

	/*!
	  \brief Returns true if this event represents a file open system
	         call error, false otherwise.

	      Precondition: is_syscall_error() must return true.
	*/
	bool is_file_open_error() const;

	/*!
	  \brief Returns true if this event represents a file-related system
	         call error (including open errors), false otherwise.

	  Precondition: is_syscall_error() must return true.
	*/
	bool is_file_error() const;

	/*!
	  \brief Returns true if this event represents a network-related system
	         call error, false otherwise.

	  Precondition: is_syscall_error() must return true.
	*/
	bool is_network_error() const;

	uint64_t get_lastevent_ts() const;

	void set_iosize(uint32_t size);
	uint32_t get_iosize() const;

	std::string get_base_dir(uint32_t id, sinsp_threadinfo*);

	/*!
	  \param resolved_str [out] the string representation of the parameter
	*/
	const char* get_param_as_str(uint32_t id, const char** resolved_str, param_fmt fmt = PF_NORMAL);

	/*!
	  \param resolved_str [out] the string representation of the parameter
	*/
	const char* get_param_value_str(std::string_view name,
	                                const char** resolved_str,
	                                param_fmt fmt = PF_NORMAL);

	inline void init() {
		m_flags = EF_NONE;
		m_info = &(m_event_info_table[m_pevt->type]);
		m_tinfo_ref.reset();
		m_tinfo = NULL;
		m_fdinfo_ref.reset();
		m_fdinfo = NULL;
		m_fdinfo_name_changed = false;
		m_iosize = 0;
		m_source_idx = sinsp_no_event_source_idx;
		m_source_name = sinsp_no_event_source_name;
	}
	inline void init_from_raw(uint8_t* evdata, uint16_t cpuid) {
		m_flags = EF_NONE;
		m_pevt = (scap_evt*)evdata;
		m_info = &(m_event_info_table[m_pevt->type]);
		m_tinfo_ref.reset();
		m_tinfo = NULL;
		m_fdinfo_ref.reset();
		m_fdinfo = NULL;
		m_fdinfo_name_changed = false;
		m_iosize = 0;
		m_cpuid = cpuid;
		m_source_idx = sinsp_no_event_source_idx;
		m_source_name = sinsp_no_event_source_name;
	}

	static std::unique_ptr<sinsp_evt> from_scap_evt(std::unique_ptr<uint8_t[]> scap_event) {
		auto ret = std::make_unique<sinsp_evt>();
		auto evdata = scap_event.release();
		ret->init_from_raw(evdata, 0);
		ret->m_pevt_storage = (char*)evdata;
		return ret;
	}

	inline void load_params() {
		struct scap_sized_buffer params[PPM_MAX_EVENT_PARAMS];

		m_params.clear();

		uint32_t nparams = scap_event_decode_params(m_pevt, params);

		for(uint32_t i = 0; i < nparams; i++) {
			m_params.emplace_back(this, i, static_cast<const char*>(params[i].buf), params[i].size);
		}
	}

	std::string get_param_value_str(uint32_t id, bool resolved);
	char* render_fd(int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt);
	int render_fd_json(Json::Value* ret,
	                   int64_t fd,
	                   const char** resolved_str,
	                   sinsp_evt::param_fmt fmt);
	inline uint32_t get_dump_flags() const { return m_dump_flags; }
	inline void set_dump_flags(uint32_t v) { m_dump_flags = v; }
	int32_t get_errorcode() const { return m_errorcode; }
	inline void set_errorcode(int32_t v) { m_errorcode = v; }

	// Save important values from the provided enter event. They
	// are accessible from get_enter_evt_param().
	void save_enter_event_params(sinsp_evt* enter_evt);
	std::optional<std::reference_wrapper<const std::string>> get_enter_evt_param(
	        const std::string& param) const;

	inline const scap_evt* get_scap_evt() const { return m_pevt; }

	inline scap_evt* get_scap_evt() { return m_pevt; }

	inline void set_scap_evt(scap_evt* v) { m_pevt = v; }

	inline const char* get_scap_evt_storage() const { return m_pevt_storage; }

	inline char* get_scap_evt_storage() { return m_pevt_storage; }

	inline void set_scap_evt_storage(char* v) { m_pevt_storage = v; }

	inline uint32_t get_flags() const { return m_flags; }

	inline void set_flags(uint32_t v) { m_flags = v; }

	inline int32_t get_rawbuf_str_len() const { return m_rawbuf_str_len; }

	inline void set_rawbuf_str_len(int32_t v) { m_rawbuf_str_len = v; }

	inline void set_filtered_out(bool v) { m_filtered_out = v; }

	inline std::shared_ptr<const sinsp_threadinfo> get_tinfo_ref() const { return m_tinfo_ref; }

	inline const std::shared_ptr<sinsp_threadinfo>& get_tinfo_ref() { return m_tinfo_ref; }

	inline void set_tinfo_ref(const std::shared_ptr<sinsp_threadinfo>& v) { m_tinfo_ref = v; }

	inline const sinsp_threadinfo* get_tinfo() const { return m_tinfo; }

	inline sinsp_threadinfo* get_tinfo() { return m_tinfo; }

	inline void set_tinfo(sinsp_threadinfo* v) { m_tinfo = v; }

	inline std::shared_ptr<const sinsp_fdinfo> get_fdinfo_ref() const { return m_fdinfo_ref; }

	inline const std::shared_ptr<sinsp_fdinfo>& get_fdinfo_ref() { return m_fdinfo_ref; }

	inline void set_fdinfo_ref(const std::shared_ptr<sinsp_fdinfo>& v) { m_fdinfo_ref = v; }

	inline const std::vector<char>& get_paramstr_storage() const { return m_paramstr_storage; }

	inline std::vector<char>& get_paramstr_storage() { return m_paramstr_storage; }

	inline const std::vector<sinsp_evt_param>& get_params() const { return m_params; }

	inline std::vector<sinsp_evt_param>& get_params() { return m_params; }

	inline char extract_typechar() {
		switch(PPME_MAKE_ENTER(get_type())) {
		case PPME_SYSCALL_OPENAT_E:
		case PPME_SYSCALL_OPENAT_2_E:
		case PPME_SYSCALL_OPENAT2_E:
		case PPME_SYSCALL_CREAT_E:
			return CHAR_FD_FILE;
		case PPME_SOCKET_SOCKET_E:
		case PPME_SOCKET_ACCEPT_E:
		case PPME_SOCKET_ACCEPT_5_E:
		case PPME_SOCKET_ACCEPT4_E:
		case PPME_SOCKET_ACCEPT4_5_E:
		case PPME_SOCKET_ACCEPT4_6_E:
			//
			// Note, this is not accurate, because it always
			// returns IPv4 even if this could be IPv6 or unix.
			// For the moment, I assume it's better than nothing, and doing
			// real event parsing here would be a pain.
			//
			return CHAR_FD_IPV4_SOCK;
		case PPME_SYSCALL_PIPE2_E:
			return CHAR_FD_FIFO;
		case PPME_SYSCALL_EVENTFD2_E:
			return CHAR_FD_EVENT;
		case PPME_SYSCALL_SIGNALFD_E:
		case PPME_SYSCALL_SIGNALFD4_E:
			return CHAR_FD_SIGNAL;
		case PPME_SYSCALL_TIMERFD_CREATE_E:
			return CHAR_FD_TIMERFD;
		default:
			return 'o';
		}
	}

	inline bool is_syscall_event() const { return get_info()->category & EC_SYSCALL; }

	inline bool has_return_value() {
		// This event does not have a return value
		if(get_type() == PPME_GENERIC_X) {
			return false;
		}

		// The event has a return value if:
		// * it is a syscall event.
		// * it is an exit event.
		// * it has at least one parameter. Some exit events are not instrumented, see
		// `PPME_SOCKET_GETSOCKNAME_X`
		if(is_syscall_event() && PPME_IS_EXIT(get_type()) && get_num_params() > 0) {
			return true;
		}

		return false;
	}

	inline int64_t get_syscall_return_value() {
		if(!has_return_value()) {
			throw sinsp_exception(
			        "Called get_syscall_return_value() on an event that does not have a return "
			        "value. "
			        "Event type: " +
			        std::to_string(get_type()));
		}

		// The return value is always the first parameter of the syscall event
		// It could have different names depending on the event type `res`,`fd`, etc.
		const sinsp_evt_param* p = get_param(0);
		if(p == NULL) {
			// We should always have the return value in the syscall
			ASSERT(false);
			return 0;
		}

		// the only return values should be on 32 or 64 bits
		switch(p->len()) {
		case sizeof(int32_t):
			return (int64_t)p->as<int32_t>();
		case sizeof(int64_t):
			return p->as<int64_t>();
		default:
			ASSERT(false);
			return 0;
		}
	}

	inline bool uses_fd() const { return get_info_flags() & EF_USES_FD; }

	inline bool creates_fd() const { return get_info_flags() & EF_CREATES_FD; }

private:
	sinsp* m_inspector;
	scap_evt* m_pevt;
	char* m_pevt_storage;  // In some cases an alternate buffer is used to hold m_pevt. This points
	                       // to that storage.
	uint16_t m_cpuid;
	uint64_t m_evtnum;
	uint32_t m_flags;
	uint32_t m_dump_flags;
	bool m_params_loaded;
	const struct ppm_event_info* m_info;
	std::vector<sinsp_evt_param> m_params;

	std::vector<char> m_paramstr_storage;
	std::vector<char> m_resolved_paramstr_storage;

	// reference to keep threadinfo alive. currently only used for synthetic container event thread
	// info it should either be null, or point to the same place as m_tinfo
	std::shared_ptr<sinsp_threadinfo> m_tinfo_ref;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;

	// If true, then the associated fdinfo changed names as a part
	// of parsing this event.
	bool m_fdinfo_name_changed;

	uint32_t m_iosize;
	int32_t m_errorcode;
	int32_t m_rawbuf_str_len;
	bool m_filtered_out;
	const struct ppm_event_info* m_event_info_table;

	std::shared_ptr<sinsp_fdinfo> m_fdinfo_ref;
	// For some exit events, the "path" argument from the
	// corresponding enter event is stored here.
	std::unordered_map<std::string, std::string> m_enter_path_param;

	size_t m_source_idx;
	const char* m_source_name;
};

uint32_t binary_buffer_to_string(char* dst,
                                 const char* src,
                                 uint32_t dstlen,
                                 uint32_t srclen,
                                 sinsp_evt::param_fmt fmt);

/*@}*/
