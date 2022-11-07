/*
Copyright (C) 2021 The Falco Authors.

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
#include <json/json.h>

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

#include "sinsp_inet.h"
#include "sinsp_public.h"
#include "scap.h"
#include "gen_filter.h"
#include "settings.h"

typedef class sinsp sinsp;
typedef class sinsp_threadinfo sinsp_threadinfo;


namespace test_helpers {
	class event_builder;
	class sinsp_mock;
}


///////////////////////////////////////////////////////////////////////////////
// Event arguments
///////////////////////////////////////////////////////////////////////////////
typedef enum filtercheck_field_flags
{
	EPF_NONE              = 0,
	EPF_FILTER_ONLY       = 1 << 0, ///< this field can only be used as a filter.
	EPF_PRINT_ONLY        = 1 << 1, ///< this field can only be printed.
	EPF_ARG_REQUIRED      = 1 << 2, ///< this field includes an argument, under the form 'property.argument'.
	EPF_TABLE_ONLY        = 1 << 3, ///< this field is designed to be used in a table and won't appear in the field listing.
	EPF_INFO              = 1 << 4, ///< this field contains summary information about the event.
	EPF_CONVERSATION      = 1 << 5, ///< this field can be used to identify conversations.
	EPF_IS_LIST           = 1 << 6, ///< this field is a list of values.
	EPF_ARG_ALLOWED       = 1 << 7, ///< this field optionally includes an argument.
	EPF_ARG_INDEX         = 1 << 8, ///< this field accepts numeric arguments.
	EPF_ARG_KEY           = 1 << 9, ///< this field accepts string arguments.
}filtercheck_field_flags;

/*!
  \brief Information about a filter/formatting field.
*/
typedef struct filtercheck_field_info
{
	ppm_param_type m_type; ///< Field type.
	filtercheck_field_flags m_flags;  ///< Field flags.
	ppm_print_format m_print_format;  ///< If this is a numeric field, this flag specifies if it should be rendered as octal, decimal or hex.
	char m_name[64];  ///< Field name.
	char m_display[64];  ///< Field display name (short description). May be empty.
	char m_description[1024];  ///< Field description.
}filtercheck_field_info;

/** @defgroup event Event manipulation
 * Classes to manipulate events, extract their content and convert them into strings.
 *  @{
 */

/*!
  \brief Wrapper that exports the libscap event tables.
*/
class SINSP_PUBLIC sinsp_evttables
{
public:
	const struct ppm_event_info* m_event_info; ///< List of events supported by the capture and analysis subsystems. Each entry fully documents an event and its parameters.
	const struct ppm_syscall_desc* m_syscall_info_table; ///< List of system calls that the capture subsystem recognizes, including the ones that are not decoded yet.
};

/*!
  \brief Event parameter wrapper.
  This class describes a raw event coming from the driver.
*/
class SINSP_PUBLIC sinsp_evt_param
{
public:
	char* m_val;	///< Pointer to the event parameter data.
	uint32_t m_len; ///< Length of the parameter pointed by m_val.
private:
	inline void init(char* valptr, uint32_t len)
	{
		m_val = valptr;
		m_len = len;
	}

	friend class sinsp_evt;
};

/*!
  \brief Event class.
  This class is returned by \ref sinsp::next() and encapsulates the state
  related to a captured event, and includes a bunch of members to manipulate
  events and their parameters, including parsing, formatting and extracting
  state like the event process or FD.
*/
class SINSP_PUBLIC sinsp_evt : public gen_event
{
public:
	/*!
	  \brief How to render an event parameter to string.
	*/
	enum param_fmt
	{
		PF_NORMAL =         (1 << 0),	///< Normal screen output
		PF_JSON =           (1 << 1),	///< Json formatting with data in normal screen format
		PF_SIMPLE =         (1 << 2),	///< Reduced output, e.g. not type character for FDs
		PF_HEX =            (1 << 3),	///< Hexadecimal output
		PF_HEXASCII =       (1 << 4),	///< Hexadecimal + ASCII output
		PF_EOLS =           (1 << 5),	///< Normal + end of lines
		PF_EOLS_COMPACT =   (1 << 6),	///< Normal + end of lines but with no force EOL at the beginning
		PF_BASE64 =         (1 << 7),	///< Base64 output
		PF_JSONEOLS =       (1 << 8),	///< Json formatting with data in hexadecimal format
		PF_JSONHEX =        (1 << 9),	///< Json formatting with data in hexadecimal format
		PF_JSONHEXASCII =   (1 << 10),	///< Json formatting with data in hexadecimal + ASCII format
		PF_JSONBASE64 =     (1 << 11),	///< Json formatting with data in base64 format
	};

	/*!
	  \brief Event subcategory specialization based on the fd type.
	*/
	enum subcategory
	{
		SC_UNKNOWN = 0,
		SC_NONE = 1,
		SC_OTHER = 2,
		SC_FILE = 3,
		SC_NET = 4,
		SC_IPC = 5,
	};

	enum fd_number_type
	{
		INVALID_FD_NUM = -100000
	};

	/*!
	  \brief Information regarding an event category, enriched with fd state.
	*/
	struct category
	{
		ppm_event_category m_category;	///< Event category from the driver
		subcategory m_subcategory;		///< Domain for IO and wait events
	};

	sinsp_evt();
	sinsp_evt(sinsp* inspector);
	~sinsp_evt();

	/*!
	  \brief Set the inspector.
	*/
	void inspector(sinsp *value)
	{
		m_inspector = value;
	}

	/*!
	  \brief Get the incremental number of this event.
	*/
	inline uint64_t get_num() const
	{
		return m_evtnum;
	}

	/*!
	  \brief Get the number of the CPU where this event was captured.
	*/
	inline int16_t get_cpuid() const
	{
		return m_cpuid;
	}

	/*!
	  \brief Get the event type.

	  \note For a list of event types, refer to \ref etypes.
	*/
	inline uint16_t get_type() const override
	{
		return m_pevt->type;
	}

	/*!
	  \brief Get the event's flags.
	*/
	inline ppm_event_flags get_info_flags() const
	{
		return m_info->flags;
	}

	/*!
	  \brief Get the event's category.
	  [DEPRECATED] use `get_category()` instead of this method.
	*/
	inline ppm_event_category get_info_category() const
	{
		return get_category();
	}

	/*!
	  \brief Return the event direction: in or out.
	*/
	event_direction get_direction() const;

	/*!
	  \brief Get the event timestamp.

	  \return The event timestamp, in nanoseconds from epoch
	*/
	inline uint64_t get_ts() const override
	{
		return m_pevt->ts;
	}

	/*!
	  \brief Return the event name string, e.g. 'open' or 'socket'.
	*/
	const char* get_name() const;

	/*!
	  \brief Return the event category.
	*/
	/// TODO: in the next future we need to rename this into `get_syscall_category_from_event`
	inline ppm_event_category get_category() const
	{
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
	int64_t get_tid();

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
	inline sinsp_fdinfo_t* get_fd_info()
	{
		return m_fdinfo;
	}

	inline bool fdinfo_name_changed() const
	{
		return m_fdinfo_name_changed;
	}

	inline void set_fdinfo_name_changed(bool changed)
	{
		m_fdinfo_name_changed = changed;
	}

	/*!
	  \brief Return the number of the FD associated with this event.

	  \note For events that are not I/O related, get_fd_num() returns sinsp_evt::INVALID_FD_NUM.
	*/
	int64_t get_fd_num();

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
	  \brief Get a parameter in raw format.

	  \param id The parameter number.
	*/
	sinsp_evt_param* get_param(uint32_t id);

	/*!
	  \brief Get a parameter in raw format.

	  \param name The parameter name.
	*/
	const sinsp_evt_param* get_param_value_raw(const char* name);

	/*!
	  \brief Get a parameter as a C++ string.

	  \param name The parameter name.
	  \param resolved If true, the library will try to resolve the parameter
	   before returning it. For example, and FD number will be converted into
	   the correspondent file, TCP tuple, etc.
	*/
	std::string get_param_value_str(const std::string& name, bool resolved = true);

	/*!
	  \brief Return the event's category, based on the event type and the FD on
	   which the event operates.
	*/
	void get_category(OUT sinsp_evt::category* cat);

	/*!
	  \brief Return true if the event has been rejected by the filtering system.
	*/
	bool is_filtered_out();
	scap_dump_flags get_dump_flags(OUT bool* should_drop);

	inline uint16_t get_source() const override
	{
		return ESRC_SINSP;
	}

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

// Doxygen doesn't understand VISIBILITY_PRIVATE
#ifdef _DOXYGEN
private:
#endif

	void set_iosize(uint32_t size);
	uint32_t get_iosize();

	std::string get_base_dir(uint32_t id, sinsp_threadinfo *tinfo);

	const char* get_param_as_str(uint32_t id, OUT const char** resolved_str, param_fmt fmt = PF_NORMAL);
	Json::Value get_param_as_json(uint32_t id, OUT const char** resolved_str, param_fmt fmt = PF_NORMAL);

	const char* get_param_value_str(const char* name, OUT const char** resolved_str, param_fmt fmt = PF_NORMAL);

	inline void init_keep_threadinfo()
	{
		m_flags = EF_NONE;
		m_info = &(m_event_info_table[m_pevt->type]);
		m_fdinfo = NULL;
		m_fdinfo_name_changed = false;
		m_iosize = 0;
		m_poriginal_evt = NULL;
	}
	inline void init()
	{
		init_keep_threadinfo();
		m_tinfo_ref.reset();
		m_tinfo = NULL;
	}
	inline void init(uint8_t* evdata, uint16_t cpuid)
	{
		m_flags = EF_NONE;
		m_pevt = (scap_evt *)evdata;
		m_info = &(m_event_info_table[m_pevt->type]);
		m_tinfo_ref.reset();
		m_tinfo = NULL;
		m_fdinfo = NULL;
		m_fdinfo_name_changed = false;
		m_iosize = 0;
		m_cpuid = cpuid;
		m_poriginal_evt = NULL;
	}
	inline void init(scap_evt *scap_event,
			 ppm_event_info * ppm_event,
			 sinsp_threadinfo *threadinfo,
			 sinsp_fdinfo_t *fdinfo)
	{
		m_pevt = scap_event;
		m_info = ppm_event;
		m_tinfo_ref.reset(); // we don't own the threadinfo so don't try to manage its lifetime
		m_tinfo = threadinfo;
		m_fdinfo = fdinfo;
	}
	inline void load_params()
	{
		uint32_t j;
		sinsp_evt_param par;
		struct scap_sized_buffer params[PPM_MAX_EVENT_PARAMS];

		m_params.clear();

		uint32_t nparams = scap_event_decode_params(m_pevt, params);

		/* We need the event info to overwrite some parameters if necessary. */
		const struct ppm_event_info* event_info = &m_event_info_table[m_pevt->type];
		int param_type = 0;
		
		for(j = 0; j < nparams; j++)
		{
			/* Here we need to manage a particular case:
			* 
			*    - PT_CHARBUF
			*    - PT_FSRELPATH
			*    - PT_BYTEBUF
			*    - PT_BYTEBUF
			* 
			* In the past these params could be `<NA>` or `(NULL)` or empty.
			* Now they can be only empty! The ideal solution would be:
			* 	params[i].buf = NULL;
			*	params[i].size = 0;
			* 
			* The problem is that userspace is not
			* able to manage `NULL` pointers... but it manages `<NA>` so we
			* convert all these cases to `<NA>` when they are empty!
			* 
			* If we read scap-files we could face `(NULL)` params, so also in
			* this case we convert them to `<NA>`.
			* 
			* To be honest there could be another corner case, but right now
			* we don't have to manage it:
			*    
			*    - PT_SOCKADDR
			*    - PT_SOCKTUPLE
			*    - PT_FDLIST
			* 
			* Could be empty, so we will have:
			* 	params[i].buf = "pointer to the next param";
			*	params[i].size = 0;
			* 
			* However, as we said in the previous case, the ideal outcome would be:
			* 	params[i].buf = NULL;
			*	params[i].size = 0;
			* 
			* The difference with the previous case is that the userspace can manage
			* these params when they have `params[i].size == 0`, so we don't have
			* to use the `<NA>` workaround! We could also introduce the `NULL` and so
			* put in place the ideal solution for this parameter, but before doing this
			* we need to be sure that the userspace never tries to deference the pointer
			* otherwise it will trigger a segmentation fault at run-time. So as a first
			* step we would keep them as they are.
			*/
			param_type = event_info->params[j].type;
			
			if((param_type == PT_CHARBUF ||
				param_type == PT_FSRELPATH ||
				param_type == PT_FSPATH)
				&&
				(params[j].size == 0 ||
				(params[j].size == 7 && strncmp((char*)params[j].buf, "(NULL)", 7) == 0)))
			{
				/* Overwrite the value and the size of the param.
				* 5 = strlen("<NA>") + `\0`.
				*/
				params[j].buf = (void*)"<NA>";
				params[j].size = 5;
			}

			par.init((char*)params[j].buf, (int)params[j].size);
			m_params.push_back(par);
		}
	}
	std::string get_param_value_str(uint32_t id, bool resolved);
	std::string get_param_value_str(const char* name, bool resolved = true);
	char* render_fd(int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt);
	int render_fd_json(Json::Value *ret, int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt);
	uint32_t get_dump_flags();
	static bool clone_event(sinsp_evt& dest, const sinsp_evt& src);

VISIBILITY_PRIVATE
	enum flags
	{
		SINSP_EF_NONE = 0,
		SINSP_EF_PARAMS_LOADED = 1,
		SINSP_EF_IS_TRACER = (1 << 1),
	};

	sinsp* m_inspector;
	scap_evt* m_pevt;
	scap_evt* m_poriginal_evt;	// This is used when the original event is replaced by a different one (e.g. in the case of user events)
	char *m_pevt_storage;           // In some cases an alternate buffer is used to hold m_pevt. This points to that storage.
	uint16_t m_cpuid;
	uint64_t m_evtnum;
	uint32_t m_flags;
	bool m_params_loaded;
	const struct ppm_event_info* m_info;
	std::vector<sinsp_evt_param> m_params;

	std::vector<char> m_paramstr_storage;
	std::vector<char> m_resolved_paramstr_storage;

	// reference to keep threadinfo alive. currently only used for synthetic container event thread info
	// it should either be null, or point to the same place as m_tinfo
	std::shared_ptr<sinsp_threadinfo> m_tinfo_ref;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;

	// If true, then the associated fdinfo changed names as a part
	// of parsing this event.
	bool m_fdinfo_name_changed;

	uint32_t m_iosize;
	int32_t m_errorcode;
	int32_t m_rawbuf_str_len;
	bool m_filtered_out;
	const struct ppm_event_info* m_event_info_table;

	std::shared_ptr<sinsp_fdinfo_t> m_fdinfo_ref;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_threadinfo;
	friend class sinsp_analyzer;
	friend class sinsp_filter_check_event;
	friend class sinsp_filter_check_thread;
	friend class sinsp_dumper;
	friend class sinsp_analyzer_fd_listener;
	friend class sinsp_analyzer_parsers;
	friend class lua_cbacks;
	friend class sinsp_container_manager;
	friend class chisel_table;
	friend class sinsp_cursesui;
	friend class sinsp_baseliner;
	friend class capture_job_handler;
	friend class capture_job;
	friend class sinsp_memory_dumper;
	friend class sinsp_memory_dumper_job;
	friend class protocol_manager;
	friend class test_helpers::event_builder;
	friend class test_helpers::sinsp_mock;
	friend class sinsp_usergroup_manager;
};

/*@}*/
