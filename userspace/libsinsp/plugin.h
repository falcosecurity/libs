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

#include <atomic>
#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <plugin_info.h>

class sinsp_filter_check_plugin;

class sinsp_async_extractor
{
public:
	sinsp_async_extractor()
	{
		m_lock = state::INIT;

		m_async_extractor_info.cb_wait = [](void *wait_ctx)
		{
			return static_cast<sinsp_async_extractor *>(wait_ctx)->wait();
		};

		m_async_extractor_info.wait_ctx = this;
	}

	~sinsp_async_extractor()
	{
		shutdown();
	}

	struct async_extractor_info *extractor_info()
	{
		return &m_async_extractor_info;
	}

	bool extract_str(uint64_t evtnum, uint32_t field_id, uint32_t ftype, char *arg, char *data, uint32_t datalen, std::string &ret)
	{
		if (!extract(evtnum, field_id, ftype, arg, data, datalen))
		{
			return false;
		}

		// The string value is now in res_str, and is an allocated string.
		// XXX/mstemm consider changing struct to have a fixed-width string.
		if(m_async_extractor_info.res_str == NULL)
		{
			return false;
		}
		ret = m_async_extractor_info.res_str;
		free(m_async_extractor_info.res_str);

		return true;
	}

	bool extract_u64(uint64_t evtnum, uint32_t field_id, uint32_t ftype, char *arg, char *data, uint32_t datalen, uint32_t &field_present, uint64_t &ret)
	{
		if (!extract(evtnum, field_id, ftype, arg, data, datalen))
		{
			return false;
		}

		// The uint64 info is now in field_present/res_u64
		field_present = m_async_extractor_info.field_present;
		ret = m_async_extractor_info.res_u64;
		return true;
	}

private:

	enum state
	{
		INIT = 0,
		INPUT_READY = 1,
		PROCESSING = 2,
		DONE = 3,
		SHUTDOWN_REQ = 4,
		SHUTDOWN_DONE = 5,
	};

	inline bool extract(uint64_t evtnum, uint32_t field_id, uint32_t ftype, char *arg, char *data, uint32_t datalen)
	{
		m_async_extractor_info.evtnum = evtnum;
		m_async_extractor_info.field_id = field_id;
		m_async_extractor_info.ftype = ftype;
		m_async_extractor_info.arg = arg;
		m_async_extractor_info.data = data;
		m_async_extractor_info.datalen = datalen;

		int old_val = state::DONE;

		while(!m_lock.compare_exchange_strong(old_val, state::INPUT_READY))
		{
			old_val = state::DONE;
		}

		//
		// Once INPUT_READY state has been aquired, wait for worker completition
		//
		while(m_lock != state::DONE);

		// rc now contains the error code for the extraction.
		int32_t rc = m_async_extractor_info.rc;
		return (rc == SCAP_SUCCESS);
	}

	inline bool wait()
	{
		m_lock = state::DONE;
		uint64_t ncycles = 0;
		bool sleeping = false;

		//
		// Worker has done and now waits for a new input or a shutdown request.
		// Note: we busy loop for the first 1ms to guarantee maximum performance.
		//       After 1ms we start sleeping to conserve CPU.
		//
		int old_val = state::INPUT_READY;

		auto start_time = chrono::high_resolution_clock::now();

		while(!m_lock.compare_exchange_strong(old_val, state::PROCESSING))
		{
			// shutdown
			if(old_val == state::SHUTDOWN_REQ)
			{
				m_lock = state::SHUTDOWN_DONE;
				return false;
			}
			old_val = state::INPUT_READY;

			if(sleeping)
			{
				this_thread::sleep_for(chrono::milliseconds(10));
			}
			else
			{
				ncycles++;
				if(ncycles >= 100000)
				{
					auto cur_time = chrono::high_resolution_clock::now();
					auto delta_time = chrono::duration_cast<std::chrono::microseconds>(cur_time - start_time).count();
					if(delta_time > 1000)
					{
						sleeping = true;
					}
					else
					{
						ncycles = 0;
					}
				}
			}
		}
		return true;
	}

	inline void shutdown()
	{
		//
		// Set SHUTDOWN_REQ iff the worker
		//
		int old_val = state::DONE;
		while(m_lock.compare_exchange_strong(old_val, state::SHUTDOWN_REQ))
		{
			old_val = state::DONE;
		}

		// await shutdown
		// XXX/mstemm add a timeout to this
		while (m_lock != state::SHUTDOWN_DONE)
			;
	}

private:
	// The shared struct to communicate with the plugin side
	struct async_extractor_info m_async_extractor_info;

	atomic<int> m_lock;
};

// Base class for source/extractor plugins. Can not be created directly.
class sinsp_plugin
{
public:
	class version {
	public:
		version(const char *version_str);
		virtual ~version();

		std::string as_string() const;

		bool m_valid;
		uint32_t m_version_major;
		uint32_t m_version_minor;
		uint32_t m_version_patch;
	};

	class event {
	public:
		// Assumes data is allocated and ownership transfers to this object.
		event();
		event(uint8_t *data, uint32_t datalen, uint64_t ts);
		~event();

		void set(uint8_t *data, uint32_t datalen, uint64_t ts);

		const uint8_t *data();
		uint32_t datalen();
		uint64_t ts();

	private:

		std::unique_ptr<uint8_t> m_data;
		uint32_t m_datalen;
		uint64_t m_ts;
	};

	// Create and register a plugin from a shared library pointed
	// to by filepath, and add it to the inspector.
	static void register_plugin(sinsp* inspector, std::string filepath, char *config, bool avoid_async);

	// Create a plugin from the dynamic library at the provided
	// path. On error, the shared_ptr will == NULL and errstr is
	// set with an error.
	static std::shared_ptr<sinsp_plugin> create_plugin(std::string &filepath, char *config, bool avoid_async, std::string &errstr);

	// Return a string with names/descriptions/etc of all plugins used by this inspector
	static std::string plugin_infos(sinsp *inspector);

	sinsp_plugin();
	virtual ~sinsp_plugin();

	bool init(char *config, int32_t &rc);

	virtual ss_plugin_type type() = 0;

	std::string get_last_error();

	const std::string &name();
	const std::string &description();
	const std::string &contact();
	const version &plugin_version();
	const filtercheck_field_info *fields();
	uint32_t nfields();

	// Will either use the the async extractor interface or direct C calls to extract the values
	bool extract_str(uint64_t evtnum, uint32_t field_id, char *arg, char *data, uint32_t datalen, std::string &ret);
	bool extract_u64(uint64_t evtnum, uint32_t field_id, char *arg, char *data, uint32_t datalen, uint32_t &field_present, uint64_t &ret);

protected:
	// Helper function to resolve symbols
	void* getsym(void* handle, const char* name, bool avoid_async);

	// Might be called by extract_str/extract_u64
	bool async_extract_str(uint64_t evtnum, uint32_t field_id, uint32_t ftype, char *arg, char *data, uint32_t datalen, std::string &ret);
        bool async_extract_u64(uint64_t evtnum, uint32_t field_id, uint32_t ftype, char *arg, char *data, uint32_t datalen, uint32_t &field_present, uint64_t &ret);

	// Helper function to set a string from an allocated charbuf and free the charbuf.
	std::string str_from_alloc_charbuf(char *charbuf);

	// Given a dynamic library handle, fill in common properties
	// (name/desc/etc) and required functions
	// (init/destroy/extract/etc).
	// Returns true on success, false + sets errstr on error.
	virtual bool resolve_dylib_symbols(void *handle, std::string &errstr);

	// Derived classes might need to access the return value from init().
	ss_plugin_t *m_plugin_handle;

private:
	// Functions common to all derived plugin
	// types. get_required_api_version/get_type are common but not
	// included here as they are called in create_plugin()
	typedef struct {
		ss_plugin_t* (*init)(char* config, int32_t* rc);
		void (*destroy)(ss_plugin_t* s);
		char* (*get_last_error)(ss_plugin_t* s);
		char* (*get_name)();
		char* (*get_description)();
		char* (*get_contact)();
		char* (*get_version)();
		char* (*get_fields)();
		char *(*extract_str)(ss_plugin_t *s, uint64_t evtnum, uint32_t id, char *arg, uint8_t *data, uint32_t datalen);
		uint64_t (*extract_u64)(ss_plugin_t *s, uint64_t evtnum, uint32_t id, char *arg, uint8_t *data, uint32_t datalen, uint32_t *field_present);
		int32_t (*register_async_extractor)(ss_plugin_t *s, async_extractor_info *info);
	} common_plugin_info;

	std::string m_name;
	std::string m_description;
	std::string m_contact;
	version m_version;

	// Allocated instead of vector to match how it will be held in filter_check_info
	std::unique_ptr<filtercheck_field_info[]> m_fields;
	int32_t m_nfields;

	std::unique_ptr<sinsp_async_extractor> m_async_extractor;

	common_plugin_info m_plugin_info;
};

class sinsp_source_plugin : public sinsp_plugin
{
public:
	sinsp_source_plugin();
	virtual ~sinsp_source_plugin();

	ss_plugin_type type() override { return TYPE_SOURCE_PLUGIN; };
	uint32_t id();
	const std::string &event_source();

	// Note that embedding ss_instance_t in the object means that
	// a plugin can only have one open active at a time.
	bool open(char *params, int32_t &rc);
	void close();
	int32_t next(event &evt, std::string &errbuf);
	int32_t next_batch(std::vector<sinsp_plugin::event> &events, std::string &errbuf);
	std::string get_progress(uint32_t &progress_pct);

	std::string event_to_string(const uint8_t *data, uint32_t datalen);

protected:
	bool resolve_dylib_symbols(void *handle, std::string &errstr) override;

private:
	uint32_t m_id;
	std::string m_event_source;

	source_plugin_info m_source_plugin_info;

	ss_instance_t *m_instance_handle;

};

class sinsp_extractor_plugin : public sinsp_plugin
{
public:
	sinsp_extractor_plugin();
	virtual ~sinsp_extractor_plugin();

	ss_plugin_type type() override { return TYPE_EXTRACTOR_PLUGIN; };

	const std::set<std::string> &extract_event_sources();

	// Return true if the provided source is compatible with this
	// extractor plugin, either because the extractor plugin does
	// not name any extract sources, or if the provided source is
	// in the set of extract sources.
	bool source_compatible(const std::string &source);

private:
	extractor_plugin_info m_extractor_plugin_info;
	std::set<std::string> m_extract_event_sources;
};
