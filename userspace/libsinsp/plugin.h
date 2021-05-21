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

class sinsp_filter_check_plugin;

class sinsp_async_extractor_ctx
{
public:
	sinsp_async_extractor_ctx()
	{
		m_lock = state::INIT;
	}

	enum state
	{
		INIT = 0,
		INPUT_READY = 1,
		PROCESSING = 2,
		DONE = 3,
		SHUTDOWN_REQ = 4,
		SHUTDOWN_DONE = 5,
	};

	inline void notify()
	{
		int old_val = state::DONE;

		while(!m_lock.compare_exchange_strong(old_val, state::INPUT_READY))
		{
			old_val = state::DONE;
		}

		//
		// Once INPUT_READY state has been aquired, wait for worker completition
		//
		while(m_lock != state::DONE);
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
		while (m_lock != state::SHUTDOWN_DONE)
			;
	}

private:
	atomic<int> m_lock;
};

class sinsp_plugin_desc
{
public:
	string m_name;
	string m_description;
	uint32_t m_id;
};

class sinsp_plugin
{
public:
	sinsp_plugin(sinsp* inspector);
	~sinsp_plugin();
	bool configure(ss_plugin_info* plugin_info, char* config, bool avoid_async);
	uint32_t get_id();
	ss_plugin_type get_type();
	static void register_plugin(sinsp* inspector, string filepath, char* config);
	static void list_plugins(sinsp* inspector);
	static void validate_plugin_version(ss_plugin_info* plugin_info);

	ss_plugin_info m_source_info;

private:
	static void* getsym(void* handle, const char* name);
	static bool create_dynlib_source(string filepath, OUT ss_plugin_info* info, OUT string* error);

	sinsp* m_inspector;
	uint32_t m_id;
	vector<filtercheck_field_info> m_fields;
	sinsp_filter_check_plugin* m_filtercheck = NULL;
	ss_plugin_type m_type;
	uint32_t m_plugin_field_present;
};
