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

#include <memory>
#include <vector>

class sinsp_pep_flt_worker
{
public:
	enum pep_flt_worker_state
	{
		WS_READY,
		WS_WORKING,
		WS_HAS_RESULT,
	};
	sinsp_pep_flt_worker(sinsp* inspector, sinsp_plugin_evt_processor* pprocessor, bool async);
	void set_filter(sinsp_filter* filter);
	~sinsp_pep_flt_worker();
	inline bool process_event();

	inline sinsp_evt* get_evt()
	{
		return &m_evt;
	}

	sinsp* m_inspector;
	sinsp_evt m_evt;
	std::vector<char> m_evt_storage;
	sinsp_filter* m_filter = NULL;
	thread* m_th = NULL;
	bool m_die = false;
	pep_flt_worker_state m_state = WS_READY;
	sinsp_plugin_evt_processor* m_pprocessor;
	uint32_t m_cnt = 0;
	uint32_t m_tmp = 0;
};

class sinsp_plugin_evt_processor
{
public:
	sinsp_plugin_evt_processor(sinsp* inspector);
	~sinsp_plugin_evt_processor();
	void init();
	void compile(string filter);
	sinsp_evt* process_event(sinsp_evt *evt);
	sinsp_evt* get_event_from_backlog();
	std::shared_ptr<sinsp_plugin> get_plugin_source_info(uint32_t id);

private:
	void prepare_worker(sinsp_pep_flt_worker& w, sinsp_evt* evt);
	bool is_worker_available();

	sinsp* m_inspector;
	uint32_t m_nworkers = 1;
	std::vector<std::shared_ptr<sinsp_pep_flt_worker>> m_workers;
	std::shared_ptr<sinsp_pep_flt_worker> m_sync_worker;
	std::vector<std::shared_ptr<sinsp_plugin>> m_source_info_list;
	bool m_inprogress = false;
	map<uint32_t, std::shared_ptr<sinsp_plugin>> m_inprogress_infos;
	std::shared_ptr<sinsp_plugin> m_cur_source_info;

friend class sinsp_pep_flt_worker;
};
