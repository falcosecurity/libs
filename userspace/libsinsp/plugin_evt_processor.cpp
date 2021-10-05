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

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "plugin.h"
#include "plugin_evt_processor.h"

class sinsp_async_extractor_ctx;

///////////////////////////////////////////////////////////////////////////////
// sinsp_pep_flt_worker implementation
///////////////////////////////////////////////////////////////////////////////
void worker_thread(sinsp_pep_flt_worker* This)
{
	while(This->m_die == false)
	{
		if(This->m_state == sinsp_pep_flt_worker::WS_WORKING)
		{
			This->process_event();
			This->m_state = sinsp_pep_flt_worker::WS_HAS_RESULT;
		}
		this_thread::yield();
	}
}

sinsp_pep_flt_worker::sinsp_pep_flt_worker(sinsp* inspector, sinsp_plugin_evt_processor* pprocessor, bool async)
{
	m_inspector = inspector;
	m_pprocessor = pprocessor;
	m_evt.m_info = &(g_infotables.m_event_info[PPME_PLUGINEVENT_E]);
	m_evt.m_inspector = m_inspector;
	if(async)
	{
		m_th = new thread(worker_thread, this);
	}
	m_evt_storage.resize(128000);
}

void sinsp_pep_flt_worker::set_filter(sinsp_filter* filter)
{
	m_filter = filter;
}

sinsp_pep_flt_worker::~sinsp_pep_flt_worker()
{
	if(m_th)
	{
		m_die = true;
		m_th->join();
		delete m_th;
	}
}

bool sinsp_pep_flt_worker::process_event()
{
	m_cnt++;
	m_evt.m_filtered_out = false;
	m_evt.m_flags = 0;
	m_evt.m_poriginal_evt = NULL;

	m_evt.m_filtered_out = false;
	if(m_filter && m_filter->run(&m_evt) == false)
	{
		m_evt.m_filtered_out = true;
	}

//	m_evt.m_filtered_out = true;
// uint64_t r = 0;
// for(uint64_t j = 0; j < 10000; j++)
// {
// 	r += j;
// 	r *= (r + j);
// }
// m_tmp = r;

	return &m_evt;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_plugin_evt_processor	 implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_plugin_evt_processor::sinsp_plugin_evt_processor(sinsp* inspector)
{
	m_inspector = inspector;
	init();
}

sinsp_plugin_evt_processor::~sinsp_plugin_evt_processor()
{
}

void sinsp_plugin_evt_processor::init()
{
	sinsp_filter* cf;

#ifdef PARALLEL_PLUGIN_EVT_FILTERING_ENABLED
	for(uint32_t j = 0; j < m_nworkers; j++)
	{
		m_workers.emplace_back(std::make_shared<sinsp_pep_flt_worker>(m_inspector, this, true));
	}
#endif

	m_sync_worker = std::make_shared<sinsp_pep_flt_worker>(m_inspector, this, false);
}

void sinsp_plugin_evt_processor::compile(string filter)
{
	sinsp_filter* cf;

#ifdef MULTITHREAD_PLUGIN_EVT_PROCESSOR_ENABLED
	for(uint32_t j = 0; j < m_nworkers; j++)
	{
		m_inprogress = true;
		m_inprogress_infos.clear();
		sinsp_filter_compiler wcompiler(m_inspector, filter);
		cf = wcompiler.compile();
		m_inprogress = false;

		m_workers[j]->set_filter(cf);
	}
#endif

	m_inprogress = true;
	m_inprogress_infos.clear();
	sinsp_filter_compiler scompiler(m_inspector, filter);
	cf = scompiler.compile();
	m_inprogress = false;
	m_sync_worker->set_filter(cf);
}

std::shared_ptr<sinsp_plugin> sinsp_plugin_evt_processor::get_plugin_source_info(uint32_t id)
{
	if(m_inprogress)
	{
		//
		// Have we already allocated the required plugin?
		//
		auto it = m_inprogress_infos.find(id);
		if(it == m_inprogress_infos.end())
		{
			//
			// Plugin not allocated yet, allocate and configure it now
			//

			//
			// Locate the sinsp_plugin object correspondng to this plugin ID
			//
			std::shared_ptr<sinsp_plugin> pplg = m_inspector->get_plugin_by_id(id);
			if(!pplg)
			{
				//
				// This should never happen
				//
				ASSERT(false);
				throw sinsp_exception("cannot find plugin with ID " + to_string(id));
			}

			// XXX/mstemm can we use the existing plugin directly that has already been initialized?
			// ss_plugin_info* newpsi = new ss_plugin_info;
			// *newpsi = pplg->m_source_info;

			// //
			// // Initialize the new plugin instance
			// //
			// newpsi->is_async_extractor_configured = false;
			// newpsi->is_async_extractor_present = false;

			// if(newpsi->init != NULL)
			// {
			// 	int32_t init_res;
			// 	newpsi->state = newpsi->init(NULL, &init_res);
			// 	if(init_res != SCAP_SUCCESS)
			// 	{
			// 		throw sinsp_exception(string("unable to initialize plugin ") + newpsi->get_name());
			// 	}
			// }

			m_inprogress_infos[id] = pplg;
			return pplg;
		}
		else
		{
			//
			// Plugin already allocated, point to the existing one
			//
			return it->second;
		}
	}
	else
	{
		return std::shared_ptr<sinsp_plugin>();
	}
}

#ifdef MULTITHREAD_PLUGIN_EVT_PROCESSOR_ENABLED
void sinsp_plugin_evt_processor::prepare_worker(sinsp_pep_flt_worker &w, sinsp_evt* evt)
{
	uint32_t pelen = evt->m_pevt->len;

	if(pelen > w.m_evt_storage.size())
	{
		w.m_evt_storage.resize(pelen);
	}

	memcpy(&(w.m_evt_storage[0]), evt->m_pevt, evt->m_pevt->len);
	w.m_evt.m_pevt = (scap_evt*)&(w.m_evt_storage[0]);
	w.m_evt.m_evtnum = evt->m_evtnum;
}
#else
void sinsp_plugin_evt_processor::prepare_worker(sinsp_pep_flt_worker &w, sinsp_evt* evt)
{
	uint32_t pelen = evt->m_pevt->len;
	w.m_evt.m_pevt = evt->m_pevt;
	w.m_evt.m_evtnum = evt->m_evtnum;
}
#endif

sinsp_evt* sinsp_plugin_evt_processor::process_event(sinsp_evt* evt)
{
#ifdef MULTITHREAD_PLUGIN_EVT_PROCESSOR_ENABLED
	if(is_worker_available())
	{
		for(auto w : m_workers)
		{
			if(w->m_state == sinsp_pep_flt_worker::WS_READY)
			{
				prepare_worker(*(w.get()), evt);
				w->m_state = sinsp_pep_flt_worker::WS_WORKING;
				return NULL;
			}
		}
	}
#endif

	prepare_worker(*(m_sync_worker.get()), evt);
	m_sync_worker->process_event();
	sinsp_evt* res = m_sync_worker->get_evt();
	return res;
}

sinsp_evt* sinsp_plugin_evt_processor::get_event_from_backlog()
{
	for(auto w : m_workers)
	{
		if(w->m_state == sinsp_pep_flt_worker::WS_HAS_RESULT)
		{
			w->m_state = sinsp_pep_flt_worker::WS_READY;
			sinsp_evt* res = w->get_evt();
			return res;
		}
	}

	return NULL;
}

bool sinsp_plugin_evt_processor::is_worker_available()
{
	for(auto w : m_workers)
	{
		if(w->m_state == sinsp_pep_flt_worker::WS_READY)
		{
			return true;
		}
	}

	return false;
}
