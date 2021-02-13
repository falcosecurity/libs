/*
Copyright (C) 2013-2021 Draios Inc dba Sysdig.

This file is part of sysdig.

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

sinsp_pep_flt_worker::sinsp_pep_flt_worker(sinsp_filter* filter, sinsp_plugin_evt_processor* pprocessor, bool async)
{
	m_filter = filter;
	m_pprocessor = pprocessor;
	m_evt.m_info = &(g_infotables.m_event_info[PPME_PLUGINEVENT_E]);
	if(async)
	{
		m_th = new thread(worker_thread, this);
	}
	m_evt_storage.resize(128000);
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

	m_evt.m_filtered_out = false;
	if(m_filter && m_filter->run(&m_evt) == false)
	{
		m_evt.m_filtered_out = true;
	}

	return &m_evt;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_plugin_evt_processor	 implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_plugin_evt_processor::sinsp_plugin_evt_processor(sinsp* inspector)
{
	m_inspector = inspector;
}

sinsp_plugin_evt_processor::~sinsp_plugin_evt_processor()
{
	for(auto it : m_source_info_list)
	{
		if(it->register_async_extractor)
		{
			if(it->is_async_extractor_present == true)
			{
				static_cast<sinsp_async_extractor_ctx *>(it->async_extractor_info.waitCtx)->shutdown();
			}
		}

		if(it->destroy != NULL)
		{
			it->destroy(it->state);
		}

		delete it;
	}

	for(auto it : m_workers)
	{
printf("T>%d\n", it->m_cnt);
		delete it;
	}

	if(m_sync_worker)
	{
printf("S>%d\n", m_sync_worker->m_cnt);
		delete m_sync_worker;
	}
}

void sinsp_plugin_evt_processor::compile(string filter)
{
	sinsp_filter* cf;

	for(uint32_t j = 0; j < m_nworkers; j++)
	{
		m_inprogress = true;
		m_inprogress_infos.clear();
		sinsp_filter_compiler wcompiler(m_inspector, filter);
		cf = wcompiler.compile();
		m_inprogress = false;

		sinsp_pep_flt_worker* w = new sinsp_pep_flt_worker(cf, this, true);
		m_workers.push_back(w);
	}

	m_inprogress = true;
	m_inprogress_infos.clear();
	sinsp_filter_compiler scompiler(m_inspector, filter);
	cf = scompiler.compile();
	m_inprogress = false;
	m_sync_worker = new sinsp_pep_flt_worker(cf, this, false);
}

ss_plugin_info* sinsp_plugin_evt_processor::get_plugin_source_info(uint32_t id)
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
			sinsp_plugin* pplg = m_inspector->get_source_plugin_by_id(id);
			if(!pplg)
			{
				//
				// This should never happen
				//
				ASSERT(false);
				throw sinsp_exception("cannot find plugin with ID " + to_string(id));
			}

			ss_plugin_info* newpsi = new ss_plugin_info;
			*newpsi = pplg->m_source_info;

			//
			// Initialize the new plugin instance
			//
			newpsi->is_async_extractor_configured = false;
			newpsi->is_async_extractor_present = false;

			if(newpsi->init != NULL)
			{
				int32_t init_res;
				newpsi->state = newpsi->init(NULL, &init_res);
				if(init_res != SCAP_SUCCESS)
				{
					throw sinsp_exception(string("unable to initialize plugin ") + newpsi->get_name());
				}
			}

			m_inprogress_infos[id] = newpsi;
			return newpsi;
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
		return NULL;
	}
}

void sinsp_plugin_evt_processor::prepare_worker(sinsp_pep_flt_worker* w, sinsp_evt* evt)
{
	uint32_t pelen = evt->m_pevt->len;

	if(pelen > w->m_evt_storage.size())
	{
		w->m_evt_storage.resize(pelen);
	}

	memcpy(&(w->m_evt_storage[0]), evt->m_pevt, evt->m_pevt->len);
	w->m_evt.m_pevt = (scap_evt*)&(w->m_evt_storage[0]);
	w->m_evt.m_evtnum = evt->m_evtnum;
}

sinsp_evt* sinsp_plugin_evt_processor::process_event(sinsp_evt* evt)
{
	if(is_worker_available())
	{
		for(auto w : m_workers)
		{
			if(w->m_state == sinsp_pep_flt_worker::WS_READY)
			{
				prepare_worker(w, evt);
				w->m_state = sinsp_pep_flt_worker::WS_WORKING;
				return NULL;
			}
		}
	}

	prepare_worker(m_sync_worker, evt);
	m_sync_worker->process_event();
	sinsp_evt* res = m_sync_worker->get_evt();
	return res;

	//while(true)
	//{
	//	sinsp_evt* bevt = get_event_from_backlog();
	//	if(bevt != NULL)
	//	{
	//		return bevt;
	//	}
	//}
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
