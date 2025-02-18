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

#include <algorithm>
#include <vector>

#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
#include <libsinsp/container_engine/cri.h>
#include <libsinsp/cri.hpp>
#ifndef _WIN32
#include <libsinsp/container_engine/docker/docker_linux.h>
#include <libsinsp/container_engine/docker/podman.h>
#endif
#include <libsinsp/container_engine/rkt.h>
#include <libsinsp/container_engine/libvirt_lxc.h>
#include <libsinsp/container_engine/lxc.h>
#include <libsinsp/container_engine/mesos.h>
#include <libsinsp/container_engine/bpm.h>
#include <libsinsp/container_engine/containerd.h>
#endif  // MINIMAL_BUILD
#include <libsinsp/container_engine/static_container.h>

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/container.h>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_observer.h>

using namespace libsinsp;

sinsp_container_manager::sinsp_container_manager(sinsp* inspector):
        m_last_flush_time_ns(0),
        m_inspector(inspector),
        m_static_container(false),
        m_container_engine_mask(~0ULL) {
	if(m_inspector != nullptr) {
		m_sinsp_stats_v2 = m_inspector->get_sinsp_stats_v2();
	} else {
		m_sinsp_stats_v2 = nullptr;
	}
}

bool sinsp_container_manager::remove_inactive_containers() {
	bool res = false;

	if(m_last_flush_time_ns == 0) {
		m_last_flush_time_ns = m_inspector->get_lastevent_ts() -
		                       m_inspector->m_containers_purging_scan_time_ns +
		                       30 * ONE_SECOND_IN_NS;
	}

	if(m_inspector->get_lastevent_ts() >
	   m_last_flush_time_ns + m_inspector->m_containers_purging_scan_time_ns) {
		res = true;

		m_last_flush_time_ns = m_inspector->get_lastevent_ts();

		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "Flushing container table");

		std::set<std::string> containers_in_use;

		threadinfo_map_t* threadtable = m_inspector->m_thread_manager->get_threads();

		threadtable->loop([&](const sinsp_threadinfo& tinfo) {
			if(!tinfo.m_container_id.empty()) {
				containers_in_use.insert(tinfo.m_container_id);
			}
			return true;
		});

		auto containers = m_containers.lock();
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_missing_container_images = 0;
			// Will include pod sanboxes, but that's ok
			m_sinsp_stats_v2->m_n_containers = containers->size();
		}
		for(auto it = containers->begin(); it != containers->end();) {
			sinsp_container_info::ptr_t container = it->second;
			if(m_sinsp_stats_v2) {
				auto container_info = container.get();
				if(!container_info || (container_info && !container_info->m_is_pod_sandbox &&
				                       container_info->m_image.empty())) {
					// Only count missing container images and exclude sandboxes
					m_sinsp_stats_v2->m_n_missing_container_images++;
				}
			}
			if(containers_in_use.find(it->first) == containers_in_use.end()) {
				for(const auto& remove_cb : m_remove_callbacks) {
					remove_cb(*container);
				}
				containers->erase(it++);
			} else {
				++it;
			}
		}
	}

	return res;
}

sinsp_container_info::ptr_t sinsp_container_manager::get_container(
        const std::string& container_id) const {
	auto containers = m_containers.lock();
	auto it = containers->find(container_id);
	if(it != containers->end()) {
		return it->second;
	}

	return nullptr;
}

bool sinsp_container_manager::resolve_container(sinsp_threadinfo* tinfo,
                                                bool query_os_for_missing_info) {
	ASSERT(tinfo);
	bool matches = false;

	tinfo->m_container_id = "";
	if(m_inspector->get_observer()) {
		matches = m_inspector->get_observer()->on_resolve_container(this,
		                                                            tinfo,
		                                                            query_os_for_missing_info);
	}

	// Delayed so there's a chance to set alternate socket paths,
	// timeouts, after creation but before inspector open.
	if(m_container_engines.empty()) {
		create_engines();
	}

	for(auto& eng : m_container_engines) {
		matches = matches || eng->resolve(tinfo, query_os_for_missing_info);
		if(matches) {
			break;
		}
	}

	// Also possibly set the category for the threadinfo
	identify_category(tinfo);

	return matches;
}

std::string sinsp_container_manager::container_to_json(const sinsp_container_info& container_info) {
	Json::Value obj;
	Json::Value& container = obj["container"];
	container["id"] = container_info.m_id;
	container["full_id"] = container_info.m_full_id;
	container["type"] = container_info.m_type;
	container["name"] = container_info.m_name;
	container["image"] = container_info.m_image;
	container["imageid"] = container_info.m_imageid;
	container["imagerepo"] = container_info.m_imagerepo;
	container["imagetag"] = container_info.m_imagetag;
	container["imagedigest"] = container_info.m_imagedigest;
	container["privileged"] = container_info.m_privileged;
	container["host_pid"] = container_info.m_host_pid;
	container["host_network"] = container_info.m_host_network;
	container["host_ipc"] = container_info.m_host_ipc;
	container["is_pod_sandbox"] = container_info.m_is_pod_sandbox;
	container["lookup_state"] = static_cast<int>(container_info.get_lookup_status());
	container["created_time"] = static_cast<Json::Value::Int64>(container_info.m_created_time);

	Json::Value mounts = Json::arrayValue;

	for(auto& mntinfo : container_info.m_mounts) {
		Json::Value mount;

		mount["Source"] = mntinfo.m_source;
		mount["Destination"] = mntinfo.m_dest;
		mount["Mode"] = mntinfo.m_mode;
		mount["RW"] = mntinfo.m_rdwr;
		mount["Propagation"] = mntinfo.m_propagation;

		mounts.append(mount);
	}

	container["Mounts"] = mounts;

	container["User"] = container_info.m_container_user;

	sinsp_container_info::container_health_probe::add_health_probes(container_info.m_health_probes,
	                                                                container);

	char addrbuff[100];
	uint32_t iph = htonl(container_info.m_container_ip);
	inet_ntop(AF_INET, &iph, addrbuff, sizeof(addrbuff));
	container["ip"] = addrbuff;

	container["cni_json"] = container_info.m_pod_sandbox_cniresult;
	container["pod_sandbox_id"] = container_info.m_pod_sandbox_id;

	Json::Value port_mappings = Json::arrayValue;

	for(auto& mapping : container_info.m_port_mappings) {
		Json::Value jmap;
		jmap["HostIp"] = mapping.m_host_ip;
		jmap["HostPort"] = mapping.m_host_port;
		jmap["ContainerPort"] = mapping.m_container_port;

		port_mappings.append(jmap);
	}

	container["port_mappings"] = port_mappings;

	Json::Value labels;
	for(auto& pair : container_info.m_labels) {
		labels[pair.first] = pair.second;
	}
	container["labels"] = labels;

	Json::Value pod_sandbox_labels;
	for(auto& pair : container_info.m_pod_sandbox_labels) {
		pod_sandbox_labels[pair.first] = pair.second;
	}
	container["pod_sandbox_labels"] = pod_sandbox_labels;

	Json::Value env_vars = Json::arrayValue;

	for(auto& var : container_info.m_env) {
		// Only append a limited set of mesos/marathon-related
		// environment variables.
		if(var.find("MESOS") != std::string::npos || var.find("MARATHON") != std::string::npos ||
		   var.find("mesos") != std::string::npos) {
			env_vars.append(var);
		}
	}
	container["env"] = env_vars;

	container["memory_limit"] = (Json::Value::Int64)container_info.m_memory_limit;
	container["swap_limit"] = (Json::Value::Int64)container_info.m_swap_limit;
	container["cpu_shares"] = (Json::Value::Int64)container_info.m_cpu_shares;
	container["cpu_quota"] = (Json::Value::Int64)container_info.m_cpu_quota;
	container["cpu_period"] = (Json::Value::Int64)container_info.m_cpu_period;
	container["cpuset_cpu_count"] = (Json::Value::Int)container_info.m_cpuset_cpu_count;

	if(!container_info.m_mesos_task_id.empty()) {
		container["mesos_task_id"] = container_info.m_mesos_task_id;
	}

	container["metadata_deadline"] = (Json::Value::UInt64)container_info.m_metadata_deadline;
	return Json::FastWriter().write(obj);
}

bool sinsp_container_manager::container_to_sinsp_event(const std::string& json,
                                                       sinsp_evt* evt,
                                                       std::unique_ptr<sinsp_threadinfo> tinfo,
                                                       char* scap_err) {
	uint32_t json_len = json.length() + 1;
	size_t totlen = sizeof(scap_evt) + sizeof(uint32_t) + json_len;

	ASSERT(evt->get_scap_evt_storage() == nullptr);
	evt->set_scap_evt_storage(new char[totlen]);
	evt->set_scap_evt((scap_evt*)evt->get_scap_evt_storage());

	evt->set_cpuid(0);
	evt->set_num(0);
	evt->set_inspector(m_inspector);

	scap_evt* scapevt = evt->get_scap_evt();
	scapevt->ts = UINT64_MAX;
	scapevt->tid = -1;
	if(scap_event_encode_params(scap_sized_buffer{scapevt, totlen},
	                            nullptr,
	                            scap_err,
	                            PPME_CONTAINER_JSON_2_E,
	                            1,
	                            json.c_str()) != SCAP_SUCCESS) {
		return false;
	}

	evt->init();
	std::shared_ptr<sinsp_threadinfo> stinfo = std::move(tinfo);
	evt->set_tinfo_ref(stinfo);
	evt->set_tinfo(stinfo.get());

	return true;
}

sinsp_container_manager::map_ptr_t sinsp_container_manager::get_containers() const {
	return m_containers.lock();
}

void sinsp_container_manager::add_container(const sinsp_container_info::ptr_t& container_info,
                                            sinsp_threadinfo* thread) {
	set_lookup_status(container_info->m_id,
	                  container_info->m_type,
	                  container_info->get_lookup_status());

	{
		auto containers = m_containers.lock();
		(*containers)[container_info->m_id] = container_info;
	}

	for(const auto& new_cb : m_new_callbacks) {
		new_cb(*container_info, thread);
	}
}

void sinsp_container_manager::replace_container(const sinsp_container_info::ptr_t& container_info) {
	auto containers = m_containers.lock();
	ASSERT(containers->find(container_info->m_id) != containers->end());
	(*containers)[container_info->m_id] = container_info;
}

void sinsp_container_manager::notify_new_container(const sinsp_container_info& container_info,
                                                   sinsp_threadinfo* tinfo) {
	if(!m_inspector->m_inited || m_inspector->is_offline()) {
		// This is either:
		// * being called from a threadinfo->resolve_container
		// 	before sinsp is actually started (ie: while parsing proc),
		//     	We should not send any event in this phase, as these containers
		//	will be part of "initial state" (dumped by dump_containers())
		// * being called in capture mode (no need to send any event as we will read it)
		//
		// Fallback at just storing the new container.
		// NOTE: this must be kept in sync with what happens on container event parsing, in
		// parsers.cpp.
		const auto container = m_inspector->m_container_manager.get_container(container_info.m_id);
		if(container != nullptr && container->is_successful()) {
			SINSP_DEBUG("Ignoring new container notification for already successful lookup of %s",
			            container_info.m_id.c_str());
		} else {
			// We don't log any warning when the inspector
			// is doing its initial scan from /proc + any
			// container lookups. Those don't have
			// retries.
			if(!container_info.is_successful() && m_inspector->m_inited) {
				// This means that the container
				// engine made multiple attempts to
				// look up the info and all attempts
				// failed. Log that as a warning.
				libsinsp_logger()->format(sinsp_logger::SEV_WARNING,
				                          "notify_new_container (%s): Saving empty container info "
				                          "after repeated failed lookups",
				                          container_info.m_id.c_str());
			}
			add_container(std::make_shared<sinsp_container_info>(container_info), tinfo);
		}
		return;
	}

	// In all other cases, containers will be stored after the proper
	// PPME_CONTAINER_JSON_2_E event is received by the engine and processed.

	std::unique_ptr<sinsp_evt> evt(new sinsp_evt());

	char scap_err[SCAP_LASTERR_SIZE];

	if(container_to_sinsp_event(container_to_json(container_info),
	                            evt.get(),
	                            container_info.get_tinfo(m_inspector),
	                            scap_err)) {
		libsinsp_logger()->format(
		        sinsp_logger::SEV_DEBUG,
		        "notify_new_container (%s): created CONTAINER_JSON event, queuing to inspector",
		        container_info.m_id.c_str());

		// Enqueue it onto the queue of pending container events for the inspector
		m_inspector->handle_async_event(std::move(evt));
	} else {
		libsinsp_logger()->format(
		        sinsp_logger::SEV_ERROR,
		        "notify_new_container (%s): could not create CONTAINER_JSON event: %s, dropping",
		        container_info.m_id.c_str(),
		        scap_err);
	}
}

bool sinsp_container_manager::async_allowed() const {
	// Until sinsp is not started, force-run synchronously
	return m_inspector->m_inited;
}

void sinsp_container_manager::dump_containers(sinsp_dumper& dumper) {
	char scap_err[SCAP_LASTERR_SIZE];
	for(const auto& it : (*m_containers.lock())) {
		sinsp_evt evt;
		if(container_to_sinsp_event(container_to_json(*it.second),
		                            &evt,
		                            it.second->get_tinfo(m_inspector),
		                            scap_err)) {
			evt.get_scap_evt()->ts = m_inspector->get_new_ts();
			dumper.dump(&evt);
		} else {
			libsinsp_logger()->format(
			        sinsp_logger::SEV_ERROR,
			        "dump_containers (%s): could not create CONTAINER_JSON event: %s, dropping",
			        scap_err,
			        it.second->m_id.c_str());
		}
	}
}

std::string sinsp_container_manager::get_container_name(sinsp_threadinfo* tinfo) const {
	std::string res;

	if(tinfo->m_container_id.empty()) {
		res = "host";
	} else {
		const sinsp_container_info::ptr_t container_info = get_container(tinfo->m_container_id);

		if(!container_info) {
			return "";
		}

		if(container_info->m_name.empty()) {
			return "";
		}

		res = container_info->m_name;
	}

	return res;
}

void sinsp_container_manager::identify_category(sinsp_threadinfo* tinfo) {
	if(tinfo->m_container_id.empty()) {
		return;
	}

	if(tinfo->m_vpid == 1) {
		if(libsinsp_logger()->get_severity() >= sinsp_logger::SEV_DEBUG) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "identify_category (%ld) (%s): initial process for "
			                          "container, assigning CAT_CONTAINER",
			                          tinfo->m_tid,
			                          tinfo->m_comm.c_str());
		}

		tinfo->m_category = sinsp_threadinfo::CAT_CONTAINER;

		return;
	}

	// Categories are passed from parent to child threads
	const sinsp_threadinfo* ptinfo = tinfo->get_parent_thread();

	if(ptinfo && ptinfo->m_category != sinsp_threadinfo::CAT_NONE) {
		if(libsinsp_logger()->get_severity() >= sinsp_logger::SEV_DEBUG) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "identify_category (%ld) (%s): taking parent category %d",
			                          tinfo->m_tid,
			                          tinfo->m_comm.c_str(),
			                          ptinfo->m_category);
		}

		tinfo->m_category = ptinfo->m_category;
		return;
	}

	sinsp_container_info::ptr_t cinfo = get_container(tinfo->m_container_id);
	if(!cinfo) {
		return;
	}

	if(!cinfo->is_successful()) {
		if(libsinsp_logger()->get_severity() >= sinsp_logger::SEV_DEBUG) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "identify_category (%ld) (%s): container metadata incomplete",
			                          tinfo->m_tid,
			                          tinfo->m_comm.c_str());
		}

		return;
	}

	// Otherwise, the thread is a part of a container health probe if:
	//
	// 1. the comm and args match one of the container's health probes
	// 2. we traverse the parent state and do *not* find vpid=1,
	//    or find a process not in a container
	//
	// This indicates the initial process of the health probe.

	sinsp_container_info::container_health_probe::probe_type ptype =
	        cinfo->match_health_probe(tinfo);

	if(ptype == sinsp_container_info::container_health_probe::PT_NONE) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "identify_category (%ld) (%s): container health probe PT_NONE",
		                          tinfo->m_tid,
		                          tinfo->m_comm.c_str());

		return;
	}

	bool found_container_init = false;
	sinsp_threadinfo::visitor_func_t visitor = [&found_container_init](sinsp_threadinfo* ptinfo) {
		if(ptinfo->m_vpid == 1 && !ptinfo->m_container_id.empty()) {
			found_container_init = true;

			return false;
		}

		return true;
	};

	tinfo->traverse_parent_state(visitor);

	if(!found_container_init) {
		libsinsp_logger()->format(
		        sinsp_logger::SEV_DEBUG,
		        "identify_category (%ld) (%s): not under container init, assigning category %s",
		        tinfo->m_tid,
		        tinfo->m_comm.c_str(),
		        sinsp_container_info::container_health_probe::probe_type_names[ptype].c_str());

		// Each health probe type maps to a command category
		switch(ptype) {
		case sinsp_container_info::container_health_probe::PT_NONE:
		case sinsp_container_info::container_health_probe::PT_END:
			break;
		case sinsp_container_info::container_health_probe::PT_HEALTHCHECK:
			tinfo->m_category = sinsp_threadinfo::CAT_HEALTHCHECK;
			break;
		case sinsp_container_info::container_health_probe::PT_LIVENESS_PROBE:
			tinfo->m_category = sinsp_threadinfo::CAT_LIVENESS_PROBE;
			break;
		case sinsp_container_info::container_health_probe::PT_READINESS_PROBE:
			tinfo->m_category = sinsp_threadinfo::CAT_READINESS_PROBE;
			break;
		}
	}
}

void sinsp_container_manager::subscribe_on_new_container(new_container_cb callback) {
	m_new_callbacks.emplace_back(callback);
}

void sinsp_container_manager::subscribe_on_remove_container(remove_container_cb callback) {
	m_remove_callbacks.emplace_back(callback);
}

void sinsp_container_manager::create_engines() {
	if(m_static_container) {
		auto engine = std::make_shared<container_engine::static_container>(*this,
		                                                                   m_static_id,
		                                                                   m_static_name,
		                                                                   m_static_image);
		m_container_engines.push_back(engine);
		m_container_engine_by_type[CT_STATIC].push_back(engine);
		return;
	}
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
#ifndef _WIN32
	if(m_container_engine_mask & (1 << CT_PODMAN)) {
		auto podman_engine = std::make_shared<container_engine::podman>(*this);
		m_container_engines.push_back(podman_engine);
		m_container_engine_by_type[CT_PODMAN].push_back(podman_engine);
	}
	if(m_container_engine_mask & (1 << CT_DOCKER)) {
		auto docker_engine = std::make_shared<container_engine::docker_linux>(*this);
		m_container_engines.push_back(docker_engine);
		m_container_engine_by_type[CT_DOCKER].push_back(docker_engine);
	}

	size_t engine_index = 0;
	if(m_container_engine_mask & ((1 << CT_CRI) | (1 << CT_CRIO) | (1 << CT_CONTAINERD))) {
		// Get CRI socket paths from settings
		libsinsp::cri::cri_settings& cri_settings = libsinsp::cri::cri_settings::get();
		if(cri_settings.get_cri_unix_socket_paths().empty()) {
			// Add default paths
			cri_settings.add_cri_unix_socket_path("/run/containerd/containerd.sock");
			cri_settings.add_cri_unix_socket_path("/run/crio/crio.sock");
			cri_settings.add_cri_unix_socket_path("/run/k3s/containerd/containerd.sock");
			cri_settings.add_cri_unix_socket_path("/run/host-containerd/containerd.sock");
		}

		const auto& cri_socket_paths = cri_settings.get_cri_unix_socket_paths();

		for(auto socket_path : cri_socket_paths) {
			auto cri_engine =
			        std::make_shared<container_engine::cri>(*this, socket_path, engine_index);
			m_container_engines.push_back(cri_engine);
			m_container_engine_by_type[CT_CRI].push_back(cri_engine);
			m_container_engine_by_type[CT_CRIO].push_back(cri_engine);
			m_container_engine_by_type[CT_CONTAINERD].push_back(cri_engine);
			engine_index++;
		}
	}
	if(m_container_engine_mask & (1 << CT_LXC)) {
		auto lxc_engine = std::make_shared<container_engine::lxc>(*this);
		m_container_engines.push_back(lxc_engine);
		m_container_engine_by_type[CT_LXC].push_back(lxc_engine);
	}
	if(m_container_engine_mask & (1 << CT_LIBVIRT_LXC)) {
		auto libvirt_lxc_engine = std::make_shared<container_engine::libvirt_lxc>(*this);
		m_container_engines.push_back(libvirt_lxc_engine);
		m_container_engine_by_type[CT_LIBVIRT_LXC].push_back(libvirt_lxc_engine);
	}
	if(m_container_engine_mask & (1 << CT_MESOS)) {
		auto mesos_engine = std::make_shared<container_engine::mesos>(*this);
		m_container_engines.push_back(mesos_engine);
		m_container_engine_by_type[CT_MESOS].push_back(mesos_engine);
	}
	if(m_container_engine_mask & (1 << CT_RKT)) {
		auto rkt_engine = std::make_shared<container_engine::rkt>(*this);
		m_container_engines.push_back(rkt_engine);
		m_container_engine_by_type[CT_RKT].push_back(rkt_engine);
	}
	if(m_container_engine_mask & (1 << CT_BPM)) {
		auto bpm_engine = std::make_shared<container_engine::bpm>(*this);
		m_container_engines.push_back(bpm_engine);
		m_container_engine_by_type[CT_BPM].push_back(bpm_engine);
	}
	if(m_container_engine_mask & (1 << CT_CONTAINERD)) {
		auto containerd_engine =
		        std::make_shared<container_engine::containerd>(*this, engine_index);
		m_container_engines.push_back(containerd_engine);
		m_container_engine_by_type[CT_CONTAINERD].push_back(containerd_engine);
	}
#endif  // _WIN32
#endif  // MINIMAL_BUILD
}

void sinsp_container_manager::update_container_with_size(sinsp_container_type type,
                                                         const std::string& container_id) {
	auto found = m_container_engine_by_type.find(type);
	if(found == m_container_engine_by_type.end()) {
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
		                          "Container type %d not found when requesting size for %s",
		                          type,
		                          container_id.c_str());
		return;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "Request size for %s", container_id.c_str());
	for(const auto& engine : found->second) {
		engine->update_with_size(container_id);
	}
}

void sinsp_container_manager::cleanup() {
	for(auto& eng : m_container_engines) {
		eng->cleanup();
	}
}

void sinsp_container_manager::set_docker_socket_path(std::string socket_path) {
#if !defined(MINIMAL_BUILD) && !defined(_WIN32) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::docker_linux::set_docker_sock(std::move(socket_path));
#endif
}

void sinsp_container_manager::set_query_docker_image_info(bool query_image_info) {
#if !defined(MINIMAL_BUILD) && !defined(_WIN32) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::docker_async_source::set_query_image_info(query_image_info);
#endif
}

void sinsp_container_manager::set_cri_extra_queries(bool extra_queries) {
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::cri::set_extra_queries(extra_queries);
#endif
}

void sinsp_container_manager::set_cri_socket_path(const std::string& path) {
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::cri::set_cri_socket_path(path);
#endif
}

void sinsp_container_manager::add_cri_socket_path(const std::string& path) {
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::cri::add_cri_socket_path(path);
#endif
}

void sinsp_container_manager::set_cri_timeout(int64_t timeout_ms) {
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::cri::set_cri_timeout(timeout_ms);
#endif
}

void sinsp_container_manager::set_cri_retry_parameters(const ::libsinsp::cri::retry_parameters& v) {
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	if(!libsinsp::cri::cri_settings::set_cri_retry_parameters(v)) {
		libsinsp_logger()->format(
		        sinsp_logger::SEV_WARNING,
		        "CRI retry parameters out of range, using defaults. Wanted: %s, Using: %s",
		        v.to_string().c_str(),
		        libsinsp::cri::cri_settings::get_cri_retry_parameters().to_string().c_str());
	}
#endif
}

void sinsp_container_manager::set_cri_async(bool async) {
#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	libsinsp::container_engine::cri::set_async(async);
#endif
}

void sinsp_container_manager::set_container_labels_max_len(uint32_t max_label_len) {
	sinsp_container_info::m_container_label_max_length = max_label_len;
}
