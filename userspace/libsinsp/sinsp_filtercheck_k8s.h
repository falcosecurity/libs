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

#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)

#include "sinsp_filtercheck.h"
#include "k8s.h"

class sinsp_filter_check_k8s : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_K8S_POD_NAME = 0,
		TYPE_K8S_POD_ID,
		TYPE_K8S_POD_LABEL,
		TYPE_K8S_POD_LABELS,
		TYPE_K8S_POD_IP,
		TYPE_K8S_POD_CNIRESULT,
		TYPE_K8S_RC_NAME,
		TYPE_K8S_RC_ID,
		TYPE_K8S_RC_LABEL,
		TYPE_K8S_RC_LABELS,
		TYPE_K8S_SVC_NAME,
		TYPE_K8S_SVC_ID,
		TYPE_K8S_SVC_LABEL,
		TYPE_K8S_SVC_LABELS,
		TYPE_K8S_NS_NAME,
		TYPE_K8S_NS_ID,
		TYPE_K8S_NS_LABEL,
		TYPE_K8S_NS_LABELS,
		TYPE_K8S_RS_NAME,
		TYPE_K8S_RS_ID,
		TYPE_K8S_RS_LABEL,
		TYPE_K8S_RS_LABELS,
		TYPE_K8S_DEPLOYMENT_NAME,
		TYPE_K8S_DEPLOYMENT_ID,
		TYPE_K8S_DEPLOYMENT_LABEL,
		TYPE_K8S_DEPLOYMENT_LABELS,
	};

	sinsp_filter_check_k8s();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t extract_arg(const std::string& fldname, const std::string& val);
	const k8s_pod_t* find_pod_for_thread(const sinsp_threadinfo* tinfo);
	const k8s_ns_t* find_ns_by_name(const std::string& ns_name);
	const k8s_rc_t* find_rc_by_pod(const k8s_pod_t* pod);
	const k8s_rs_t* find_rs_by_pod(const k8s_pod_t* pod);
	std::vector<const k8s_service_t*> find_svc_by_pod(const k8s_pod_t* pod);
	const k8s_deployment_t* find_deployment_by_pod(const k8s_pod_t* pod);
	void concatenate_labels(const k8s_pair_list& labels, std::string* s);
	void concatenate_container_labels(const std::map<std::string, std::string>& labels, std::string* s);
	bool find_label(const k8s_pair_list& labels, const std::string& key, std::string* value);
	std::string m_argname;
	std::string m_tstr;
	uint32_t m_u32val;
};

#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)