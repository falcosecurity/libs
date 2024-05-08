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

#include <libsinsp/sinsp_filtercheck_k8s.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static inline bool str_match_start(std::string_view val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_k8s_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.ns.name", "Namespace Name", "The Kubernetes namespace name. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.name", "Pod Name", "The Kubernetes pod name. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.id", "Legacy Pod UID", "[LEGACY] The Kubernetes pod UID, e.g. 3e41dc6b-08a8-44db-bc2a-3724b18ab19a. This legacy field points to `k8s.pod.uid`; however, the pod ID typically refers to the pod sandbox ID. We recommend using the semantically more accurate `k8s.pod.uid` field. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.uid", "Pod UID", "The Kubernetes pod UID, e.g. 3e41dc6b-08a8-44db-bc2a-3724b18ab19a. Note that the pod UID is a unique identifier assigned upon pod creation within Kubernetes, allowing the Kubernetes control plane to manage and track pods reliably. As such, it is fundamentally a different concept compared to the pod sandbox ID. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.sandbox_id", "Pod / Sandbox ID", "The truncated Kubernetes pod sandbox ID (first 12 characters), e.g 63060edc2d3a. The sandbox ID is specific to the container runtime environment. It is the equivalent of the container ID for the pod / sandbox and extracted from the Linux cgroups. As such, it differs from the pod UID. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet. In Kubernetes, pod sandbox container processes can exist where `container.id` matches `k8s.pod.sandbox_id`, lacking other 'container.*' details."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.full_sandbox_id", "Pod / Sandbox ID", "The full Kubernetes pod / sandbox ID, e.g 63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "k8s.pod.label", "Pod Label", "The Kubernetes pod label. The label can be accessed either with the familiar brackets notation, e.g. 'k8s.pod.label[foo]' or by appending a dot followed by the name, e.g. 'k8s.pod.label.foo'. The label name itself can include the original special characters such as '.', '-', '_' or '/' characters. For instance, 'k8s.pod.label[app.kubernetes.io/name]', 'k8s.pod.label.app.kubernetes.io/name' or 'k8s.pod.label[custom-label_one]' are all valid. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.labels", "Pod Labels", "The Kubernetes pod comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.ip", "Pod Ip", "The Kubernetes pod ip, same as container.ip field as each container in a pod shares the network stack of the sandbox / pod. Only ipv4 addresses are tracked. Consider k8s.pod.cni.json for logging ip addresses for each network interface. This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.cni.json", "Pod CNI result json", "The Kubernetes pod CNI result field from the respective pod status info, same as container.cni.json field. It contains ip addresses for each network interface exposed as unparsed escaped JSON string. Supported for CRI container engine (containerd, cri-o runtimes), optimized for containerd (some non-critical JSON keys removed). Useful for tracking ips (ipv4 and ipv6, dual-stack support) for each network interface (multi-interface support). This field is extracted from the container runtime socket simultaneously as we look up the 'container.*' fields. In cases of lookup delays, it may not be available yet."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rc.name", "Replication Controller Name", "Kubernetes replication controller name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rc.id", "Replication Controller ID", "Kubernetes replication controller id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.rc.label", "Replication Controller Label", "Kubernetes replication controller label. E.g. 'k8s.rc.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rc.labels", "Replication Controller Labels", "Kubernetes replication controller comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.svc.name", "Service Name", "Kubernetes service name (can return more than one value, concatenated)."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.svc.id", "Service ID", "Kubernetes service id (can return more than one value, concatenated)."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.svc.label", "Service Label", "Kubernetes service label. E.g. 'k8s.svc.label.foo' (can return more than one value, concatenated)."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.svc.labels", "Service Labels", "Kubernetes service comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.ns.id", "Namespace ID", "Kubernetes namespace id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.ns.label", "Namespace Label", "Kubernetes namespace label. E.g. 'k8s.ns.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.ns.labels", "Namespace Labels", "Kubernetes namespace comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rs.name", "Replica Set Name", "Kubernetes replica set name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rs.id", "Replica Set ID", "Kubernetes replica set id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.rs.label", "Replica Set Label", "Kubernetes replica set label. E.g. 'k8s.rs.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rs.labels", "Replica Set Labels", "Kubernetes replica set comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.deployment.name", "Deployment Name", "Kubernetes deployment name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.deployment.id", "Deployment ID", "Kubernetes deployment id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.deployment.label", "Deployment Label", "Kubernetes deployment label. E.g. 'k8s.rs.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.deployment.labels", "Deployment Labels", "Kubernetes deployment comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
};

sinsp_filter_check_k8s::sinsp_filter_check_k8s()
{
	static const filter_check_info s_field_infos = {
		"k8s",
		"",
		"Kubernetes context about pods and namespace name. These fields are populated with data gathered from the container runtime.",
		sizeof(sinsp_filter_check_k8s_fields) / sizeof(sinsp_filter_check_k8s_fields[0]),
		sinsp_filter_check_k8s_fields,
		filter_check_info::FL_NONE,
	};

	m_info = &s_field_infos;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_k8s::allocate_new()
{
	return std::make_unique<sinsp_filter_check_k8s>();
}

int32_t sinsp_filter_check_k8s::parse_field_name(std::string_view val, bool alloc_state, bool needed_for_filtering)
{
	if(STR_MATCH("k8s.pod.label") &&
		!STR_MATCH("k8s.pod.labels"))
	{
		m_field_id = TYPE_K8S_POD_LABEL;
		m_field = &m_info->m_fields[m_field_id];

		return extract_arg("k8s.pod.label", val);
	}
	else if(STR_MATCH("k8s.rc.label") &&
		!STR_MATCH("k8s.rc.labels"))
	{
		m_field_id = TYPE_K8S_RC_LABEL;
		m_field = &m_info->m_fields[m_field_id];

		return extract_arg("k8s.rc.label", val);
	}
	else if(STR_MATCH("k8s.rs.label") &&
		!STR_MATCH("k8s.rs.labels"))
	{
		m_field_id = TYPE_K8S_RS_LABEL;
		m_field = &m_info->m_fields[m_field_id];

		return extract_arg("k8s.rs.label", val);
	}
	else if(STR_MATCH("k8s.svc.label") &&
		!STR_MATCH("k8s.svc.labels"))
	{
		m_field_id = TYPE_K8S_SVC_LABEL;
		m_field = &m_info->m_fields[m_field_id];

		return extract_arg("k8s.svc.label", val);
	}
	else if(STR_MATCH("k8s.ns.label") &&
		!STR_MATCH("k8s.ns.labels"))
	{
		m_field_id = TYPE_K8S_NS_LABEL;
		m_field = &m_info->m_fields[m_field_id];

		return extract_arg("k8s.ns.label", val);
	}
	else if(STR_MATCH("k8s.deployment.label") &&
		!STR_MATCH("k8s.deployment.labels"))
	{
		m_field_id = TYPE_K8S_DEPLOYMENT_LABEL;
		m_field = &m_info->m_fields[m_field_id];

		return extract_arg("k8s.deployment.label", val);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(val, alloc_state, needed_for_filtering);
	}
}

int32_t sinsp_filter_check_k8s::extract_arg(string_view fldname, string_view val)
{
	int32_t parsed_len = 0;

	if(val.size() > fldname.size() && val.at(fldname.size()) == '.')
	{
		size_t endpos;
		for(endpos = fldname.size() + 1; endpos < val.length(); ++endpos)
		{
			if(!isalnum(val.at(endpos))
				&& val.at(endpos) != '/'
				&& val.at(endpos) != '_'
				&& val.at(endpos) != '-'
				&& val.at(endpos) != '.')
			{
				break;
			}
		}

		parsed_len = (uint32_t)endpos;
		m_argname = val.substr(fldname.size() + 1, endpos - fldname.size() - 1);
	}
	else if(val.size() > fldname.size() && val.at(fldname.size()) == '[')
	{
		size_t startpos = fldname.size();
		parsed_len = (uint32_t)val.find(']', startpos);

		if ((uint32_t) parsed_len == (uint32_t) std::string::npos)
		{
			throw sinsp_exception("the field '" + string(fldname) + "' requires an argument but ']' is not found");
		}
		m_argname = val.substr(startpos + 1, parsed_len - startpos - 1);
		parsed_len++;
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + string(val));
	}

	return parsed_len;
}

void sinsp_filter_check_k8s::concatenate_container_labels(const map<std::string, std::string>& labels, string* s)
{
	for (auto const& label_pair : labels)
	{
		// exclude annotations and internal labels
		if (label_pair.first.find("annotation.") == 0 || label_pair.first.find("io.kubernetes.") == 0) {
			continue;
		}
		if(!s->empty())
		{
			s->append(", ");
		}
		s->append(label_pair.first);
		if(!label_pair.second.empty())
		{
			s->append(":" + label_pair.second);
		}
	}
}

uint8_t* sinsp_filter_check_k8s::extract_single(sinsp_evt *evt, uint32_t* len, bool sanitize_strings)
{
	*len = 0;

	ASSERT(evt);
	if(evt == NULL)
	{
		ASSERT(false);
		return NULL;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return NULL;
	}

	// Here we extract info only if we have the container
	if(tinfo->m_container_id.empty())
	{
		return NULL;
	}

	const auto container_info = m_inspector->m_container_manager.get_container(tinfo->m_container_id);
	// No m_pod_sandbox_id means no k8s.
	// m_pod_sandbox_id retrieved from the ContainerStatusResponse CRI API call.
	if(container_info == nullptr || container_info->m_pod_sandbox_id.empty())
	{
		return NULL;
	}

	m_tstr.clear();

	// Note: All fields are retrieved from the CRI API calls aka as part of the container engine lookups.
	// There is no interaction w/ the Kubernetes Server in any way to retrieve these fields. As alternative explore the new `k8smeta` plugin.
	// Comments explain the origin of each field (either ContainerStatusResponse or PodSandboxStatusResponse CRI API call).

	switch(m_field_id)
	{
	case TYPE_K8S_POD_NAME:
		// Retrieved from the ContainerStatusResponse CRI API call.
		if(container_info->m_labels.count("io.kubernetes.pod.name") > 0)
		{
			m_tstr = container_info->m_labels.at("io.kubernetes.pod.name");
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_K8S_NS_NAME:
		// Retrieved from the ContainerStatusResponse CRI API call.
		if(container_info->m_labels.count("io.kubernetes.pod.namespace") > 0)
		{
			m_tstr = container_info->m_labels.at("io.kubernetes.pod.namespace");
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_K8S_POD_ID:
	case TYPE_K8S_POD_UID:
		// Retrieved from the ContainerStatusResponse CRI API call.
		if(container_info->m_labels.count("io.kubernetes.pod.uid") > 0)
		{
			m_tstr = container_info->m_labels.at("io.kubernetes.pod.uid");
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_K8S_POD_SANDBOX_ID:
	case TYPE_K8S_POD_FULL_SANDBOX_ID:
		// Retrieved from the ContainerStatusResponse CRI API call.
		m_tstr = container_info->m_pod_sandbox_id;
		if(m_field_id == TYPE_K8S_POD_SANDBOX_ID)
		{
			if(m_tstr.size() > 12)
			{
				m_tstr.resize(12);
			}
		}
		RETURN_EXTRACT_STRING(m_tstr);
		break;
	case TYPE_K8S_POD_LABEL:
	case TYPE_K8S_POD_LABELS:
		// Requires s_cri_extra_queries enabled, which is the default for Falco.
		// Note that m_pod_sandbox_labels, while part of the container struct, is retrieved from an extra PodSandboxStatusResponse call, not the ContainerStatusResponse CRI API call.
		{
			sinsp_container_info::ptr_t sandbox_container_info;
			if(container_info->m_pod_sandbox_cniresult.empty()) // more robust check than checking for empty labels
			{
				// Fallback: Retrieve PodSandboxStatusResponse fields stored in explicit pod sandbox container
				sandbox_container_info = m_inspector->m_container_manager.get_container(container_info->m_pod_sandbox_id.substr(0, 12));
			}
			if (m_field_id == TYPE_K8S_POD_LABEL)
			{
				if(sandbox_container_info && sandbox_container_info->m_pod_sandbox_labels.count(m_argname) > 0) // fallback
				{
					m_tstr = sandbox_container_info->m_pod_sandbox_labels.at(m_argname);
				}
				else if (container_info->m_pod_sandbox_labels.count(m_argname) > 0)
				{
					m_tstr = container_info->m_pod_sandbox_labels.at(m_argname);
				}
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else if (m_field_id == TYPE_K8S_POD_LABELS)
			{
				if(sandbox_container_info) // fallback
				{
					concatenate_container_labels(sandbox_container_info->m_pod_sandbox_labels, &m_tstr);
				} else
				{
					concatenate_container_labels(container_info->m_pod_sandbox_labels, &m_tstr);
				}
				RETURN_EXTRACT_STRING(m_tstr);
			}
		}
		break;
	case TYPE_K8S_POD_IP:
		// Requires s_cri_extra_queries enabled, which is the default for Falco.
		// Note that m_pod_sandbox_labels, while part of the container struct, is retrieved from an extra PodSandboxStatusResponse call, not the ContainerStatusResponse CRI API call.
		if(container_info->m_pod_sandbox_cniresult.empty()) // more robust check than checking for 0 in m_container_ip
		{
			// Fallback: Retrieve PodSandboxStatusResponse fields stored in pod sandbox container
			const sinsp_container_info::ptr_t sandbox_container_info = m_inspector->m_container_manager.get_container(container_info->m_pod_sandbox_id.substr(0, 12));
			if(sandbox_container_info)
			{
				m_u32val = htonl(sandbox_container_info->m_container_ip);
			}
		} else
		{
			m_u32val = htonl(container_info->m_container_ip);
		}
		char addrbuff[100];
		inet_ntop(AF_INET, &m_u32val, addrbuff, sizeof(addrbuff));
		m_tstr = addrbuff;
		RETURN_EXTRACT_STRING(m_tstr);
		break;
	case TYPE_K8S_POD_CNIRESULT:
		// Requires s_cri_extra_queries enabled, which is the default for Falco.
		// Note that m_pod_sandbox_labels, while part of the container struct, is retrieved from an extra PodSandboxStatusResponse call, not the ContainerStatusResponse CRI API call.
		if(container_info->m_pod_sandbox_cniresult.empty())
		{
			// Fallback: Retrieve PodSandboxStatusResponse fields stored in pod sandbox container
			const sinsp_container_info::ptr_t sandbox_container_info = m_inspector->m_container_manager.get_container(container_info->m_pod_sandbox_id.substr(0, 12));
			if(sandbox_container_info)
			{
				RETURN_EXTRACT_STRING(sandbox_container_info->m_pod_sandbox_cniresult);
			}
		}
		RETURN_EXTRACT_STRING(container_info->m_pod_sandbox_cniresult);
		break;
	default:
		break;
	}

	// all the rest of the fields are deprecated and return NULL since
	// we removed the k8s client from the inspector.
	return NULL;
}
