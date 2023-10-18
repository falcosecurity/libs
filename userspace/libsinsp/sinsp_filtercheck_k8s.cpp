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

#include "sinsp_filtercheck_k8s.h"
#include "sinsp.h"
#include "sinsp_int.h"

using namespace std;

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_k8s_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.name", "Pod Name", "Kubernetes pod name."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.id", "Pod ID", "Kubernetes pod id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "k8s.pod.label", "Pod Label", "Kubernetes pod label. E.g. 'k8s.pod.label.foo'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.labels", "Pod Labels", "Kubernetes pod comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.ip", "Pod Ip", "Kubernetes pod ip, same as container.ip field as each container in a pod shares the network stack of the sandbox / pod. Only ipv4 addresses are tracked. Consider k8s.pod.cni.json for logging ip addresses for each network interface."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.pod.cni.json", "Pod CNI result json", "Kubernetes pod CNI result field from the respective pod status info, same as container.cni.json field. It contains ip addresses for each network interface exposed as unparsed escaped JSON string. Supported for CRI container engine (containerd, cri-o runtimes), optimized for containerd (some non-critical JSON keys removed). Useful for tracking ips (ipv4 and ipv6, dual-stack support) for each network interface (multi-interface support)."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rc.name", "Replication Controller Name", "Kubernetes replication controller name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rc.id", "Replication Controller ID", "Kubernetes replication controller id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.rc.label", "Replication Controller Label", "Kubernetes replication controller label. E.g. 'k8s.rc.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.rc.labels", "Replication Controller Labels", "Kubernetes replication controller comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.svc.name", "Service Name", "Kubernetes service name (can return more than one value, concatenated)."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.svc.id", "Service ID", "Kubernetes service id (can return more than one value, concatenated)."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "k8s.svc.label", "Service Label", "Kubernetes service label. E.g. 'k8s.svc.label.foo' (can return more than one value, concatenated)."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "k8s.svc.labels", "Service Labels", "Kubernetes service comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "k8s.ns.name", "Namespace Name", "Kubernetes namespace name."},
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
	m_info.m_name = "k8s";
	m_info.m_desc = "Kubernetes related context. When configured to fetch from the API server, all fields are available. Otherwise, only the `k8s.pod.*` and `k8s.ns.name` fields are populated with data gathered from the container runtime.";
	m_info.m_fields = sinsp_filter_check_k8s_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_k8s_fields) / sizeof(sinsp_filter_check_k8s_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
}

sinsp_filter_check* sinsp_filter_check_k8s::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_k8s();
}

int32_t sinsp_filter_check_k8s::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);

	if(STR_MATCH("k8s.pod.label") &&
		!STR_MATCH("k8s.pod.labels"))
	{
		m_field_id = TYPE_K8S_POD_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("k8s.pod.label", val);
	}
	else if(STR_MATCH("k8s.rc.label") &&
		!STR_MATCH("k8s.rc.labels"))
	{
		m_field_id = TYPE_K8S_RC_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("k8s.rc.label", val);
	}
	else if(STR_MATCH("k8s.rs.label") &&
		!STR_MATCH("k8s.rs.labels"))
	{
		m_field_id = TYPE_K8S_RS_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("k8s.rs.label", val);
	}
	else if(STR_MATCH("k8s.svc.label") &&
		!STR_MATCH("k8s.svc.labels"))
	{
		m_field_id = TYPE_K8S_SVC_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("k8s.svc.label", val);
	}
	else if(STR_MATCH("k8s.ns.label") &&
		!STR_MATCH("k8s.ns.labels"))
	{
		m_field_id = TYPE_K8S_NS_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("k8s.ns.label", val);
	}
	else if(STR_MATCH("k8s.deployment.label") &&
		!STR_MATCH("k8s.deployment.labels"))
	{
		m_field_id = TYPE_K8S_DEPLOYMENT_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("k8s.deployment.label", val);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
}

int32_t sinsp_filter_check_k8s::extract_arg(const string& fldname, const string& val)
{
	int32_t parsed_len = 0;

	if(val[fldname.size()] == '.')
	{
		size_t endpos;
		for(endpos = fldname.size() + 1; endpos < val.length(); ++endpos)
		{
			if(!isalnum(val[endpos])
				&& val[endpos] != '/'
				&& val[endpos] != '_'
				&& val[endpos] != '-'
				&& val[endpos] != '.')
			{
				break;
			}
		}

		parsed_len = (uint32_t)endpos;
		m_argname = val.substr(fldname.size() + 1, endpos - fldname.size() - 1);
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
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

uint8_t* sinsp_filter_check_k8s::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
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
	m_tstr.clear();
	// there is metadata we can pull from the container directly instead of the k8s apiserver
	const sinsp_container_info::ptr_t container_info =
		m_inspector->m_container_manager.get_container(tinfo->m_container_id);
	if(!tinfo->m_container_id.empty() && container_info && !container_info->m_labels.empty())
	{
		switch(m_field_id)
		{
		case TYPE_K8S_POD_NAME:
			if(container_info->m_labels.count("io.kubernetes.pod.name") > 0)
			{
				m_tstr = container_info->m_labels.at("io.kubernetes.pod.name");
				RETURN_EXTRACT_STRING(m_tstr);
			}
			break;
		case TYPE_K8S_NS_NAME:
			if(container_info->m_labels.count("io.kubernetes.pod.namespace") > 0)
			{
				m_tstr = container_info->m_labels.at("io.kubernetes.pod.namespace");
				RETURN_EXTRACT_STRING(m_tstr);
			}
			break;
		case TYPE_K8S_POD_ID:
			if(container_info->m_labels.count("io.kubernetes.pod.uid") > 0)
			{
				m_tstr = container_info->m_labels.at("io.kubernetes.pod.uid");
				RETURN_EXTRACT_STRING(m_tstr);
			}
			break;
		case TYPE_K8S_POD_LABEL:
		case TYPE_K8S_POD_LABELS:
			if(container_info->m_labels.count("io.kubernetes.sandbox.id") > 0)
			{
				std::string sandbox_container_id;
				sandbox_container_id = container_info->m_labels.at("io.kubernetes.sandbox.id");
				if(sandbox_container_id.size() > 12)
				{
					sandbox_container_id.resize(12);
				}
				const sinsp_container_info::ptr_t sandbox_container_info =
					m_inspector->m_container_manager.get_container(sandbox_container_id);
				if(sandbox_container_info && !sandbox_container_info->m_labels.empty())
				{
					if (m_field_id == TYPE_K8S_POD_LABEL && sandbox_container_info->m_labels.count(m_argname) > 0)
					{
						m_tstr = sandbox_container_info->m_labels.at(m_argname);
						RETURN_EXTRACT_STRING(m_tstr);
					}
					if (m_field_id == TYPE_K8S_POD_LABELS)
					{
						concatenate_container_labels(sandbox_container_info->m_labels, &m_tstr);
						RETURN_EXTRACT_STRING(m_tstr);
					}
				}

			}
			break;
		case TYPE_K8S_POD_IP:
			m_u32val = htonl(container_info->m_container_ip);
			char addrbuff[100];
			inet_ntop(AF_INET, &m_u32val, addrbuff, sizeof(addrbuff));
			m_tstr = addrbuff;
			RETURN_EXTRACT_STRING(m_tstr);
			break;
		case TYPE_K8S_POD_CNIRESULT:
			RETURN_EXTRACT_STRING(container_info->m_pod_cniresult);
			break;
		default:
			ASSERT(false);
			break;
		}
	}

	// all the rest of the fields are deprecated and return NULL since
	// we removed the k8s client from the inspector.
	return NULL;
}

