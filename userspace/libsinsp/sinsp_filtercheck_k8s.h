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

#include <libsinsp/sinsp_filtercheck.h>

class sinsp_filter_check_k8s : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_K8S_NS_NAME = 0,
		TYPE_K8S_POD_NAME,
		TYPE_K8S_POD_ID,
		TYPE_K8S_POD_UID,
		TYPE_K8S_POD_SANDBOX_ID,
		TYPE_K8S_POD_FULL_SANDBOX_ID,
		TYPE_K8S_POD_LABEL,
		TYPE_K8S_POD_LABELS,
		TYPE_K8S_POD_IP,
		TYPE_K8S_POD_CNIRESULT,
		// below fields are all deprecated
		TYPE_K8S_RC_NAME,
		TYPE_K8S_RC_ID,
		TYPE_K8S_RC_LABEL,
		TYPE_K8S_RC_LABELS,
		TYPE_K8S_SVC_NAME,
		TYPE_K8S_SVC_ID,
		TYPE_K8S_SVC_LABEL,
		TYPE_K8S_SVC_LABELS,
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
	virtual ~sinsp_filter_check_k8s() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;

protected:
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;

private:
	int32_t extract_arg(const std::string& fldname, const std::string& val);
	void concatenate_container_labels(const std::map<std::string, std::string>& labels, std::string* s);
	std::string m_argname;
	std::string m_tstr;
	uint32_t m_u32val;
};
