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

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_filtercheck.h>

class sinsp_filter_check_container : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CONTAINER_ID = 0,
		TYPE_CONTAINER_FULL_CONTAINER_ID,
		TYPE_CONTAINER_NAME,
		TYPE_CONTAINER_IMAGE,
		TYPE_CONTAINER_IMAGE_ID,
		TYPE_CONTAINER_TYPE,
		TYPE_CONTAINER_PRIVILEGED,
		TYPE_CONTAINER_MOUNTS,
		TYPE_CONTAINER_MOUNT,
		TYPE_CONTAINER_MOUNT_SOURCE,
		TYPE_CONTAINER_MOUNT_DEST,
		TYPE_CONTAINER_MOUNT_MODE,
		TYPE_CONTAINER_MOUNT_RDWR,
		TYPE_CONTAINER_MOUNT_PROPAGATION,
		TYPE_CONTAINER_IMAGE_REPOSITORY,
		TYPE_CONTAINER_IMAGE_TAG,
		TYPE_CONTAINER_IMAGE_DIGEST,
		TYPE_CONTAINER_HEALTHCHECK,
		TYPE_CONTAINER_LIVENESS_PROBE,
		TYPE_CONTAINER_READINESS_PROBE,
		TYPE_CONTAINER_START_TS,
		TYPE_CONTAINER_DURATION,
		TYPE_CONTAINER_IP_ADDR,
		TYPE_CONTAINER_CNIRESULT,
	};

	sinsp_filter_check_container();
	virtual ~sinsp_filter_check_container() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;

	const std::string& get_argstr() const;

protected:
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;

private:
	int32_t extract_arg(const std::string& val, size_t basename);

	std::string m_tstr;
	uint32_t m_u32val;
	int32_t m_argid;
	std::string m_argstr;
	int64_t m_s64val;
};
