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
#include <set>
#include <string>

#include <libscap/engine/gvisor/gvisor.h>

namespace scap_gvisor {

uint32_t platform::get_threadinfos(uint64_t *n, const scap_threadinfo **tinfos)
{
	runsc::result sandboxes_res = runsc::list(m_root_path);
	std::vector<std::string> &sandboxes = sandboxes_res.output;

	m_threadinfos_threads.clear();
	m_threadinfos_fds.clear();

	for(const auto &sandbox: sandboxes)
	{
		runsc::result procfs_res = runsc::trace_procfs(m_root_path, sandbox);

		// We may be unable to read procfs for several reasons, e.g. the pause container on k8s or a sandbox that was
		// being removed
		if(procfs_res.error != 0)
		{
			continue;
		}

		for(const auto &line: procfs_res.output)
		{
			// skip first line of the output and empty lines
			if(line.find("PROCFS DUMP") != std::string::npos ||
			   std::all_of(line.begin(), line.end(), isspace))
			{
				continue;
			}

			uint32_t id = get_numeric_sandbox_id(sandbox);
			parsers::procfs_result res = parsers::parse_procfs_json(line, id);
			if(res.status != SCAP_SUCCESS)
			{
				*tinfos = NULL;
				*n = 0;
				snprintf(m_lasterr, SCAP_LASTERR_SIZE, "%s", res.error.c_str());
				return res.status;
			}

			m_threadinfos_threads.emplace_back(res.tinfo);
			m_threadinfos_fds[res.tinfo.tid] = res.fdinfos;
		}
	}

	*tinfos = m_threadinfos_threads.data();
	*n = m_threadinfos_threads.size();

	return SCAP_SUCCESS;
}

uint32_t platform::get_fdinfos(const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos)
{
	*n = m_threadinfos_fds[tinfo->tid].size();
	if(*n != 0)
	{
		*fdinfos = m_threadinfos_fds[tinfo->tid].data();
	}

	return SCAP_SUCCESS;
}

uint32_t platform::get_numeric_sandbox_id(std::string sandbox_id)
{
	if (auto it = m_sandbox_ids.find(sandbox_id); it != m_sandbox_ids.end())
	{
		return it->second;
	}

	// If an entry does not exist we need to generate an unique numeric ID for the sandbox
	std::set<uint32_t> ids_in_use;
	for(auto const &it : m_sandbox_ids)
	{
		ids_in_use.insert(it.second);
	}

	uint32_t id;

	// Create a "seed" initial number, this could be any number and it's an implementation detail
	// but having something that resembles the sandbox ID helps with debugging
	try
	{
		// If it's a hex number take the 32 most significant bits
		std::string container_id_32 = sandbox_id.length() > 8 ? sandbox_id.substr(0, 7) : sandbox_id;
		id = stoul(container_id_32, nullptr, 16);
	} catch (...)
	{
		// If not, take the character representation of the first 4 bytes

		// Ensure the string is at least 4 characters (meaning >= 4 bytes)
		if (sandbox_id.size() < 4)
		{
			sandbox_id.append(std::string(4 - sandbox_id.size(), '0'));
		}

		const char *chars = sandbox_id.c_str();
		id = chars[3] | chars[2] << 8 | chars[1] << 16 | chars[0] << 24;
	}
	
	// Ensure ID is not 0
	if (id == 0)
	{
		id = 1;
	}

	// Find the first available ID
	while (ids_in_use.find(id) != ids_in_use.end())
	{
		id += 1;
		if (id == 0)
		{
			id = 1;
		}
	}

	m_sandbox_ids[sandbox_id] = id;

	return id;
}

void platform::release_sandbox_id(std::string sandbox_id)
{
	m_sandbox_ids.erase(sandbox_id);
}

}
