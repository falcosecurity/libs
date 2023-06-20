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
#include "gvisor.h"

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

			parsers::procfs_result res = parsers::parse_procfs_json(line, sandbox);
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

}
