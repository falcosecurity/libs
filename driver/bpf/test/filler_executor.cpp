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

#include "filler_executor.h"

#include <cstring>

filler_executor::filler_executor(ppm_event_type event_type, struct sys_exit_args ctx):
	m_event_type(event_type), m_ctx(ctx)
{
	m_scratch = (char*)malloc(sizeof(char) * SCRATCH_SIZE_HALF);
	m_filler_nparams = g_event_info[m_event_type].nparams;
	m_scratch_header_offset = sizeof(struct ppm_evt_hdr) + sizeof(__u16) * m_filler_nparams;

	std::string filler_name = "bpf_sys_";
	filler_name.append(g_event_info[m_event_type].name);

	if(PPME_IS_ENTER(m_event_type))
	{
		filler_name.append("_e");
	}
	else
	{
		filler_name.append("_x");
	}
	m_filler_name = filler_name;
}

int filler_executor::do_test()
{
	return do_test_single_filler(m_filler_name.c_str(), m_ctx, m_event_type, m_scratch);
}

filler_executor::~filler_executor()
{
	free(m_scratch);
}

unsigned long filler_executor::get_retval()
{
	return m_scratch[m_scratch_header_offset];
}

unsigned long filler_executor::get_argument(uint32_t off)
{
	return m_scratch[m_scratch_header_offset + off];
}

unsigned long filler_executor::get_argument(void* to, uint32_t off, unsigned long n)
{
	memcpy(to, m_scratch + m_scratch_header_offset + off, n);
	return n;
}
