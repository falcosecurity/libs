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

#include "filler_test.h"

#include <cstring>

filler_test::filler_test(ppm_event_type event_type):
	m_event_type(event_type)
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

int filler_test::do_test(
	unsigned long retval,
	unsigned long arg0,
	unsigned long arg1,
	unsigned long arg2,
	unsigned long arg3,
	unsigned long arg4,
	unsigned long arg5)
{
	// This is the set of registers
	// for x86_64, see (man 2 syscall)
	// to support other architectures
	struct pt_regs regs;
	regs.di = arg0;
	regs.si = arg1;
	regs.dx = arg2;
	regs.r10 = arg3;
	regs.r8 = arg4;
	regs.r9 = arg5;

	struct sys_exit_args ctx
	{
		.regs = reinterpret_cast<unsigned long>(&regs),
		.ret = retval,
	};
	return do_test_single_filler(m_filler_name.c_str(), ctx, m_event_type, m_scratch);
}

filler_test::~filler_test()
{
	free(m_scratch);
}

unsigned long filler_test::get_retval()
{
	return m_scratch[m_scratch_header_offset];
}

unsigned long filler_test::get_argument(uint32_t off)
{
	return m_scratch[m_scratch_header_offset + off];
}

unsigned long filler_test::get_argument(void* to, uint32_t off, unsigned long n)
{
	memcpy(to, m_scratch + m_scratch_header_offset + off, n);
	return n;
}
