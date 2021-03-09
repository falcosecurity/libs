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

#include <gtest.h>

extern "C"
{
#include "test_fillers.h"
}

// todo(fntlnz): do we really want to pass data or just what is needed?
// it may create confusion because the filler does not get data at all but ctx void ptr
// todo(fntlnz): finish this test and make the others
TEST(test_run_approach, basic)
{
	int err;

	struct pt_regs regs = {
		.di = 100,
	};

	struct sys_exit_args ctx
	{
		.regs = reinterpret_cast<unsigned long>(&regs),
		.ret = 110,
	};

	struct tail_context tail_ctx
	{
		.evt_type = PPME_SYSCALL_RENAMEAT2_X,
		.curarg = 0,
		.curoff = 0,
		.len = 0,
		.prev_res = 0,
	};

	struct sysdig_bpf_per_cpu_state state
	{
		.tail_ctx = tail_ctx
	};

	struct filler_data data
	{
		.ctx = &ctx,
		.state = &state,
	};

	std::string filler_name = "bpf_sys_renameat2_x";

	char *scratch = (char *)malloc(sizeof(char) * SCRATCH_SIZE_HALF);

	err = do_test_single_filler(filler_name.c_str(), data, scratch);
	int nparams = g_event_info[data.state->tail_ctx.evt_type].nparams;
	int header_offset = sizeof(struct ppm_evt_hdr) + sizeof(__u16) * nparams;

	ASSERT_EQ(err, 0);
	ASSERT_EQ((int) scratch[header_offset], 110);
	ASSERT_EQ((int) scratch[header_offset + sizeof(long)], 100);
}
