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

#include "filler_executor.h"

TEST(test_renameat2, basic)
{
	int err;
	uint32_t off;

	struct pt_regs regs;
	regs.di = -100;
	regs.si = (unsigned long)"oldpath";
	regs.dx = -100;
	regs.r10 = (unsigned long)"newpath";

	struct sys_exit_args ctx
	{
		.regs = reinterpret_cast<unsigned long>(&regs),
		.ret = 110,
	};

	auto fe = new filler_executor(PPME_SYSCALL_RENAMEAT2_X, ctx);
	err = fe->do_test();
	ASSERT_EQ(err, 0);

	auto ret = (unsigned long)fe->get_retval();
	ASSERT_EQ(ret, 110);
	off = sizeof(ret);

	auto olddirfd = (long)fe->get_argument(off);
	ASSERT_EQ(olddirfd, -100);
	off += sizeof(olddirfd);

	char oldpath[PPM_MAX_PATH_SIZE];
	fe->get_argument(&oldpath, off, PPM_MAX_PATH_SIZE);
	ASSERT_STREQ(oldpath, "oldpath");
	off += strlen(oldpath) + 1;

	auto newdirfd = (long)fe->get_argument(off);
	ASSERT_EQ(newdirfd, -100);
	off += sizeof(newdirfd);

	char newpath[PPM_MAX_PATH_SIZE];
	fe->get_argument(&newpath, off, PPM_MAX_PATH_SIZE);
	ASSERT_STREQ(newpath, "newpath");
}
