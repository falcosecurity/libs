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

#include <libsinsp/sinsp.h>
#include <gtest/gtest.h>

#include "filter_compiler.h"

TEST(sinsp_filter_check, bcontains_bstartswith)
{
	// craft a fake read exit event containing the "hello" string
	char scap_evt_err[2048];
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};
	uint8_t scap_evt_buf[2048];
	size_t evt_size;
	scap_sized_buffer scap_evt;
	scap_evt.buf = (void*) &scap_evt_buf[0];
	scap_evt.size = (size_t) sizeof(scap_evt_buf);
	if (scap_event_encode_params(
		scap_evt, &evt_size, scap_evt_err, PPME_SYSCALL_READ_X, 3, (int64_t) 0,
		scap_const_sized_buffer{&read_buf[0],sizeof(read_buf)}) != SCAP_SUCCESS)
	{
		FAIL() << "could not create scap event";
	}
	sinsp_evt evt;
	evt.init((uint8_t*) scap_evt.buf, 0); // 68656c6c6f

	// test filters with bcontains
	filter_compile(NULL, "evt.buffer bcontains");
	filter_compile(NULL, "evt.buffer bcontains 2");
	filter_compile(NULL, "evt.buffer bcontains 2g");
	filter_run(&evt, true, "evt.buffer bcontains 68656c6c6f");
	filter_run(&evt, true, "evt.buffer bcontains 656c6C");
	filter_run(&evt, false, "evt.buffer bcontains 20");
	filter_run(&evt, false, "evt.buffer bcontains 656c6cAA");

	// test filters with bstartswith
	filter_compile(NULL, "evt.buffer bstartswith");
	filter_compile(NULL, "evt.buffer bstartswith 2");
	filter_compile(NULL, "evt.buffer bstartswith 2g");
	filter_run(&evt, true, "evt.buffer bstartswith 68");
	filter_run(&evt, true, "evt.buffer bstartswith 68656c6c6f");
	filter_run(&evt, false, "evt.buffer bstartswith 65");
	filter_run(&evt, false, "evt.buffer bstartswith 656c6C");
	filter_run(&evt, false, "evt.buffer bstartswith 20");
	filter_run(&evt, false, "evt.buffer bstartswith 656c6cAA");
}
