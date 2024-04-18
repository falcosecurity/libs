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

#include <sinsp_with_test_input.h>
#include "filter_compiler.h"


TEST_F(sinsp_with_test_input, pmatch)
{
	add_default_init_thread();

	open_inspector();

	int64_t fd = 1;
	sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, fd, "/opt/dir/subdir/file.txt", 0, 0, 0, (uint64_t) 0);

	filter_run(evt, true, "fd.name pmatch (/opt/dir)");
	filter_run(evt, true, "fd.name pmatch (/opt/dir/subdir)");
	filter_run(evt, false, "fd.name pmatch (/opt/dir2)");
	filter_run(evt, true, "fd.name pmatch (/opt/dir, /opt/dir2)");
	filter_run(evt, false, "fd.name pmatch (/opt/dir3, /opt/dir2)");
	filter_run(evt, true, "fd.name pmatch (/opt/*)");
	filter_run(evt, true, "fd.name pmatch (/opt/*/subdir)");
	// In Windows systems, the function used to perform path matching differs
	// from linux and macos: instead of `fnmatch` is used `PathMatchSpecA`
	// (from the Windows API); this function reflects the Windows behaviour
	// in path matching (case insentive...). Given that we need to exclude
	// some tests.
#if !defined(_WIN32)
	filter_run(evt, true, "fd.name pmatch (/opt/di?/subdir)");
	filter_run(evt, false, "fd.name pmatch (/opt/dii?/subdir)");
	filter_run(evt, true, "fd.name pmatch (/opt/di[r]/subdir)");
	filter_run(evt, false, "fd.name pmatch (/opt/di[!r]/subdir)");
	filter_run(evt, false, "fd.name pmatch (/opt/di[t]/subdir)");
#endif
	filter_run(evt, false, "fd.name pmatch (/opt/di/subdir)");
	filter_run(evt, false, "fd.name pmatch (/opt/*/subdir2)");
	filter_run(evt, true, "fd.name pmatch (/opt/*/*)");
	filter_run(evt, false, "fd.name pmatch (/opt/*/*/subsubdir)");
}
