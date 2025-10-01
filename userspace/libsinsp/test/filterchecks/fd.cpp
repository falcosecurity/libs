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

#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, FD_FILTER_extract_from_null_type_filename) {
	add_default_init_thread();

	open_inspector();

	const std::string path = "/home/file.txt";

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_OPEN_X,
	                                      6,
	                                      (int64_t)-1,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                      (uint32_t)0,
	                                      (uint32_t)0,
	                                      (uint64_t)0);
	ASSERT_FALSE(field_has_value(evt, "fd.filename"));
}
