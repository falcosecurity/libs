// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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
#include "convert_event_test.h"

// todo!: remove it when we will add the first example.
TEST_F(convert_event_test, tmp_example) {
	uint64_t ts = 12;
	int64_t tid = 25;

	// At the moment we don't have event managed by the converter so this should fail.
	assert_single_conversion_failure(create_safe_scap_event(ts, tid, PPME_SYSCALL_OPEN_E, 0));
}
