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

#pragma once

#include <libscap/engine/test_input/scap_test.h>
#include <libscap/scap_procs.h>

#define TEST_INPUT_ENGINE "test_input"

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_test_input_engine_params
	{
		scap_test_input_data* test_input_data; ///<  only used for testing scap consumers by supplying arbitrary test data.
	};

	struct scap_platform;
	struct scap_platform* scap_test_input_alloc_platform(proc_entry_callback proc_callback,
							     void* proc_callback_context);
#ifdef __cplusplus
};
#endif
