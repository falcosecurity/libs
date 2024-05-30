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

#ifdef __cplusplus
extern "C" {
#endif

// this is passed by value everywhere so keep it small
// it only contains a pointer to a struct containing the engine-specific bits
struct scap_engine_handle {
	void* m_handle;
};

#ifdef __cplusplus
}
#endif
