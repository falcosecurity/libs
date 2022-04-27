/*
Copyright (C) 2022 The Falco Authors.

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

#ifndef SCAP_HANDLE_T
#error "You need to define SCAP_HANDLE_T to a concrete type before including engine_handle.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// this is passed by value everywhere so keep it small
// it only contains a pointer to a struct containing the engine-specific bits
struct scap_engine_handle {
	SCAP_HANDLE_T* m_handle;
};

#ifdef __cplusplus
}
#endif
