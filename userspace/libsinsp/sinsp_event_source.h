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

#include <cstddef>

/**
 * @brief The dummy event source index for unknown event sources.
 */
constexpr size_t sinsp_no_event_source_idx = -1;

/**
 * @brief The dummy event source name for unknown event sources.
 */
constexpr const char* sinsp_no_event_source_name = NULL;

/**
 * @brief The name of the event source implemented by libsinsp itself.
 */
constexpr const char* sinsp_syscall_event_source_name = "syscall";
