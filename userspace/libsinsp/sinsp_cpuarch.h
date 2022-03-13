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

// Set of CPU architecture-specific thread event bugs
#define LIBSINSP_CPUARCH_THREAD_EVENT_BUG_UNRELIABLE_CLONE_EXIT_EVENT_TO_CHILD    (1 << 0)
#define LIBSINSP_CPUARCH_THREAD_EVENT_BUG_UNRELIABLE_EXECVE_EXIT_EVENT_ON_SUCCESS (1 << 1)

#ifdef __aarch64__
#define LIBSINSP_CPUARCH_THREAD_EVENT_BUGS                                               ( \
               LIBSINSP_CPUARCH_THREAD_EVENT_BUG_UNRELIABLE_CLONE_EXIT_EVENT_TO_CHILD |    \
               LIBSINSP_CPUARCH_THREAD_EVENT_BUG_UNRELIABLE_EXECVE_EXIT_EVENT_ON_SUCCESS )
#else
#define LIBSINSP_CPUARCH_THREAD_EVENT_BUGS 0
#endif
