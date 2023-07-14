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

typedef struct _scap_agent_info scap_agent_info;
typedef struct _scap_machine_info scap_machine_info;

void scap_os_get_agent_info(scap_agent_info* agent_info);
int32_t scap_os_get_machine_info(scap_machine_info* machine_info, char* lasterr);

#ifdef __cplusplus
}
#endif