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

// IMPORTANT: if you plan to change of the following fields, remember to update SCAP_MAX_FIELD_SIZE
// to always be the maximum of all the others.
#define SCAP_MAX_PATH_SIZE 1024
#define SCAP_MAX_ARGS_SIZE 4096
#define SCAP_MAX_ENV_SIZE 4096
#define SCAP_MAX_CGROUPS_SIZE 4096
#define SCAP_MAX_FIELD_SIZE 4096

#define SCAP_IPV6_ADDR_LEN 16
