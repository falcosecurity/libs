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

#include <libscap/engine/source_plugin/source_plugin_public.h>

void get_plugin_api_sample_syscall_source(plugin_api& out);
void get_plugin_api_sample_syscall_extract(plugin_api& out);
void get_plugin_api_sample_syscall_parse(plugin_api& out);
void get_plugin_api_sample_syscall_async(plugin_api& out);
void get_plugin_api_sample_plugin_source(plugin_api& out);
void get_plugin_api_sample_plugin_extract(plugin_api& out);
void get_plugin_api_sample_syscall_tables(plugin_api& out);
void get_plugin_api_sample_syscall_subtables(plugin_api& out);
void get_plugin_api_sample_syscall_subtables_array(plugin_api& out);
void get_plugin_api_sample_metrics(plugin_api& out);
void get_plugin_api_sample_routines(plugin_api& out);
