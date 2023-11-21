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

#include <libscap/engine/source_plugin/plugin_info.h>

#define SOURCE_PLUGIN_ENGINE "source_plugin"

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_source_plugin_engine_params
	{
		scap_source_plugin* input_plugin; ///< use this to configure a source plugin that will produce the events for this capture
		char* input_plugin_params;	  ///< optional parameters string for the source plugin pointed by src_plugin
	};

#ifdef __cplusplus
};
#endif
