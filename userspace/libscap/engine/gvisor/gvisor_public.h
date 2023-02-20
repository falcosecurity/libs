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

#define GVISOR_ENGINE "gvisor"

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_gvisor_engine_params
	{
		const char* gvisor_root_path;	///< When using gvisor, the root path used by runsc commands
		const char* gvisor_config_path; ///< When using gvisor, the path to the configuration file

		bool no_events; //< Pinky swear we don't want any event from it (i.e. next will always fail, just have proc scan)
		int gvisor_epoll_timeout;	///< When using gvisor, the timeout to wait for a new event
	};

	struct scap_platform;
	struct scap_platform* scap_gvisor_alloc_platform();

#ifdef __cplusplus
};
#endif
