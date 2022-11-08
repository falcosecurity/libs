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

#include <stdbool.h>
#include "../../ringbuffer/devset.h"

struct scap;

struct udig_engine
{
	struct scap_device_set m_dev_set;

	char* m_lasterr;
	bool m_udig_capturing;
#ifdef _WIN32
	HANDLE m_win_buf_handle;
	HANDLE m_win_descs_handle;
#endif
};
