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

#include <stdio.h>

#include "scap.h"
#include "scap-int.h"
#include "ringbuffer/ringbuffer.h"

int32_t scap_next_kmod(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	return ringbuffer_next(&handle->m_dev_set, pevent, pcpuid);
}
