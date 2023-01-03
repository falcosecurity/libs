/*
Copyright (C) 2021 The Falco Authors.

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

typedef struct scap scap_t;
typedef struct scap_threadinfo scap_threadinfo;
typedef struct scap_fdinfo scap_fdinfo;

typedef void (*proc_entry_callback)(void* context,
				    int64_t tid,
				    scap_threadinfo* tinfo,
				    scap_fdinfo* fdinfo);

struct scap_proclist
{
	proc_entry_callback m_proc_callback;
	void* m_proc_callback_context;

	scap_threadinfo* m_proclist;
};

#ifdef __cplusplus
}
#endif
