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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scap scap_t;
typedef struct scap_threadinfo scap_threadinfo;
typedef struct scap_fdinfo scap_fdinfo;

/*!
  @brief Callback function to be called for each thread or fd found

  @param context: the context passed in scap_open_args
  @param error: a buffer of SCAP_LASTERR_SIZE characters to store the error message in case of error
  @param tid: the thread id
  @param tinfo: the thread info
  @param fdinfo: the fd info, if any (NULL if adding a thread)
  @param new_tinfo: a pointer to a thread info pointer. If the callback returns a different thread
  info,

  @return SCAP_* status code

  *Note*: currently tinfo may be NULL if fdinfo is not NULL. This makes life harder for fd
  callbacks.

  Memory ownership rule: tinfo and fdinfo are owned by the caller and must not be freed or stored
  by the callback. The callback can return a different tinfo, which must not be freed or stored by
  the caller, but can be assumed to be valid at least until the next call to the callback.
*/

typedef int32_t (*proc_entry_callback)(void* context,
                                       char* error,
                                       int64_t tid,
                                       scap_threadinfo* tinfo,
                                       scap_fdinfo* fdinfo,
                                       scap_threadinfo** new_tinfo);

int32_t default_proc_entry_callback(void* context,
                                    char* error,
                                    int64_t tid,
                                    scap_threadinfo* tinfo,
                                    scap_fdinfo* fdinfo,
                                    scap_threadinfo** new_tinfo);

struct scap_proclist {
	proc_entry_callback m_proc_callback;
	void* m_proc_callback_context;

	scap_threadinfo* m_proclist;
};

void init_proclist(struct scap_proclist* proclist,
                   proc_entry_callback callback,
                   void* callback_context);

#ifdef __cplusplus
}
#endif
