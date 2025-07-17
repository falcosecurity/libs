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

typedef void (*proc_table_refresh_start)(void* context);
typedef void (*proc_table_refresh_end)(void* context);

/*!
  @brief Full set of callbacks for proc table refresh
  @param refresh_start: callback to be called at the start of the proc table refresh
  @param refresh_end: callback to be called at the end of the proc table refresh
  @param proc_callback: callback to be called for each thread or fd found
  @param callback_context: context to be passed to the proc_callback
*/
typedef struct scap_proc_callbacks {
	proc_table_refresh_start m_refresh_start_cb;
	proc_table_refresh_end m_refresh_end_cb;
	proc_entry_callback m_proc_entry_cb;
	void* m_callback_context;
} scap_proc_callbacks;

void default_refresh_start_end_callback(void* context);

int32_t default_proc_entry_callback(void* context,
                                    char* error,
                                    int64_t tid,
                                    scap_threadinfo* tinfo,
                                    scap_fdinfo* fdinfo,
                                    scap_threadinfo** new_tinfo);

struct scap_proclist {
	scap_proc_callbacks m_callbacks;
	scap_threadinfo* m_proclist;
};

void init_proclist(struct scap_proclist* proclist, scap_proc_callbacks callbacks);

#ifdef __cplusplus
}
#endif
