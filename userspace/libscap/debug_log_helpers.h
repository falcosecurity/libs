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
#ifndef __DEBUG_LOG_HELPERS_H
#define __DEBUG_LOG_HELPERS_H

#include <libscap/scap_log.h>

#include <stdio.h>

#define scap_log(HANDLE, sev, ...) scap_log_impl(HANDLE->m_log_fn, sev, __VA_ARGS__)
#define scap_debug_log(HANDLE, ...) scap_log_impl(HANDLE->m_log_fn, FALCOSECURITY_LOG_SEV_DEBUG, __VA_ARGS__)

/**
 * If debug_log_fn has been established in the handle, call that function
 * to log a debug message.
 */
static inline void scap_log_impl(falcosecurity_log_fn log_fn, enum falcosecurity_log_severity sev, const char* fmt, ...)
{
	if(log_fn != NULL)
	{
		char buf[256];
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);

		log_fn("libscap", buf, sev);
	}
}

#endif /* __DEBUG_LOG_HELPERS_H */
