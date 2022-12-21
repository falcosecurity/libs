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
#ifndef __DEBUG_LOG_HELPERS_H
#define __DEBUG_LOG_HELPERS_H

#include <stdarg.h>

#define scap_debug_log(HANDLE, ...) scap_debug_log_impl(HANDLE->m_debug_log_fn, __VA_ARGS__)

/**
 * If debug_log_fn has been established in the handle, call that function
 * to log a debug message.
 */
static inline void scap_debug_log_impl(void(*debug_log_fn)(const char* msg), const char* fmt, ...)
{
	if (debug_log_fn != NULL)
	{
		char buf[256];
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);

		(*debug_log_fn)(buf);
	}
}

#endif /* __DEBUG_LOG_HELPERS_H */
