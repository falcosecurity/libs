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

#include "scap.h"
#include <stdarg.h>

/**
 * If debug_log_fn has been established in the handle, call that function
 * to log a debug message.
 */
static void scap_debug_log(scap_t* handle, const char* fmt, ...)
{
	if (handle->m_debug_log_fn != NULL)
	{
		char buf[256];
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);

		(*handle->m_debug_log_fn)(buf);
	}
}

#endif /* __DEBUG_LOG_HELPERS_H */
