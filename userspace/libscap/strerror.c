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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "scap.h"

#ifdef _WIN32
#define strerror_r(errnum, buf, size) strerror_s(buf, size, errnum)
#endif

int32_t scap_errprintf_unchecked(char *buf, int errnum, const char* fmt, ...)
{
	int len;

	va_list va;
	va_start(va, fmt);
	// no error, just print the message
	len = vsnprintf(buf, SCAP_LASTERR_SIZE, fmt, va);
	va_end(va);

	if (errnum > 0 && len < SCAP_LASTERR_SIZE - 1)
	{
		char err_buf[SCAP_LASTERR_SIZE] = "unknown error";
		strerror_r(errnum, err_buf, sizeof(err_buf));
		snprintf(buf + len, SCAP_LASTERR_SIZE - len, ": %s", err_buf);
	}

	// so you can return scap_errprintf(...) directly
	return SCAP_FAILURE;
}
