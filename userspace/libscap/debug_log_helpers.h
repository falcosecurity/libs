/*

Copyright (c) 2021 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __DEBUG_LOG_HELPERS_H
#define __DEBUG_LOG_HELPERS_H

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
