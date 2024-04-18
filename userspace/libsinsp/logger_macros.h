// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#define SINSP_LOG_(severity, fmt, ...)                                         \
	do                                                                     \
	{                                                                      \
		if(libsinsp_logger()->is_enabled(severity))                              \
		{                                                              \
			libsinsp_logger()->format((severity), ("" fmt), ##__VA_ARGS__);  \
		}                                                              \
	}                                                                      \
	while(false)

#define SINSP_LOG_STR_(severity, msg)                                          \
	do                                                                     \
	{                                                                      \
		if(libsinsp_logger()->is_enabled(severity))                              \
		{                                                              \
			libsinsp_logger()->log((msg), (severity));                       \
		}                                                              \
	}                                                                      \
	while(false)

#define SINSP_FATAL(...)    SINSP_LOG_(sinsp_logger::SEV_FATAL,    ##__VA_ARGS__)
#define SINSP_CRITICAL(...) SINSP_LOG_(sinsp_logger::SEV_CRITICAL, ##__VA_ARGS__)
#define SINSP_ERROR(...)    SINSP_LOG_(sinsp_logger::SEV_ERROR,    ##__VA_ARGS__)
#define SINSP_WARNING(...)  SINSP_LOG_(sinsp_logger::SEV_WARNING,  ##__VA_ARGS__)
#define SINSP_NOTICE(...)   SINSP_LOG_(sinsp_logger::SEV_NOTICE,   ##__VA_ARGS__)
#define SINSP_INFO(...)     SINSP_LOG_(sinsp_logger::SEV_INFO,     ##__VA_ARGS__)
#define SINSP_DEBUG(...)    SINSP_LOG_(sinsp_logger::SEV_DEBUG,    ##__VA_ARGS__)
#define SINSP_TRACE(...)    SINSP_LOG_(sinsp_logger::SEV_TRACE,    ##__VA_ARGS__)

#define SINSP_STR_FATAL(str)     SINSP_LOG_STR_(sinsp_logger::SEV_FATAL,   (str))
#define SINSP_STR_CRITICAL(str)  SINSP_LOG_STR_(sinsp_logger::SEV_CRITICAL,(str))
#define SINSP_STR_ERROR(str)     SINSP_LOG_STR_(sinsp_logger::SEV_ERROR,   (str))
#define SINSP_STR_WARNING(str)   SINSP_LOG_STR_(sinsp_logger::SEV_WARNING, (str))
#define SINSP_STR_NOTICE(str)    SINSP_LOG_STR_(sinsp_logger::SEV_NOTICE,  (str))
#define SINSP_STR_INFO(str)      SINSP_LOG_STR_(sinsp_logger::SEV_INFO,    (str))
#define SINSP_STR_DEBUG(str)     SINSP_LOG_STR_(sinsp_logger::SEV_DEBUG,   (str))
#define SINSP_STR_TRACE(str)     SINSP_LOG_STR_(sinsp_logger::SEV_TRACE,   (str))

#if _DEBUG
#    define DBG_SINSP_FATAL(...)    SINSP_FATAL(   __VA_ARGS__)
#    define DBG_SINSP_CRITICAL(...) SINSP_CRITICAL(__VA_ARGS__)
#    define DBG_SINSP_ERROR(...)    SINSP_ERROR(   __VA_ARGS__)
#    define DBG_SINSP_WARNING(...)  SINSP_WARNING( __VA_ARGS__)
#    define DBG_SINSP_NOTICE(...)   SINSP_NOTICE(  __VA_ARGS__)
#    define DBG_SINSP_INFO(...)     SINSP_INFO(    __VA_ARGS__)
#    define DBG_SINSP_DEBUG(...)    SINSP_DEBUG(   __VA_ARGS__)
#    define DBG_SINSP_TRACE(...)    SINSP_TRACE(   __VA_ARGS__)

#    define DBG_SINSP_STR_FATAL(str)     SINSP_STR_FATAL(str)
#    define DBG_SINSP_STR_CRITICAL(str)  SINSP_STR_CRITICAL(str)
#    define DBG_SINSP_STR_ERROR(str)     SINSP_STR_ERROR(str)
#    define DBG_SINSP_STR_WARNING(str)   SINSP_STR_WARNING(str)
#    define DBG_SINSP_STR_NOTICE(str)    SINSP_STR_NOTICE(str)
#    define DBG_SINSP_STR_INFO(str)      SINSP_STR_INFO(str)
#    define DBG_SINSP_STR_DEBUG(str)     SINSP_STR_DEBUG(str)
#    define DBG_SINSP_STR_TRACE(str)     SINSP_STR_TRACE(str)
#else
#    define DBG_SINSP_FATAL(fmt, ...)
#    define DBG_SINSP_CRITICAL(fmt, ...)
#    define DBG_SINSP_ERROR(fmt, ...)
#    define DBG_SINSP_WARNING(fmt, ...)
#    define DBG_SINSP_NOTICE(fmt, ...)
#    define DBG_SINSP_INFO(fmt, ...)
#    define DBG_SINSP_DEBUG(fmt, ...)
#    define DBG_SINSP_TRACE(fmt, ...)

#    define DBG_SINSP_STR_FATAL(str)
#    define DBG_SINSP_STR_CRITICAL(str)
#    define DBG_SINSP_STR_ERROR(str)
#    define DBG_SINSP_STR_WARNING(str)
#    define DBG_SINSP_STR_NOTICE(str)
#    define DBG_SINSP_STR_INFO(str)
#    define DBG_SINSP_STR_DEBUG(str)
#    define DBG_SINSP_STR_TRACE(str)
#endif
