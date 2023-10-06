#pragma once

enum falcosecurity_log_severity
{
	FALCOSECURITY_LOG_SEV_FATAL = 1,
	FALCOSECURITY_LOG_SEV_CRITICAL = 2,
	FALCOSECURITY_LOG_SEV_ERROR = 3,
	FALCOSECURITY_LOG_SEV_WARNING = 4,
	FALCOSECURITY_LOG_SEV_NOTICE = 5,
	FALCOSECURITY_LOG_SEV_INFO = 6,
	FALCOSECURITY_LOG_SEV_DEBUG = 7,
	FALCOSECURITY_LOG_SEV_TRACE = 8,
};

typedef void (*falcosecurity_log_fn)(const char* component, const char* msg, const enum falcosecurity_log_severity sev);
