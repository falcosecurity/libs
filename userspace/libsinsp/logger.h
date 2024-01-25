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

#include <libsinsp/logger_macros.h>
#include <libsinsp/sinsp_public.h>
#include <libscap/scap_log.h>

#include <atomic>
#include <string>

/**
 * Component logging API.  This API exposes the ability to log to a
 * variety of log sinks.  sinsp_logger will use only one enabled log* sink;
 * if multiple are enabled, then it will use the first available one it
 * finds.  The order in which log sinks is considered is: (1) a registered
 * callback function, (2) a registered file, (3) standard output, and
 * (4) standard error.
 */
class SINSP_PUBLIC sinsp_logger
{
public:
	enum severity
	{
		SEV_FATAL = FALCOSECURITY_LOG_SEV_FATAL,
		SEV_CRITICAL = FALCOSECURITY_LOG_SEV_CRITICAL,
		SEV_ERROR = FALCOSECURITY_LOG_SEV_ERROR,
		SEV_WARNING = FALCOSECURITY_LOG_SEV_WARNING,
		SEV_NOTICE = FALCOSECURITY_LOG_SEV_NOTICE,
		SEV_INFO = FALCOSECURITY_LOG_SEV_INFO,
		SEV_DEBUG = FALCOSECURITY_LOG_SEV_DEBUG,
		SEV_TRACE = FALCOSECURITY_LOG_SEV_TRACE,
	};
	const static severity SEV_MIN = SEV_FATAL;
	const static severity SEV_MAX = SEV_TRACE;

	using callback_t = void (*)(std::string&& str, severity sev);

	const static uint32_t OT_NONE;
	const static uint32_t OT_STDOUT;
	const static uint32_t OT_STDERR;
	const static uint32_t OT_FILE;
	const static uint32_t OT_CALLBACK;
	const static uint32_t OT_NOTS;
	const static uint32_t OT_ENCODE_SEV;

	/**
	 * Get the currently configured output type, which includes the
	 * configured output sinks as well as whether timestamps are enabled
	 * or not.
	 */
	uint32_t get_log_output_type() const;

	/** Enable the standard output log sink. */
	void add_stdout_log();

	/** Enable the standard error log sink. */
	void add_stderr_log();

	/**
	 * Enable the file log sink.
	 *
	 * @param[in] filename The filename to which sinsp_logger should write
	 *                     logs.
	 */
	void add_file_log(const std::string& filename);

	/** Disables tagging logs with the current timestamp. */
	void disable_timestamps();

	/** Adds encoded severity to log messages */
	void add_encoded_severity();

	/**
	 * Registered the given callback as the logging callback.
	 *
	 * Note: the given callback must be thread-safe.
	 */
	void add_callback_log(callback_t callback);

	/** Deregister any registered logging callbacks.  */
	void remove_callback_log();

	/**
	 * Set the minimum severity of logs that this sinsp_logger will emit.
	 */
	void set_severity(severity sev);

	/**
	 * Returns the minimum severity of logs that this sinsp_logger
	 * will emit.
	 */
	severity get_severity() const;

	/**
	 * Returns true if logs generated at the given severity will be written
	 * to the logging sink, false otherwise.
	 *
	 * Note that this is intentionally inline.
	 */
	bool is_enabled(const severity sev) const { return (sev <= m_sev); }

	/**
	 * Returns true if the logger has at least one output configured.
	 *
	 * Note that this is intentionally inline.
	 */
	bool has_output() const { return m_flags != OT_NONE; }

	/**
	 * Emit the given msg to the configured log sink if the given sev
	 * is greater than or equal to the minimum configured logging severity.
	 */
	void log(std::string msg, severity sev = SEV_INFO);

	/**
	 * Write the given printf-style log message of the given severity
	 * with the given format to the configured log sink.
	 */
	void format(severity sev, const char* fmt, ...);

	/**
	 * Write the given printf-style log message of the given severity
	 * with the given format to the configured log sink.
	 *
	 * @returns a pointer to static thread-local storage containing the
	 *          formatted log message.
	 */
	const char* format_and_return(severity sev, const char* fmt, ...);

	/**
	 * Write the given printf-style log message of SEV_INFO severity
	 * with the given format to the configured log sink.
	 */
	void format(const char* fmt, ...);

	/** Sets `sev` to the decoded severity or SEV_MAX+1 for errors.
	 *  Returns the length of the severity string on success
	 *  and 0 in case of errors
	 */
	static size_t decode_severity(const std::string &s, severity& sev);

	/**
	 *  Reset the logger instance to its defaults.
	 */
	void reset();

	static sinsp_logger* instance();

private:
	/**
	 * Initialize this sinsp_logger with no output sinks enabled.
	 */
	sinsp_logger();
	~sinsp_logger();

	static sinsp_logger s_logger;

	/** Disable copy constructor and assignment operator */
	sinsp_logger(const sinsp_logger&) = delete;
	sinsp_logger& operator=(const sinsp_logger&) = delete;

	/** Returns true if the callback log sync is enabled, false otherwise. */
	bool is_callback() const;


	/** Returns a string containing encoded severity, for OT_ENCODE_SEV. */
	static const char* encode_severity(severity sev);
	std::atomic<FILE*> m_file;
	std::atomic<callback_t> m_callback;
	std::atomic<uint32_t> m_flags;
	std::atomic<severity> m_sev;
};

/*!
  \brief Get the logger instance.
*/
sinsp_logger* libsinsp_logger();

using sinsp_logger_callback = sinsp_logger::callback_t;
