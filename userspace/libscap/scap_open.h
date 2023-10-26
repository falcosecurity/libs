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

#include <stdint.h>
#include <stdbool.h>

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "scap_limits.h"
#include "scap_procs.h"
#include "../../driver/ppm_events_public.h"
#include "falcosecurity/log.h"

#ifdef __cplusplus
extern "C"
{
#endif

	/*!
	  \brief Scap possible modes
	*/
	typedef enum
	{
		/*!
		 * Default value that mostly exists so that sinsp can have a valid value
		 * before it is initialized.
		 */
		SCAP_MODE_NONE = 0,
		/*!
		 * Read system call data from a capture file.
		 */
		SCAP_MODE_CAPTURE,
		/*!
		 * Read system call data from the underlying operating system.
		 */
		SCAP_MODE_LIVE,
		/*!
		 * Do not read system call data. If next is called, a dummy event is
		 * returned.
		 */
		SCAP_MODE_NODRIVER,
		/*!
		 * Do not read system call data. Events come from the configured input plugin.
		 */
		SCAP_MODE_PLUGIN,
		/*!
		 * Read system call and event data from the test event generator.
		 * Do not attempt to query the underlying system.
		 */
		SCAP_MODE_TEST,
	} scap_mode_t;

	/*!
	 * \brief Argument for scap_open
	 * Set any PPM_SC syscall idx to true to enable its tracing at driver level,
	 * otherwise syscalls are not traced (so called "uninteresting syscalls").
	 */
	typedef struct
	{
		bool ppm_sc[PPM_SC_MAX];
	} interesting_ppm_sc_set;

	typedef struct scap_open_args
	{
		const char* engine_name;				 ///< engine name ("kmod", "bpf", ...).
		scap_mode_t mode;					 ///< scap-mode required by the engine.
		bool import_users;					 ///< true if the user list should be created when opening the capture.
		interesting_ppm_sc_set ppm_sc_of_interest; ///< syscalls of interest.
                falcosecurity_log_fn log_fn; //< Function which SCAP may use to log messages
		uint64_t proc_scan_timeout_ms; //< Timeout in msec, after which so-far-successful scan of /proc should be cut short with success return
		uint64_t proc_scan_log_interval_ms; //< Interval for logging progress messages from /proc scan
		void* engine_params;			   ///< engine-specific params.
	} scap_open_args;

#ifdef __cplusplus
}
#endif
