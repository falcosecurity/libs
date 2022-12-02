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

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "plugin_info.h"
#include "scap_limits.h"
#include "scap_procs.h"
#include "scap_test.h"
#include "../../driver/ppm_events_public.h"
#include "../../driver/ppm_tp.h"

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

	/*!
	 * \brief Argument for scap_open
	 * Set any tracepoint idx to true to enable its tracing at driver level,
	 * otherwise a tp is not attached (so called "uninteresting tracepoint").
	 */
	typedef struct
	{
		bool tp[TP_VAL_MAX];
	} interesting_tp_set;

	typedef struct scap_open_args
	{
		const char* engine_name;				 ///< engine name ("kmod", "bpf", ...).
		scap_mode_t mode;					 ///< scap-mode required by the engine.
		proc_entry_callback proc_callback;			 ///< Callback to be invoked for each thread/fd that is extracted from /proc, or NULL if no callback is needed.
		void* proc_callback_context;				 ///< Opaque pointer that will be included in the calls to proc_callback. Ignored if proc_callback is NULL.
		bool import_users;					 ///< true if the user list should be created when opening the capture.
		const char* suppressed_comms[SCAP_MAX_SUPPRESSED_COMMS]; ///< A list of processes (comm) for which no
									 // events should be returned, with a trailing NULL value.
									 // You can provide additional comm
									 // values via scap_suppress_events_comm().
		interesting_ppm_sc_set ppm_sc_of_interest; ///< syscalls of interest.
		interesting_tp_set tp_of_interest; ///< tp of interest. If left empty, no tracepoints will be attached
		void(*debug_log_fn)(const char* msg); //< Function which SCAP may use to log a debug message
		void* engine_params;			   ///< engine-specific params.
	} scap_open_args;

#ifdef __cplusplus
}
#endif
