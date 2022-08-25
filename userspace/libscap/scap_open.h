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
extern "C" {
#endif

/*!
  \brief Arguments for scap_open
*/
typedef enum {
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
#ifdef HAS_ENGINE_MODERN_BPF
	/*!
	 * Read system call data from the underlying operating system using a modern
	 * bpf probe.
	 */
	SCAP_MODE_MODERN_BPF,
#endif
} scap_mode_t;

/*!
  \brief Argument for scap_open
  Set any PPM_SC syscall idx to true to enable its tracing at driver level,
  otherwise syscalls are not traced (so called "uninteresting syscalls").
*/
typedef struct {
	bool ppm_sc[PPM_SC_MAX];
} interesting_ppm_sc_set;

/*!
  \brief Argument for scap_open
  Set any tracepoint idx to true to enable its tracing at driver level,
  otherwise a tp is not attached (so called "uninteresting tracepoint").
*/
typedef struct {
	bool tp[TP_VAL_MAX];
} interesting_tp_set;

typedef struct scap_open_args
{
	scap_mode_t mode;
	int fd; // If non-zero, will be used instead of fname.
	const char* fname; ///< The name of the file to open. NULL for live captures.
	uint32_t fbuffer_size; ///< If non-zero, offline captures will read from file using a buffer of this size.
	proc_entry_callback proc_callback; ///< Callback to be invoked for each thread/fd that is extracted from /proc, or NULL if no callback is needed.
	void* proc_callback_context; ///< Opaque pointer that will be included in the calls to proc_callback. Ignored if proc_callback is NULL.
	bool import_users; ///< true if the user list should be created when opening the capture.
	uint64_t start_offset; ///< Used to start reading a capture file from an arbitrary offset. This is leveraged when opening merged files.
	const char *bpf_probe; ///< The name of the BPF probe to open. If NULL, the kernel driver will be used.
	const char *suppressed_comms[SCAP_MAX_SUPPRESSED_COMMS]; ///< A list of processes (comm) for which no
	// events should be returned, with a trailing NULL value.
	// You can provide additional comm
	// values via scap_suppress_events_comm().
	bool udig; ///< If true, UDIG will be used for event capture.
	bool gvisor; //< If true, gVisor will be used for event capture
	const char *gvisor_root_path; ///< When using gvisor, the root path used by runsc commands
	const char *gvisor_config_path; ///< When using gvisor, the path to the configuration file

	interesting_ppm_sc_set *ppm_sc_of_interest; ///< Leave it NULL to collect all supported syscalls
	interesting_tp_set *tp_of_interest; ///< Leave it NULL to attach all supported tracepoints

	scap_source_plugin* input_plugin; ///< use this to configure a source plugin that will produce the events for this capture
	char* input_plugin_params; ///< optional parameters string for the source plugin pointed by src_plugin

	scap_test_input_data* test_input_data; ///< only used for testing scap consumers by supplying arbitrary test data
}scap_open_args;

#ifdef __cplusplus
}
#endif
