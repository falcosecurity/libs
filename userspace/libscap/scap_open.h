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

	typedef enum
	{
		UNKNOWN_ENGINE = 0,
		KMOD_ENGINE = 1,
		BPF_ENGINE = 2,
		UDIG_ENGINE = 3,
		NODRIVER_ENGINE = 4,
		SAVEFILE_ENGINE = 5,
		PLUGIN_ENGINE = 6,
		GVISOR_ENGINE = 7,
		MODERN_BPF_ENGINE = 8,
		TEST_INPUT_ENGINE = 9,
	} scap_engine_t;

	typedef struct scap_open_args
	{
		scap_engine_t engine;
		scap_mode_t mode;
		proc_entry_callback proc_callback;			 ///< Callback to be invoked for each thread/fd that is extracted from /proc, or NULL if no callback is needed.
		void* proc_callback_context;				 ///< Opaque pointer that will be included in the calls to proc_callback. Ignored if proc_callback is NULL.
		bool import_users;					 ///< true if the user list should be created when opening the capture.
		const char* suppressed_comms[SCAP_MAX_SUPPRESSED_COMMS]; ///< A list of processes (comm) for which no
									 // events should be returned, with a trailing NULL value.
									 // You can provide additional comm
									 // values via scap_suppress_events_comm().
		interesting_ppm_sc_set ppm_sc_of_interest; ///< syscall of interest

		union
		{
			struct
			{
				uint64_t single_buffer_dim; ///<  dim of a single shared buffer. Usually, we have one buffer for every online CPU.
			} kmod_args;

			struct
			{
				uint64_t single_buffer_dim; ///<  dim of a single shared buffer. Usually, we have one buffer for every online CPU.
				const char* bpf_probe;	    ///<  The path to the BPF probe object file.
			} bpf_args;

			struct
			{
				uint64_t single_buffer_dim; ///<  dim of a single shared buffer. Usually, we have one buffer for every online CPU.
			} udig_args;

			struct
			{
				int fd;		       ///< If non-zero, will be used instead of fname.
				const char* fname;     ///< The name of the file to open.
				uint64_t start_offset; ///< Used to start reading a capture file from an arbitrary offset. This is leveraged when opening merged files.
				uint32_t fbuffer_size; ///< If non-zero, offline captures will read from file using a buffer of this size.
			} scap_file_args;

			struct
			{
				scap_source_plugin* input_plugin; ///< use this to configure a source plugin that will produce the events for this capture
				char* input_plugin_params;	  ///< optional parameters string for the source plugin pointed by src_plugin
			} plugin_args;

			struct
			{
				const char* gvisor_root_path;	///< When using gvisor, the root path used by runsc commands
				const char* gvisor_config_path; ///< When using gvisor, the path to the configuration file
			} gvisor_args;

			struct
			{
				uint64_t single_buffer_dim; ///<  dim of a single shared buffer. Usually, we have one buffer for every online CPU.
			} modern_bpf_args;

			struct
			{
				scap_test_input_data* test_input_data; ///<  only used for testing scap consumers by supplying arbitrary test data.
			} test_input_args;
		};

	} scap_open_args;

#ifdef __cplusplus
}
#endif
