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

#include <libscap/engine_handle.h>
#include <libscap/scap_open.h>

#ifdef __cplusplus
extern "C" {
#endif

struct scap_stats;
typedef struct scap scap_t;
struct scap_stats_v2;
typedef struct ppm_evt_hdr scap_evt;
struct scap_proclist;

enum scap_ppm_sc_mask_op {
	// SCAP_PPM_SC_MASK_ZERO = 0, //< disable all syscalls - SUPPORT DROPPED
	SCAP_PPM_SC_MASK_SET = 1, //< enable a syscall
	SCAP_PPM_SC_MASK_UNSET = 2, //< disable a syscall
};

/**
 * @brief settings configurable for scap engines
 */
enum scap_setting {
	/**
	 * @brief sampling ratio
	 * arg1: sampling ratio (power of 2, <= 128)
	 * arg2: dropping mode enabled (1) / disabled (0)
	 */
	SCAP_SAMPLING_RATIO,
	/**
	 * @brief length of captured data buffers
	 * arg1: the length (< 65536)
	 */
	SCAP_SNAPLEN,
	/**
	 * @brief enable/disable individual syscalls
	 * arg1: scap_ppm_sc_op
	 * arg2: ppm_sc id
	 */
	SCAP_PPM_SC_MASK,
	/**
	 * @brief enable/disable dynamic snaplen
	 * arg1: enabled?
	 */
	SCAP_DYNAMIC_SNAPLEN,
	/**
	 * @brief full capture port range
	 * arg1: min port
	 * arg2: max port
	 */
	SCAP_FULLCAPTURE_PORT_RANGE,
	/**
	 * @brief port for statsd metrics
	 * arg1: statsd port
	 */
	SCAP_STATSD_PORT,
	/**
	 * @brief tell drivers to drop failed syscalls exit
	 * arg1: whether to enabled or disable the feature
	 */
	SCAP_DROP_FAILED,
};

struct scap_savefile_vtable {
	/**
	 * @brief return the current read position in the capture
	 * @param engine the handle to the engine
	 * @return the current read offset, in (uncompressed) bytes
	 */
	uint64_t (*ftell_capture)(struct scap_engine_handle engine);

	/**
	 * @brief seek through the capture
	 * @param engine the handle to the engine
	 * @param off offset (in uncompressed bytes) where to seek
	 */
	void (*fseek_capture)(struct scap_engine_handle engine, uint64_t off);

	/**
	 * @brief restart a capture from the current offset
	 * @param handle the full scap_t handle
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*restart_capture)(struct scap* handle);

	/**
	 * @brief return the current offset in the capture file
	 * @param engine the handle to the engine
	 * @return the current read offset, in (compressed) bytes
	 */
	int64_t (*get_readfile_offset)(struct scap_engine_handle engine);
};

#define ENGINE_FLAG_BPF_STATS_ENABLED (1<<0)

struct scap_vtable {
	/**
	 * @brief name of the engine
	 */
	const char* name;

	const struct scap_savefile_vtable *savefile_ops;

	/**
	 * @brief allocate an engine-specific handle
	 * @param main_handle pointer to the main scap_t handle
	 * @param lasterr_ptr pointer to a SCAP_LASTERR_SIZE buffer
	 *                    for error messages, can be stored
	 *                    in the engine handle for easier access
	 * @return pointer to the newly allocated handle or NULL
	 */
	SCAP_HANDLE_T* (*alloc_handle)(scap_t* main_handle, char *lasterr_ptr);

	/**
	 * @brief perform engine-specific initialization
	 * @param main_handle pointer to the main scap_t handle
	 * @param open_args a scap open request structure
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*init)(scap_t* main_handle, scap_open_args* open_args);

	/**
	 * @brief get features supported by the engine
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return a bitmask of ENGINE_FLAGS_*
	 */
	uint64_t (*get_flags)(struct scap_engine_handle engine);

	/**
	 * @brief free the engine-specific handle
	 * @param engine wraps the pointer to the engine-specific handle
	 */
	void (*free_handle)(struct scap_engine_handle engine);

	/**
	 * @brief close the engine
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*close)(struct scap_engine_handle engine);

	/**
	 * @brief fetch the next event
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param pevent [out] where the pointer to the next event gets stored
	 * @param pdevid [out] where the device on which the event was received
	 *               gets stored
	 * @param pflags [out] where the flags for the event get stored
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * SCAP_SUCCESS: event successfully returned and stored in *pevent
	 * SCAP_FAILURE: an error occurred
	 * SCAP_TIMEOUT: no events arrived for a while (not an error)
	 * SCAP_EOF: no more events are going to arrive
	 *
	 * The memory pointed to by *pevent must be owned by the engine
	 * and must remain valid at least until the next call to next()
	 */
	int32_t (*next)(struct scap_engine_handle engine, scap_evt** pevent, uint16_t* pdevid, uint32_t* pflags);

	/**
	 * @brief start a capture
	 * @param engine
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*start_capture)(struct scap_engine_handle engine);

	/**
	 * @brief stop a running capture
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*stop_capture)(struct scap_engine_handle engine);

	/**
	 * @brief change engine settings
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param setting the setting to change
	 * @param arg1 setting-specific value
	 * @param arg2 setting-specific value
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*configure)(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2);

	/**
	 * @brief get engine statistics
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param stats the stats struct to be filled
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*get_stats)(struct scap_engine_handle engine, struct scap_stats *stats);

	/**
	 * @brief get engine statistics (including counters and `bpftool prog show` like stats)
	 * @param flags holding statistics category flags
	 * @param nstats Pointer reflecting number of statistics in returned buffer
	 * @param rc Pointer to return code
	 * @return Pointer to a \ref scap_stats_v2 structure filled with the statistics
	 */
	const struct scap_stats_v2* (*get_stats_v2)(struct scap_engine_handle engine, uint32_t flags, uint32_t* nstats, int32_t* rc);

	/**
	 * @brief get the number of tracepoint hits
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param ret [out] the number of hits
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*get_n_tracepoint_hit)(struct scap_engine_handle engine, long *ret);

	/**
	 * @brief get the number of used devices
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return the number of used devices
	 */
	uint32_t (*get_n_devs)(struct scap_engine_handle engine);

	/**
	 * @brief get the maximum buffer space used so far
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return the buffer space used, in bytes
	 */
	uint64_t (*get_max_buf_used)(struct scap_engine_handle engine);

	/**
	 * @brief get the API version
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return the API version
	 */
	uint64_t (*get_api_version)(struct scap_engine_handle engine);

	/**
	 * @brief get the schema version
	 * @param engine wraps the pointer to the engine-specific handle
	 * @return the schema version
	 */
	uint64_t (*get_schema_version)(struct scap_engine_handle engine);
};

#ifdef __cplusplus
}
#endif
