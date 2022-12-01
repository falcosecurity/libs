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

#include "engine_handle.h"
#include "scap_open.h"

#ifdef __cplusplus
extern "C" {
#endif

struct scap_stats;
typedef struct scap scap_t;
typedef struct ppm_evt_hdr scap_evt;

enum scap_eventmask_op {
	SCAP_PPM_SC_MASK_ZERO = 0, //< disable all syscalls
	SCAP_PPM_SC_MASK_SET = 1, //< enable a syscall
	SCAP_PPM_SC_MASK_UNSET = 2, //< disable a syscall
};

enum scap_tpmask_op {
	SCAP_TPMASK_SET = 0, //< enable a tp
	SCAP_TPMASK_UNSET = 1, //< disable a tp
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
	 * @brief control tracers capture
	 * arg1: enabled?
	 */
	SCAP_TRACERS_CAPTURE,
	/**
	 * @brief length of captured data buffers
	 * arg1: the length (< 65536)
	 */
	SCAP_SNAPLEN,
	/**
	 * @brief enable/disable individual syscalls
	 * arg1: scap_eventmask_op
	 * arg2: event id (ignored for SCAP_EVENTMASK_ZERO)
	 */
	SCAP_EVENTMASK,
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
	 * @brief enable/disable individual tracepoints
	 * arg1: scap_tpmask_op
	 * arg2: tp id
	 */
	SCAP_TPMASK,
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

	/**
	 * @brief return the flags for the last read event
	 * @param engine the handle to the engine
	 * @return the flags of the event (currently only SCAP_DF_LARGE is supported)
	 */
	uint32_t (*get_event_dump_flags)(struct scap_engine_handle engine);
};

struct scap_vtable {
	/**
	 * @brief name of the engine
	 */
	const char* name;

	/**
	 * @brief one of the SCAP_MODE_* constants, designating the purpose
	 * of the engine (live capture, capture files, etc.)
	 */
	scap_mode_t mode;

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
	 * @param pcpuid [out] where the CPU on which the event was received
	 *               gets stored
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
	int32_t (*next)(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pcpuid);

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
	 * @brief get the list of all threads in the system, with their cpu usage
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param procinfo_p pointer to pointer to the resulting list
	 * @param lasterr pointer to a buffer of SCAP_LASTERR_SIZE bytes
	 *                for the error message (if any)
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * `procinfo_p` must not be NULL, but `*procinfo_p` may be; the returned
	 * list will be (re)allocated on demand
	 */
	int32_t (*get_threadlist)(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr);

	/**
	 * @brief get information about all threads in the system
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param n [out] the number of scap_threadinfo structures returned
	 * @param tinfos [out] an array of scap_threadinfo structures
	 * 				 that represent the state of the system, owned by the engine
	 * @return SCAP_SUCCESS or a failure code
	 *
	 */
	int32_t (*get_threadinfos)(struct scap_engine_handle engine, uint64_t *n, const scap_threadinfo **tinfos);

	/**
	 * @brief get information about file descriptors for a thread that was identified by get_threadinfos
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param tinfo a thread pointer returned by get_threadinfos
	 * @param n [out] the number of scap_fdinfo structures returned 
	 * @param fdinfos [out] an array of scap_fdinfo structures
	 * @return SCAP_SUCCESS or a failure code
	 *
	 */
	int32_t (*get_fdinfos)(struct scap_engine_handle engine, const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos);

	/**
	 * @brief get the vpid of a process
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param pid the pid of the process to check
	 * @param vpid output parameter, pointer to the vpid
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * `vpid` is the pid as seen by the process itself, i.e. within its
	 * PID namespace
	 */
	int32_t (*get_vpid)(struct scap_engine_handle engine, uint64_t pid, int64_t *vpid);

	/**
	 * @brief get the vtid of a process
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param tid the tid of the process to check
	 * @param vtid output parameter, pointer to the vtid
	 * @return SCAP_SUCCESS or a failure code
	 *
	 * `vtid` is the tid as seen by the process itself, i.e. within its
	 * PID namespace
	 */
	int32_t (*get_vtid)(struct scap_engine_handle engine, uint64_t tid, int64_t *vtid);

	/**
	 * @brief get the current process id in the init pid namespace
	 * @param engine wraps the pointer to the engine-specific handle
	 * @param pid output parameter, pointer to the pid
	 * @param error a SCAP_LASTERR_SIZE buffer for error messages
	 * @return SCAP_SUCCESS or a failure code
	 */
	int32_t (*getpid_global)(struct scap_engine_handle engine, int64_t* pid, char* error);
};

#ifdef __cplusplus
}
#endif
