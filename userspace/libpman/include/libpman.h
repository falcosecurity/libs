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

#include <stdbool.h>
#include <stdint.h>

#include <libscap/scap_log.h>
#include <libscap/scap.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declare them */
struct metrics_v2;
struct scap_stats;

/* `libpman` return values convention:
 * In case of success `0` is returned otherwise `errno`. If `errno` is not
 * available `-1` is returned.
 *
 * Please Note:
 * Libbpf always sets `errno` to the corresponding Exx (positive) error code.
 * Libbpf APIs usually return `0` in case of success.
 */

/////////////////////////////
// SETUP CONFIGURATION
/////////////////////////////

/**
 * @brief Set `libpman` initial state:
 * - set `libbpf` strict mode.
 * - set `libbpf` logging function according to the verbosity.
 * - set available number of CPUs.
 * - set dimension of a single per-CPU ring buffer.
 *
 * @param log_fn logging callback
 * @param buf_bytes_dim dimension of a single per-CPU buffer in bytes.
 * @param buffers_num determines the number of allocated ring buffers:
 * - if buffers_num > 1, it is the number of requested ring buffers
 * - if buffers_num > 0 && buffers_num <= 1, 1 / buffers_num is the number of CPUs to which we want
 *   to associate a ring buffer.
 * - if buffers_num == 0, it means that 1 ring buffer is shared among all available CPUs
 * @param allocate_online_only if true, allocate ring buffers taking only into account online CPUs.
 *   This parameter is taken into account only if buffers_num >= 0 && buffers_num <= 1.
 * @return `0` on success, `-1` in case of error.
 */
int pman_init_state(falcosecurity_log_fn log_fn,
                    unsigned long buf_bytes_dim,
                    double buffers_num,
                    bool allocate_online_only);

/**
 * @brief Return the number of allocated ring buffers.
 *
 * @return number of allocated ring buffers.
 */
int pman_get_required_buffers(void);

/**
 * @brief Return whether modern bpf is supported by running kernel.
 *
 * @return supported true or false.
 */
bool pman_check_support();

/////////////////////////////
// PROBE LIFECYCLE
/////////////////////////////

/**
 * @brief Open the bpf skeleton obtaining a pointer
 * to it.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_open_probe(void);

/**
 * @brief Prepares the bpf skeleton object checking if
 * it satisfies each events_prog_name feature requirements for each prog.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_prepare_progs_before_loading(void);

/**
 * @brief Load into the kernel all the programs and maps
 * contained into the skeleton.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_load_probe(void);

/**
 * @brief Clean what we have previously allocated:
 * - bpf_skeleton
 * - ringbuffer manager
 * - consumers/producers vectors
 * - stats buffer dynamically allocated
 */
void pman_close_probe(void);

/////////////////////////////
// MANAGE RINGBUFFERS
/////////////////////////////

/**
 * @brief Performs all necessary operations on ringbuf array before the
 * loading phase:
 * - Set inner map dimension.
 * - Set array max entries.
 * - Allocate memory for producers and consumers.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_prepare_ringbuf_array_before_loading(void);

/**
 * @brief Performs all necessary operations on ringbuf array after the
 * loading phase:
 * - Create all the ring_buffer maps inside the array.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_finalize_ringbuf_array_after_loading(void);

/**
 * @brief Search for the event with the lowest timestamp in
 * all the ring buffers.
 *
 * @param event_ptr in case of success return a pointer
 * to the event, otherwise return NULL.
 * @param buffer_id in case of success returns the id of the ring buffer
 * from which we retrieved the event, otherwise return `-1`.
 */
void pman_consume_first_event(void** event_ptr, int16_t* buffer_id);

/////////////////////////////
// CAPTURE (EXCHANGE VALUES WITH BPF SIDE)
/////////////////////////////

/**
 * @brief Instrument the bpf probe with the right sc_set. This API
 * sets both interesting syscalls and interesting tracepoints.
 *
 * @param sc_set pointer to the interesting sc_set
 *
 * @return `0` on success, `1` in case of error.
 */
int pman_enforce_sc_set(bool* sc_set);

/**
 * @brief Receive a pointer to `struct scap_stats` and fill it
 * with info about the number of events and number of drops.
 *
 * @param scap_stats_struct pointer to `struct scap_stats`.
 * @return `0` on success, `errno` in case of error.
 */
int pman_get_scap_stats(struct scap_stats* scap_stats_struct);

/**
 * @brief Return a `metrics_v2` struct filled with statistics.
 *
 * @param flags holding statistics category flags.
 * @param nstats number of stats allocated.
 * @param rc return code, SCAP_FAILURE in case of error.
 *
 * @return pointer to `struct metrics_v2`
 */
struct metrics_v2* pman_get_metrics_v2(uint32_t flags, uint32_t* nstats, int32_t* rc);

/**
 * @brief Receive an array with `nCPUs` elements. For every CPU
 * we set the number of events caught.
 *
 * @param n_events_per_cpu array of `nCPUs` elements.
 * @return `0` on success, `errno` in case of error.
 */
int pman_get_n_tracepoint_hit(long* n_events_per_cpu);

/////////////////////////////
// MAPS
/////////////////////////////

/**
 * @brief Ensure that `bytebufs` cannot be longer than
 * `snaplen`.
 *
 * @param desired_snaplen maximum length we accept
 */
void pman_set_snaplen(uint32_t desired_snaplen);

/**
 * @brief Set the boot_time so all the events generated
 * by the probe can provide a full timestamp based on Epoch.
 *
 * @param boot_time system boot_time from Epoch.
 */
void pman_set_boot_time(uint64_t boot_time);

void pman_set_dropping_mode(bool value);

void pman_set_sampling_ratio(uint32_t value);

/**
 * @brief Ask driver to drop failed syscalls.
 * It only applied to syscall exit events.
 *
 * @param drop_failed whether to enable the drop failed mode.
 */
void pman_set_drop_failed(bool drop_failed);

/**
 * @brief Ask driver to enable/disable dynamic_snaplen.
 *
 * @param do_dynamic_snaplen whether to enable the dynamic_snaplen.
 */
void pman_set_do_dynamic_snaplen(bool do_dynamic_snaplen);

/**
 * @brief Ask driver to set a range of interesting ports.
 *
 * @param range_start first interesting port.
 * @param range_end last interesting port.
 */
void pman_set_fullcapture_port_range(uint16_t range_start, uint16_t range_end);

/**
 * @brief Ask driver to set a specific statsd_port.
 *
 * @param statsd_port port number.
 */
void pman_set_statsd_port(uint16_t statsd_port);

/**
 * @brief Set scap tid for socket calibration logic.
 *
 * @param scap_tid
 */
void pman_set_scap_tid(int32_t scap_tid);

/**
 * @brief Get API version to check it a runtime.
 *
 * @return API version
 */
uint64_t pman_get_probe_api_ver(void);

/**
 * @brief Get schema version to check it a runtime.
 *
 * @return schema version
 */
uint64_t pman_get_probe_schema_ver(void);

/**
 * @brief Performs all necessary operations on maps before the
 * loading phase:
 * - Fill read-only global variables.
 * - Set the number of entries for `BPF_MAP_TYPE_ARRAY`.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_prepare_maps_before_loading(void);

/**
 * @brief Performs all necessary operations on maps after the
 * loading phase:
 * - Set values to BPF global variables.
 * - Fill tail tables.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_finalize_maps_after_loading(void);

/**
 * @brief Mark a single syscall as (un)interesting
 *
 * @param syscall_id syscall system id.
 * @param interesting true if the syscall must be marked as interesting.
 *
 * @return `0` on success, `errno` in case of error.
 */
int pman_mark_single_64bit_syscall(int syscall_id, bool interesting);

/////////////////////////////
// ITERATORS
/////////////////////////////

int32_t pman_iter_fetch_task(const struct scap_fetch_callbacks* callbacks,
                             uint32_t tid,
                             scap_threadinfo** tinfo,
                             char* error);
int32_t pman_iter_fetch_tasks(const struct scap_fetch_callbacks* callbacks, char* error);
int32_t pman_iter_fetch_proc_file(const struct scap_fetch_callbacks* callbacks,
                                  uint32_t pid,
                                  uint32_t fd,
                                  char* error);
int32_t pman_iter_fetch_proc_files(const struct scap_fetch_callbacks* callbacks,
                                   uint32_t pid,
                                   bool must_fetch_sockets,
                                   uint64_t* num_files_fetched,
                                   char* error);
int32_t pman_iter_fetch_procs_files(const struct scap_fetch_callbacks* callbacks, char* error);

#ifdef __cplusplus
}
#endif
