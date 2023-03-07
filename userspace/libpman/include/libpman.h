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

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

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
	 * @param verbosity use `true` if you want to activate libbpf verbosity.
	 * @param buf_bytes_dim dimension of a single per-CPU buffer in bytes.
	 * @param cpus_for_each_buffer number of CPUs to which we want to associate a ring buffer.
	 * @param allocate_online_only if true, allocate ring buffers taking only into account online CPUs.
	 * @return `0` on success, `-1` in case of error.
	 */
	int pman_init_state(bool verbosity, unsigned long buf_bytes_dim, uint16_t cpus_for_each_buffer, bool allocate_online_only);

	/**
	 * @brief Clear the `libpman` global state before it is used.
	 * This API could be useful if we open the modern bpf engine multiple times.
	 */
	void pman_clear_state(void);

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
	 */
	void pman_close_probe(void);

	/////////////////////////////
	// ATTACH PROGRAMS
	/////////////////////////////

	/**
	 * @brief Attach all available BPF programs
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_all_programs(void);

	/**
	 * @brief Detach all available BPF programs
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_all_programs(void);

	/**
	 * @brief Update single program state,
	 * attaching or detaching it.
	 */
	int pman_update_single_program(int tp, bool enabled);

	/**
	 * @brief Attach only the syscall_exit_dispatcher
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_syscall_exit_dispatcher(void);

	/**
	 * @brief Detach only the syscall_exit_dispatcher
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_syscall_exit_dispatcher(void);

	/**
	 * @brief Attach only the syscall_enter_dispatcher
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_syscall_enter_dispatcher(void);

	/**
	 * @brief Detach only the syscall_enter_dispatcher
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_syscall_enter_dispatcher(void);

	/**
	 * @brief Attach only the sched_process_exit tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_sched_proc_exit(void);

	/**
	 * @brief Detach only the sched_process_exit tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_sched_proc_exit(void);

	/**
	 * @brief Attach only the sched_switch tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_sched_switch(void);

	/**
	 * @brief Detach only the sched_switch tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_sched_switch(void);

#ifdef CAPTURE_SCHED_PROC_EXEC
	/**
	 * @brief Attach only the sched_proc_exec tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_sched_proc_exec(void);

	/**
	 * @brief Detach only the sched_proc_exec tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_sched_proc_exec(void);
#endif

#ifdef CAPTURE_SCHED_PROC_FORK
	/**
	 * @brief Attach only the sched_proc_fork tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_sched_proc_fork(void);

	/**
	 * @brief Detach only the sched_proc_fork tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_sched_proc_fork(void);
#endif

#ifdef CAPTURE_PAGE_FAULTS
	/**
	 * @brief Attach only the page_fault_user tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_page_fault_user(void);

	/**
	 * @brief Detach only the page_fault_user tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_page_fault_user(void);

	/**
	 * @brief Attach only the page_fault_kernel tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_page_fault_kernel(void);

	/**
	 * @brief Detach only the page_fault_kernel tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_page_fault_kernel(void);
#endif

	/**
	 * @brief Attach only the signal_deliver tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_attach_signal_deliver(void);

	/**
	 * @brief Detach only the signal_deliver tracepoint
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_detach_signal_deliver(void);

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
	 * @brief Enable BPF-capture if we have previously
	 * disabled it.
	 */
	int pman_enable_capture(bool *tp_set);

	/**
	 * @brief Disable BPF capture for example when we
	 * want to dump a particular event.
	 */
	int pman_disable_capture(void);

	/**
	 * @brief Receive a pointer to `struct scap_stats` and fill it
	 * with info about the number of events and number of drops.
	 *
	 * @param scap_stats_struct opaque pointer to `struct scap_stats`.
	 * We used an opaque pointer because we don't want to introduce scap
	 * definitions in this file.
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_get_scap_stats(void* scap_stats_struct);

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
	 * @brief Some bpf programs exceed the maximum complexity
	 * so they have to tail-call other programs. To do that, they
	 * need a particular tail table that we call `extra_event_prog_tail_table`.
	 *
	 * -> EXTRA EVENT PROG TAIL TABLE
	 * extra_event_prog_tail_table(extra_event_prog_code, program_fd).
	 *
	 * `extra_event_prog_code` is an enum defined in
	 * `/driver/ppm_events_public.h`
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_fill_extra_event_prog_tail_table(void);

	/**
	 * @brief The syscall dispatchers will look into these tables
	 * to understand which programs they have to call. We have 2
	 * different tables one for syscall enter events and the other
	 * for syscall exit events:
	 *
	 * -> SYSCALL ENTER TAIL TABLE
	 * syscall_enter_tail_table(syscall_id, enter_program_fd).
	 * Returns the fd of the right bpf program to call.
	 *
	 * -> SYSCALL EXIT TAIL TABLE
	 * syscall_exit_tail_table(syscall_id, exit_program_fd).
	 * Returns the fd of the right bpf program to call.
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_fill_syscalls_tail_table(void);

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
	 */
	void pman_mark_single_64bit_syscall(int syscall_id, bool interesting);

	/**
	 * @brief Mark all syscalls as uninteresting.
	 */
	void pman_clean_all_64bit_interesting_syscalls(void);

#ifdef __cplusplus
}
#endif
