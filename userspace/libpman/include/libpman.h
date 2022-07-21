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
	 * In case of success `0` is return otherwise `errno`. If `errno` is not
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
	 * @brief Set libbpf inital configurations:
	 * - libbpf strict mode.
	 * - libbpf logging function according to the verbosity.
	 * - set available number of CPUs.
	 *
	 * @param verbosity use `true` if you want to activate libbpf verbosity.
	 * @return `0` on success, `-1` in case of error.
	 */
	int pman_set_libbpf_configuration(bool verbosity);

	/**
	 * @brief Return the number of available CPUs on the system, not the
	 * online CPUs!
	 *
	 * @return number of available CPUs on success, `-1` in case of error.
	 */
	int pman_get_cpus_number(void);

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
	 * @brief Search for one event to read in all the ringbufs.
	 *
	 * @param event_ptr in case of success return a pointer
	 * to the event, otherwise return NULL.
	 * @param cpu_id in case of success returns the id of the CPU
	 * on which we have found the event, otherwise return NULL
	 * @return `0` if an event is found otherwise returns `-1`
	 */
	int pman_consume_one_from_buffers(void** event_ptr, uint16_t* cpu_id);

	/////////////////////////////
	// CAPTURE (EXCHANGE VALUES WITH BPF SIDE)
	/////////////////////////////

	/**
	 * @brief Enable BPF-capture if we have previously
	 * disabled it.
	 */
	void pman_enable_capture(void);

	/**
	 * @brief Disable BPF capture for example when we
	 * want to dump a particular event.
	 */
	void pman_disable_capture(void);

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
	 * @brief For every syscall set if it is interesting or not.
	 *
	 * @param intersting_syscalls array of size `SYSCALL_TABLE_SIZE` that says
	 * if the single syscall is interesting or not.
	 */
	void pman_fill_64bit_interesting_syscalls_table(bool* intersting_syscalls);

	/////////////////////////////
	// TEST HELPERS
	/////////////////////////////
#ifdef TEST_HELPERS

	/**
	 * @brief Mark a single syscall as interesting
	 *
	 * @param intersting_syscall_id syscall id.
	 */
	void pman_mark_single_64bit_syscall_as_interesting(int intersting_syscall_id);

	/**
	 * @brief Mark all syscalls as uninteresting.
	 */
	void pman_mark_all_64bit_syscalls_as_uninteresting(void);

	/**
	 * @brief Print some statistics about events captured and
	 * events dropped
	 *
	 * @return `0` on success, `errno` in case of error.
	 */
	int pman_print_stats(void);

	/**
	 * @brief Given the event type, returns the number of params
	 * for that event.
	 *
	 * @param event_type event type
	 * @return number of params associated with the event type
	 */
	uint8_t pman_get_event_params(int event_type);

	/**
	 * @brief Given the event type, returns the name of the BPF
	 * program associated with that event.
	 *
	 * @param event_type event type
	 * @return name of the BPF program associated with the event type
	 */
	const char* pman_get_event_prog_name(int event_type);
#endif

#ifdef __cplusplus
}
#endif
