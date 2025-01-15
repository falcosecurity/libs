// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/common.h>
#include <driver/modern_bpf/shared_definitions/struct_definitions.h>
#include <driver/ppm_events_public.h>
#include <driver/driver_config.h>

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/* The `volatile` qualifier is necessary to make sure Clang doesn't optimize away the read-only
 * global variables, ignoring user-space provided value. Without it, Clang is free to
 * just assume 0 and remove the variable completely.
 *
 * These read-only global variables need to be set before BPF skeleton is loaded into the
 * kernel by the user-space. These maps don't change after loading phase. They are initialized by
 * userspace before loading phase and they can no longer be modified neither
 * on the userspace-side nor on the bpf-side.
 */

/**
 * @brief Take as input the `ppm_event_code` enum and returns the number
 * of parameters for that event.
 */
__weak const volatile uint8_t g_event_params_table[PPM_EVENT_MAX];

/**
 * @brief Take as input the `syscall_id` and returns the PPM_SC_CODE
 * associated with the syscall.
 */
__weak const volatile uint16_t g_ppm_sc_table[SYSCALL_TABLE_SIZE];

/**
 * @brief Actual probe API version
 */
__weak const volatile uint64_t probe_api_ver = PPM_API_CURRENT_VERSION;

/**
 * @brief Actual probe schema version
 */
__weak const volatile uint64_t probe_schema_var = PPM_SCHEMA_CURRENT_VERSION;

/**
 * @brief Given the syscall id on 64-bit-architectures returns:
 * - `UF_NEVER_DROP` if the syscall must not be dropped in the sampling logic.
 * - `UF_ALWAYS_DROP` if the syscall must always be dropped in the sampling logic.
 * - `UF_NONE` if we drop the syscall depends on the sampling ratio.
 */
__weak const volatile uint8_t g_64bit_sampling_syscall_table[SYSCALL_TABLE_SIZE];

/**
 * @brief Given the syscall id on 32-bit x86 arch returns
 * its x64 value. Used to support ia32 syscall emulation.
 */
__weak const volatile uint32_t g_ia32_to_64_table[SYSCALL_TABLE_SIZE];

/**
 * @brief Number of ring buffers. If set to zero, events will be pushed to the ring buffer
 * associated with the current CPU).
 */
__weak const volatile uint16_t ringbufs_num;


/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/*=============================== BPF GLOBAL VARIABLES ===============================*/

/**
 * @brief Variable used only kernel side to understand when we need to send
 * `DROP_E` and `DROP_X` events
 */
__weak bool is_dropping;

/**
 * @brief Pointer we use to understand if we are operating on a socket.
 */
__weak void *socket_file_ops = NULL;

/*=============================== BPF GLOBAL VARIABLES ===============================*/

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/**
 * @brief This tail table is used by the syscall_exit_disptacher.
 * Given the syscall_id, it calls the right bpf program to manage
 * the syscall exit event.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SYSCALL_TABLE_SIZE);
	__type(key, uint32_t);
	__type(value, uint32_t);
} syscall_exit_tail_table __weak SEC(".maps");

/**
 * @brief This tail table is used when a sys exit bpf program needs another program
 * to complete its execution flow.
 * Given a predefined tail-code (`sys_exit_extra_code`), it calls
 * the right bpf program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SYS_EXIT_EXTRA_CODE_MAX);
	__type(key, uint32_t);
	__type(value, uint32_t);
} syscall_exit_extra_tail_table __weak SEC(".maps");

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/**
 * @brief This table is used to keep track of which syscalls must be filtered out
 * according to the simple consumer logic.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SYSCALL_TABLE_SIZE);
	__type(key, uint32_t);
	__type(value, bool);
} interesting_syscalls_table_64bit __weak SEC(".maps");

/**
 * @brief Global capture settings shared between userspace and
 * bpf programs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct capture_settings);
} capture_settings __weak SEC(".maps");

/* These maps have one entry for each CPU.
 *
 * PLEASE NOTE:
 * We cannot use `BPF_MAP_TYPE_PERCPU_ARRAY` since there is a limit on the maximum size
 * of the single array element. `BPF_MAP_TYPE_PERCPU_ARRAY` maps have just one entry that is
 * a per-cpu array. The problem is that the maximum size of the single element could be 32 KB
 * at maximum, while we need at least 128 KB, so an array-size of 128 KB * n_cpus.
 * For more info:
 * https://github.com/torvalds/linux/blob/09688c0166e76ce2fb85e86b9d99be8b0084cdf9/mm/percpu.c#L1756
 *
 */

/**
 * @brief For every CPU on the system we have an auxiliary
 * map where the event is temporally saved before being
 * pushed in the ringbuffer.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct auxiliary_map);
} auxiliary_maps __weak SEC(".maps");

/**
 * @brief For every CPU on the system we have a counter
 * map where we store the number of events correctly pushed
 * and the number of events dropped.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct counter_map);
} counter_maps __weak SEC(".maps");

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/*=============================== RINGBUF MAP ===============================*/

/**
 * @brief We use this map to let the verifier understand the content of our array of maps
 * (`ringbuf_maps`)
 */
struct ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
};

/**
 * @brief This array of maps will contain a variable number of ring buffers
 * according to the user-provided configuration. It could also contain only
 * one buffer shared between all CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__array(values, struct ringbuf_map);
} ringbuf_maps __weak SEC(".maps");

/*=============================== RINGBUF MAP ===============================*/
