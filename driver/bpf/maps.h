/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __MAPS_H
#define __MAPS_H

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

#ifdef __KERNEL__
struct bpf_map_def __bpf_section("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") tail_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = PPM_FILLER_MAX,
};

struct bpf_map_def __bpf_section("maps") syscall_code_routing_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = SYSCALL_TABLE_SIZE,
};

struct bpf_map_def __bpf_section("maps") syscall_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct syscall_evt_pair),
	.max_entries = SYSCALL_TABLE_SIZE,
};

struct bpf_map_def __bpf_section("maps") event_info_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_info),
	.max_entries = PPM_EVENT_MAX,
};

struct bpf_map_def __bpf_section("maps") fillers_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_entry),
	.max_entries = PPM_EVENT_MAX,
};

struct bpf_map_def __bpf_section("maps") frame_scratch_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") tmp_scratch_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") settings_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_settings),
	.max_entries = 1,
};

struct bpf_map_def __bpf_section("maps") local_state_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_per_cpu_state),
	.max_entries = 0,
};

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
struct bpf_map_def __bpf_section("maps") stash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct sys_stash_args),
	.max_entries = 65535,
};
#endif

struct bpf_map_def __bpf_section("maps") rtt_static_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct tuple),
        .value_size = sizeof(struct statistics),
        .max_entries = 65535,
};

struct bpf_map_def __bpf_section("maps") stash_tuple_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct tuple),
	.max_entries = 65535,
};

enum offcpu_type {
    ON, // 0
    DISK, // 1
    NET, // 2
    LOCK, // 3
    IDLE, // 4
    OTHER,
    EPOLL
};

#define NUM 16
#define HALF_NUM (NUM >> 1)
struct info_t {
    u32 pid;
    u32 tid;
    u64 start_ts;
    u64 end_ts;
    u32 index;
    u64 times_specs[NUM];
    u64 rq[HALF_NUM];
    u8 time_type[NUM];
};

struct bpf_map_def __bpf_section("maps") on_start_ts = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u64),
        .max_entries = 65535,
};

struct bpf_map_def __bpf_section("maps") off_start_ts = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u64),
        .max_entries = 65535,
};

struct bpf_map_def __bpf_section("maps") cpu_runq = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u64),
        .max_entries = 65535,
};

struct bpf_map_def __bpf_section("maps") type_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(enum offcpu_type),
        .max_entries = 65535,
};

struct bpf_map_def __bpf_section("maps") syscall_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(enum offcpu_type),
        .max_entries = 1000,
};

struct bpf_map_def __bpf_section("maps") cpu_analysis_pid_whitelist = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(bool),
        .max_entries = 1000,
};

struct bpf_map_def __bpf_section("maps") cpu_analysis_pid_blacklist = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(bool),
        .max_entries = 1000,
};

struct bpf_map_def __bpf_section("maps") cpu_records = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(struct info_t),
        .max_entries = 1000,
};

struct bpf_map_def __bpf_section("maps") cpu_focus_threads = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u64),
        .max_entries = 65535,
};
#endif // __KERNEL__

#endif
