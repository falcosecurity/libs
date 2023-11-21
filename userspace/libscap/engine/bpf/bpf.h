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
#include <libscap/ringbuffer/devset.h>
#include <libscap/scap_open.h>
#include <libscap/engine/bpf/attached_prog.h>
#include <libscap/scap_stats_v2.h>
#include <libscap/engine/bpf/scap_bpf_stats.h>

//
// ebpf defs
//

#ifndef BPF_PROGS_TAIL_CALLED_MAX
#define BPF_PROGS_TAIL_CALLED_MAX 256
#endif

#define BPF_MAPS_MAX 32

struct bpf_engine
{
	struct scap_device_set m_dev_set;
	size_t m_ncpus;
	char* m_lasterr;

	int m_tail_called_fds[BPF_PROGS_TAIL_CALLED_MAX];
	int m_tail_called_cnt;
	bpf_attached_prog m_attached_progs[BPF_PROG_ATTACHED_MAX];

	int m_bpf_map_fds[BPF_MAPS_MAX];
	int m_bpf_prog_array_map_idx;
	char m_filepath[PATH_MAX];

	/* ELF related */
	int program_fd;
	Elf *elf;
	GElf_Ehdr ehdr;

	interesting_ppm_sc_set curr_sc_set;
	uint64_t m_api_version;
	uint64_t m_schema_version;
	bool capturing;
	scap_stats_v2* m_stats;
	uint32_t m_nstats;
	uint64_t m_flags;
};
