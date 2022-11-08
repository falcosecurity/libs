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
#include <limits.h>
#include "../../ringbuffer/devset.h"
#include "../../../../driver/ppm_events_public.h"

//
// ebpf defs
//

#ifndef BPF_PROGS_MAX
#define BPF_PROGS_MAX 156
#endif

#define BPF_MAPS_MAX 32

struct bpf_prog {
	int fd;
	int efd;
	char name[NAME_MAX];
};

struct bpf_engine
{
	struct scap_device_set m_dev_set;
	size_t m_ncpus;
	char* m_lasterr;
	struct bpf_prog m_bpf_progs[BPF_PROGS_MAX];
	int m_bpf_prog_cnt;
	int m_bpf_map_fds[BPF_MAPS_MAX];
	int m_bpf_prog_array_map_idx;
	char m_filepath[PATH_MAX];
	interesting_tp_set oargs_tp_set;
};

#define SCAP_HANDLE_T struct bpf_engine
