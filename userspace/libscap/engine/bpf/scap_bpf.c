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

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <gelf.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>
#include <libscap/strl.h>

#define SCAP_HANDLE_T struct bpf_engine

#include <libscap/engine/bpf/bpf.h>
#include <libscap/engine_handle.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/engine/bpf/scap_bpf.h>
#include <libscap/scap_engine_util.h>
#include <driver_config.h>
#include <driver/bpf/types.h>
#include <driver/bpf/maps.h>
#include <libscap/compat/misc.h>
#include <libscap/compat/bpf.h>
#include <libscap/strl.h>
#include <libscap/strerror.h>

static const char * const bpf_kernel_counters_stats_names[] = {
	[BPF_N_EVTS] = "n_evts",
	[BPF_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[BPF_N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[BPF_N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[BPF_N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[BPF_N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[BPF_N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[BPF_N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[BPF_N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[BPF_N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[BPF_N_DROPS_BUFFER_CLOSE_EXIT] = "n_drops_buffer_close_exit",
	[BPF_N_DROPS_BUFFER_PROC_EXIT] = "n_drops_buffer_proc_exit",
	[BPF_N_DROPS_SCRATCH_MAP] = "n_drops_scratch_map",
	[BPF_N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[BPF_N_DROPS_BUG] = "n_drops_bug",
	[BPF_N_DROPS] = "n_drops",
};

static const char * const bpf_libbpf_stats_names[] = {
	[RUN_CNT] = ".run_cnt", ///< `bpf_prog_info` run_cnt.
	[RUN_TIME_NS] = ".run_time_ns", ///<`bpf_prog_info` run_time_ns.
	[AVG_TIME_NS] = ".avg_time_ns", ///< Average time spent in bpg program, calculation: run_time_ns / run_cnt.
};

static inline scap_evt* scap_bpf_next_event(scap_device* dev)
{
	return scap_bpf_evt_from_perf_sample(dev->m_sn_next_event);
}

static inline void scap_bpf_advance_to_next_evt(scap_device* dev, scap_evt *event)
{
	scap_bpf_advance_to_evt(dev, true,
				dev->m_sn_next_event,
				&dev->m_sn_next_event,
				&dev->m_sn_len);
}

#define GET_BUF_POINTERS scap_bpf_get_buf_pointers
#define ADVANCE_TAIL scap_bpf_advance_tail
#define ADVANCE_TO_EVT scap_bpf_advance_to_next_evt
#define READBUF scap_bpf_readbuf
#define NEXT_EVENT scap_bpf_next_event

#include <libscap/ringbuffer/ringbuffer.h>

//
// Some of this code is taken from the kernel samples under samples/bpf,
// namely the parsing of the ELF objects, which is very tedious and not
// worth reinventing from scratch. The code has been readapted and simplified
// to tailor our use case. In the future, a full switch to libbpf
// is possible, but at the moment is not very worth the effort considering the
// subset of features needed.
//

struct bpf_map_data {
	int fd;
	size_t elf_offset;
	struct bpf_map_def def;
};

static struct bpf_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct bpf_engine *engine = calloc(1, sizeof(struct bpf_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
		for(int j=0; j < BPF_PROGS_TAIL_CALLED_MAX; j++)
		{
			engine->m_tail_called_fds[j] = -1;
		}

		for(int j=0; j < BPF_PROG_ATTACHED_MAX; j++)
		{
			engine->m_attached_progs[j].fd = -1;
			engine->m_attached_progs[j].efd = -1;
		}
	}
	return engine;
}

static void free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

#ifndef UINT32_MAX
# define UINT32_MAX (4294967295U)
#endif

/* Recommended log buffer size.
 * Taken from libbpf source code: https://github.com/libbpf/libbpf/blob/67a4b1464349345e483df26ed93f8d388a60cee1/src/bpf.h#L201
 */
static const int BPF_LOG_SIZE = UINT32_MAX >> 8; /* verifier maximum in kernels <= 5.1 */

static char* license;

#define FILLER_NAME_FN(x) #x,
static const char *g_filler_names[PPM_FILLER_MAX] = {
	FILLER_LIST_MAPPER(FILLER_NAME_FN)
};
#undef FILLER_NAME_FN

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int sys_perf_event_open(struct perf_event_attr *attr,
			       pid_t pid, int cpu, int group_fd,
			       unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

/* Here the filler_name is something like 'sys_open_x'.
 * Starting from the entire section name 'raw_tracepoint/filler/sys_open_x'
 * here we obtain just the final part 'sys_open_x'.
 */
static int32_t lookup_filler_id(const char *filler_name)
{
	int j;

	/* In our table we must have a filler_name corresponding to the final
	 * part of the elf section.
	 */
	for(j = 0; j < sizeof(g_filler_names) / sizeof(g_filler_names[0]); ++j)
	{
		if(strcmp(filler_name, g_filler_names[j]) == 0)
		{
			return j;
		}
	}

	return -1;
}

static int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (unsigned long) key;
	attr.value = (unsigned long) value;
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (unsigned long) key;
	attr.value = (unsigned long) value;

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_create(enum bpf_map_type map_type,
			  int key_size, int value_size, int max_entries,
			  uint32_t map_flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_map_freeze(int fd)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd;

	/* Do not check for errors as BPF_MAP_FREEZE was introduced in kernel 5.2 */
	sys_bpf(BPF_MAP_FREEZE, &attr, sizeof(attr));
	return SCAP_SUCCESS;
}

static int bpf_obj_get_info_by_fd(int fd, void *info, __u32 *info_len)
{
	union bpf_attr attr;
	int err;

	bzero(&attr, sizeof(attr));
	attr.info.bpf_fd = fd;
	attr.info.info_len = *info_len;
	attr.info.info = ptr_to_u64(info);

	err = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	if (!err)
		*info_len = attr.info.info_len;
	return SCAP_SUCCESS;
}

static int bpf_load_program(const struct bpf_insn *insns,
			    enum bpf_prog_type type,
			    size_t insns_cnt,
			    char *log_buf,
			    size_t log_buf_sz,
			    const char *prog_name)
{
	union bpf_attr attr;
	int fd;

	bzero(&attr, sizeof(attr));

	attr.prog_type = type;
	attr.insn_cnt = (uint32_t) insns_cnt;
	attr.insns = (unsigned long) insns;
	attr.license = (unsigned long) license;
	attr.log_buf = (unsigned long) NULL;
	attr.log_size = 0;
	attr.log_level = 0;
	if (prog_name != NULL) {
		snprintf(attr.prog_name, BPF_OBJ_NAME_LEN, "%s", prog_name);
	}

	/* Try a first time without catching verifier logs.
	 * If `log_buf` paramater is NULL it means that we have no intention
	 * to collect verifier logs in any case, so only 1 attempt is enough,
	 * the second one would be useless without catching logs.
	 */
	fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if(fd >= 0 || !log_buf || !log_buf_sz)
	{
		return fd;
	}

	/* Try a second time catching verifier logs. This step is performed
	 * only if we have a buffer for collecting them (so only if we
	 * pass to `bpf_load_program()` function a `log_buf`!= NULL).
	 */
	attr.log_buf = (unsigned long) log_buf;
	attr.log_size = log_buf_sz;
	attr.log_level = 1;
	log_buf[0] = 0;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int32_t get_elf_section(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname, GElf_Shdr *shdr, Elf_Data **data)
{
	Elf_Scn *scn = elf_getscn(elf, i);
	if(!scn)
	{
		return SCAP_FAILURE;
	}

	if(gelf_getshdr(scn, shdr) != shdr)
	{
		return SCAP_FAILURE;
	}

	*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
	if(!*shname || !shdr->sh_size)
	{
		return SCAP_FAILURE;
	}

	*data = elf_getdata(scn, 0);
	if(!*data || elf_getdata(scn, *data) != NULL)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

static int cmp_symbols(const void *l, const void *r)
{
	const GElf_Sym *lsym = (const GElf_Sym *)l;
	const GElf_Sym *rsym = (const GElf_Sym *)r;

	if(lsym->st_value < rsym->st_value)
	{
		return -1;
	}
	else if(lsym->st_value > rsym->st_value)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static int32_t load_elf_maps_section(struct bpf_engine *handle, struct bpf_map_data *maps,
				     int maps_shndx, Elf *elf, Elf_Data *symbols,
				     int strtabidx, int *nr_maps)
{
	Elf_Data *data_maps = NULL;
	GElf_Sym *sym;
	Elf_Scn *scn;
	int i;

	scn = elf_getscn(elf, maps_shndx);
	if(scn)
	{
		data_maps = elf_getdata(scn, NULL);
	}

	if(!scn || !data_maps)
	{
		return scap_errprintf(handle->m_lasterr, 0, "Failed to get Elf_Data from maps section %d", maps_shndx);
	}

	*nr_maps = 0;
	sym = calloc(BPF_MAPS_MAX + 1, sizeof(GElf_Sym));
	if(sym == NULL)
	{
		return scap_errprintf(handle->m_lasterr, 0, "calloc(BPF_MAPS_MAX + 1) failed");
	}

	for(i = 0; i < symbols->d_size / sizeof(GElf_Sym); i++)
	{
		ASSERT(*nr_maps < BPF_MAPS_MAX + 1);
		if(!gelf_getsym(symbols, i, &sym[*nr_maps]))
		{
			continue;
		}

		if(sym[*nr_maps].st_shndx != maps_shndx)
		{
			continue;
		}

		(*nr_maps)++;
	}

	qsort(sym, *nr_maps, sizeof(GElf_Sym), cmp_symbols);

	ASSERT(data_maps->d_size / *nr_maps == sizeof(struct bpf_map_def));

	for(i = 0; i < *nr_maps; i++)
	{
		struct bpf_map_def *def;
		size_t offset;

		offset = sym[i].st_value;
		def = (struct bpf_map_def *)(data_maps->d_buf + offset);
		maps[i].elf_offset = offset;
		memcpy(&maps[i].def, def, sizeof(struct bpf_map_def));
	}

	free(sym);
	return SCAP_SUCCESS;
}

static int32_t load_maps(struct bpf_engine *handle, struct bpf_map_data *maps, int nr_maps)
{
	int j;

	for(j = 0; j < nr_maps; ++j)
	{
		if(j == SCAP_PERF_MAP ||
		   j == SCAP_LOCAL_STATE_MAP ||
		   j == SCAP_FRAME_SCRATCH_MAP ||
		   j == SCAP_TMP_SCRATCH_MAP)
		{
			maps[j].def.max_entries = handle->m_ncpus;
		}

		handle->m_bpf_map_fds[j] = bpf_map_create(maps[j].def.type,
							  maps[j].def.key_size,
							  maps[j].def.value_size,
							  maps[j].def.max_entries,
							  maps[j].def.map_flags);

		maps[j].fd = handle->m_bpf_map_fds[j];

		if(handle->m_bpf_map_fds[j] < 0)
		{
			return scap_errprintf(handle->m_lasterr, -handle->m_bpf_map_fds[j], "can't create map %d", j);
		}

		if(maps[j].def.type == BPF_MAP_TYPE_PROG_ARRAY)
		{
			handle->m_bpf_prog_array_map_idx = j;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t parse_relocations(struct bpf_engine *handle, Elf_Data *data, Elf_Data *symbols,
				 GElf_Shdr *shdr, struct bpf_insn *insn,
				 struct bpf_map_data *maps, int nr_maps)
{
	int nrels;
	int i;

	nrels = shdr->sh_size / shdr->sh_entsize;

	for(i = 0; i < nrels; i++)
	{
		GElf_Sym sym;
		GElf_Rel rel;
		unsigned int insn_idx;
		bool match = false;
		int map_idx;

		gelf_getrel(data, i, &rel);

		insn_idx = rel.r_offset / sizeof(struct bpf_insn);

		gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

		if(insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW))
		{
			return scap_errprintf(handle->m_lasterr, 0, "invalid relocation for insn[%d].code 0x%x", insn_idx, insn[insn_idx].code);
		}

		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

		for(map_idx = 0; map_idx < nr_maps; map_idx++)
		{
			if(maps[map_idx].elf_offset == sym.st_value)
			{
				match = true;
				break;
			}
		}

		if(match)
		{
			insn[insn_idx].imm = maps[map_idx].fd;
		}
		else
		{
			return scap_errprintf(handle->m_lasterr, 0, "invalid relocation for insn[%d] no map_data match\n", insn_idx);
		}
	}

	return SCAP_SUCCESS;
}

/* load all bpf programs */
static int32_t load_single_prog(struct bpf_engine* handle, const char *event, struct bpf_insn *prog, int size)
{
	enum bpf_prog_type program_type;
	size_t insns_cnt;
	bool raw_tp;
	int err;
	int fd;
	const char *final_section_name = NULL;

	insns_cnt = size / sizeof(struct bpf_insn);

	char *error = malloc(BPF_LOG_SIZE);
	if(!error)
	{
		return scap_errprintf(handle->m_lasterr, 0, "malloc(BPF_LOG_BUF_SIZE) failed");
	}

	const char *full_event = event;
	if(memcmp(event, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
	{
		raw_tp = true;
		program_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
		event += sizeof("raw_tracepoint/") - 1;
	}
	else
	{
		raw_tp = false;
		program_type = BPF_PROG_TYPE_TRACEPOINT;
		event += sizeof("tracepoint/") - 1;
	}

	if(*event == 0)
	{
		free(error);
		return scap_errprintf(handle->m_lasterr, 0, "event name cannot be empty");
	}

	/* 'event' looks like "raw_tracepoint/raw_syscalls/sys_enter". Skip
	 * to the last word after '/', if possible.
	 */
	final_section_name = strrchr(event, '/');
	if (final_section_name != NULL) {
		final_section_name++;
	} else {
		final_section_name = event;
	}

	fd = bpf_load_program(prog, program_type, insns_cnt, error, BPF_LOG_SIZE, final_section_name);
	if(fd < 0)
	{
		/* It is possible than some old kernels don't support the prog_name so in case
		 * of loading failure, we try again the loading without the name. See it in libbpf:
		 * https://github.com/torvalds/linux/blob/16a8829130ca22666ac6236178a6233208d425c3/tools/lib/bpf/libbpf.c#L4833
		 */
		fd = bpf_load_program(prog, program_type, insns_cnt, error, BPF_LOG_SIZE, NULL);
		if(fd < 0)
		{
			fprintf(stderr, "-- BEGIN PROG LOAD LOG --\n%s\n-- END PROG LOAD LOG --\n", error);
			free(error);
			return scap_errprintf(handle->m_lasterr, -fd, "libscap: bpf_load_program() event=%s", full_event);
		}
	}
	free(error);

	/* If the program is tail called, so not directly attached to the kernel ("filler")
	 * we save the fd and populate the filler table. Note that we store the `fd` to free
	 * the prog at the end of the capture, we will never use it again during the capture!
	 */
	if(memcmp(event, "filler/", sizeof("filler/") - 1) == 0)
	{
		if(handle->m_tail_called_cnt + 1 >= BPF_PROGS_TAIL_CALLED_MAX)
		{
			return scap_errprintf(handle->m_lasterr, 0, "libscap: too many tail_called programs recorded: %d (limit is %d)", handle->m_tail_called_cnt + 1 ,BPF_PROGS_TAIL_CALLED_MAX);
		}

		handle->m_tail_called_fds[handle->m_tail_called_cnt++] = fd;

		event += sizeof("filler/") - 1;
		if(*event == 0)
		{
			return scap_errprintf(handle->m_lasterr, 0, "filler name cannot be empty");
		}

		int prog_id = lookup_filler_id(event);
		if(prog_id == -1)
		{
			return scap_errprintf(handle->m_lasterr, 0, "invalid filler name: %s", event);
		}
		else if (prog_id >= BPF_PROGS_TAIL_CALLED_MAX)
		{
			return scap_errprintf(handle->m_lasterr, 0, "program ID exceeds BPF_PROGS_TAIL_CALLED_MAX limit (%d/%d)", prog_id, BPF_PROGS_TAIL_CALLED_MAX);
		}

		/* Fill the tail table. The key is our filler internal code extracted
		 * from `g_filler_names` in `lookup_filler_id` function. The value
		 * is the program fd.
		 */
		err = bpf_map_update_elem(handle->m_bpf_map_fds[handle->m_bpf_prog_array_map_idx], &prog_id, &fd, BPF_ANY);
		if(err < 0)
		{
			return scap_errprintf(handle->m_lasterr, -err, "failure populating program array");
		}

		return SCAP_SUCCESS;
	}

	/* If we reach this point we are evaluating a program that should be directly attached to the kernel */
	if(is_sys_enter(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SYS_ENTER], raw_tp, event, fd);
	}

	if(is_sys_exit(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SYS_EXIT], raw_tp, event, fd);
	}

	if(is_sched_proc_exit(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SCHED_PROC_EXIT], raw_tp, event, fd);
	}

	if(is_sched_switch(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SCHED_SWITCH], raw_tp, event, fd);
	}

	if(is_page_fault_user(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_PAGE_FAULT_USER], raw_tp, event, fd);
	}

	if(is_page_fault_kernel(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_PAGE_FAULT_KERNEL], raw_tp, event, fd);
	}

	if(is_signal_deliver(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SIGNAL_DELIVER], raw_tp, event, fd);
	}

	if(is_sched_prog_fork_move_args(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SCHED_PROC_FORK_MOVE_ARGS], raw_tp, event, fd);
	}

	if(is_sched_prog_fork_missing_child(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SCHED_PROC_FORK_MISSING_CHILD], raw_tp, event, fd);
	}

	if(is_sched_prog_exec_missing_exit(event))
	{
		fill_attached_prog_info(&handle->m_attached_progs[BPF_PROG_SCHED_PROC_EXEC_MISSING_EXIT], raw_tp, event, fd);
	}

	return SCAP_SUCCESS;
}

static int32_t load_bpf_file(struct bpf_engine *handle)
{
	int j;
	int maps_shndx = 0;
	int strtabidx = 0;
	GElf_Shdr shdr;
	GElf_Shdr shdr_prog;
	Elf_Data *data;
	Elf_Data *data_prog;
	Elf_Data *symbols = NULL;
	char *shname;
	char *shname_prog;
	int nr_maps = 0;
	struct bpf_map_data maps[BPF_MAPS_MAX];
	struct utsname osname;
	int32_t res = SCAP_FAILURE;
	bool got_api_version = false;
	bool got_schema_version = false;

	if(uname(&osname))
	{
		return scap_errprintf(handle->m_lasterr, errno, "can't call uname()");
	}

	if(elf_version(EV_CURRENT) == EV_NONE)
	{
		return scap_errprintf(handle->m_lasterr, 0, "invalid ELF version");
	}

	if (!handle->elf)
	{
		handle->program_fd = open(handle->m_filepath, O_RDONLY, 0);
		if(handle->program_fd < 0)
		{
			return scap_errprintf(handle->m_lasterr, 0, "can't open BPF probe '%s'", handle->m_filepath);
		}

		handle->elf = elf_begin(handle->program_fd, ELF_C_READ_MMAP_PRIVATE, NULL);
		if(!handle->elf)
		{
			scap_errprintf(handle->m_lasterr, 0, "can't read ELF format");
			goto end;
		}

		if(gelf_getehdr(handle->elf, &handle->ehdr) != &handle->ehdr)
		{
			scap_errprintf(handle->m_lasterr, 0, "can't read ELF header");
			goto end;
		}

		for(j = 0; j < handle->ehdr.e_shnum; ++j)
		{
			if(get_elf_section(handle->elf, j, &handle->ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
			{
				continue;
			}

			if(strcmp(shname, "maps") == 0)
			{
				maps_shndx = j;
			}
			else if(shdr.sh_type == SHT_SYMTAB)
			{
				strtabidx = shdr.sh_link;
				symbols = data;
			}
			else if(strcmp(shname, "kernel_version") == 0)
			{
				if(strcmp(osname.release, data->d_buf))
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe is compiled for %s, but running version is %s",
						 (char *)data->d_buf, osname.release);
					goto end;
				}
			}
			else if(strcmp(shname, "api_version") == 0)
			{
				got_api_version = true;
				memcpy(&handle->m_api_version, data->d_buf, sizeof(handle->m_api_version));
			}
			else if(strcmp(shname, "schema_version") == 0)
			{
				got_schema_version = true;
				memcpy(&handle->m_schema_version, data->d_buf, sizeof(handle->m_schema_version));
			}
			else if(strcmp(shname, "license") == 0)
			{
				license = data->d_buf;
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe license is %s", license);
			}
		}

		if(!got_api_version)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "missing api_version section");
			goto end;
		}

		if(!got_schema_version)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "missing schema_version section");
			goto end;
		}

		if(!symbols)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "missing SHT_SYMTAB section");
			goto end;
		}

		if(maps_shndx)
		{
			if(load_elf_maps_section(handle, maps, maps_shndx, handle->elf, symbols, strtabidx, &nr_maps) != SCAP_SUCCESS)
			{
				goto end;
			}

			if(load_maps(handle, maps, nr_maps) != SCAP_SUCCESS)
			{
				goto end;
			}
		}

		for(j = 0; j < handle->ehdr.e_shnum; ++j)
		{
			if(get_elf_section(handle->elf, j, &handle->ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
			{
				continue;
			}

			if(shdr.sh_type == SHT_REL)
			{
				struct bpf_insn *insns;

				if(get_elf_section(handle->elf, shdr.sh_info, &handle->ehdr, &shname_prog, &shdr_prog, &data_prog) != SCAP_SUCCESS)
				{
					continue;
				}

				insns = (struct bpf_insn *)data_prog->d_buf;

				if(parse_relocations(handle, data, symbols, &shdr, insns, maps, nr_maps))
				{
					continue;
				}
			}
		}
	}
	res = SCAP_SUCCESS;
end:
	return res;
}

static int load_all_progs(struct bpf_engine *handle)
{
	GElf_Shdr shdr;
	Elf_Data *data;
	char *shname;

	for(int j = 0; j < handle->ehdr.e_shnum; ++j)
	{
		if(get_elf_section(handle->elf, j, &handle->ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		if(memcmp(shname, "tracepoint/", sizeof("tracepoint/") - 1) == 0 ||
		   memcmp(shname, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
		{

			if(load_single_prog(handle, shname, data->d_buf, data->d_size) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
		}
	}
	return SCAP_SUCCESS;
}

static int allocate_scap_stats_v2(struct bpf_engine *handle)
{
	int nprogs_attached = 0;
	for(int j=0; j < BPF_PROG_ATTACHED_MAX; j++)
	{
		if (handle->m_attached_progs[j].fd != -1)
		{
			nprogs_attached++;
		}
	}
	handle->m_nstats = (BPF_MAX_KERNEL_COUNTERS_STATS + (nprogs_attached * BPF_MAX_LIBBPF_STATS));
	handle->m_stats = (scap_stats_v2 *)malloc(handle->m_nstats * sizeof(scap_stats_v2));

	if(!handle->m_stats)
	{
		handle->m_nstats = 0;
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

static void *perf_event_mmap(struct bpf_engine *handle, int fd, unsigned long *size, unsigned long buf_bytes_dim)
{
	int page_size = getpagesize();
	unsigned long ring_size = buf_bytes_dim;
	int header_size = page_size;
	unsigned long total_size = ring_size * 2 + header_size;

	*size = 0;

	//
	// All this playing with MAP_FIXED might be very very wrong, revisit
	//

	void *tmp = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(tmp == MAP_FAILED)
	{
		scap_errprintf(handle->m_lasterr, errno, "mmap (1) failed (If you get memory allocation errors try to reduce the buffer dimension)");
		return MAP_FAILED;
	}

	// Map the second copy to allow us to handle the wrap case normally
	void *p1 = mmap(tmp + ring_size, ring_size + header_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	if(p1 == MAP_FAILED)
	{
		scap_errprintf(handle->m_lasterr, errno, "mmap (2) failed (If you get memory allocation errors try to reduce the buffer dimension)");
		munmap(tmp, total_size);
		return MAP_FAILED;
	}

	ASSERT(p1 == tmp + ring_size);

	// Map the main copy
	void *p2 = mmap(tmp, ring_size + header_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	if(p2 == MAP_FAILED)
	{
		scap_errprintf(handle->m_lasterr, errno, "mmap (3) failed (If you get memory allocation errors try to reduce the buffer dimension)");
		munmap(tmp, total_size);
		return MAP_FAILED;
	}

	ASSERT(p2 == tmp);

	*size = total_size;

	return tmp;
}

static int32_t populate_syscall_table_map(struct bpf_engine *handle)
{
	int j;
	int ret;

	for(j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		const struct syscall_evt_pair *p = &g_syscall_table[j];
		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SYSCALL_TABLE], &j, p, BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SYSCALL_TABLE bpf_map_update_elem");
		}
	}

	return bpf_map_freeze(handle->m_bpf_map_fds[SCAP_SYSCALL_TABLE]);
}

static int32_t set_single_syscall_of_interest(struct bpf_engine *handle, int syscall_id, bool interesting)
{
	int ret = 0;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_INTERESTING_SYSCALLS_TABLE], &syscall_id, &interesting, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_INTERESTING_SYSCALLS_TABLE unable to update syscall: %d", syscall_id);
	}
	return SCAP_SUCCESS;
}

static int32_t populate_event_table_map(struct bpf_engine *handle)
{
	int j;
	int ret;

	for(j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_info *e = &g_event_info[j];
		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_EVENT_INFO_TABLE], &j, e, BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret, "SCAP_EVENT_INFO_TABLE bpf_map_update_elem");
		}
	}

	return bpf_map_freeze(handle->m_bpf_map_fds[SCAP_EVENT_INFO_TABLE]);
}

static int32_t populate_fillers_table_map(struct bpf_engine *handle)
{
	int j;
	int ret;

	for(j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_entry *e = &g_ppm_events[j];
		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_FILLERS_TABLE], &j, e, BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret, "SCAP_FILLERS_TABLE bpf_map_update_elem ");
		}
	}

	/* Even if the filler ppm code is defined it could happen that there
	 * is no filler implementation, some fillers are architecture-specifc.
	 * For example `sched_prog_exec` filler exists only on `ARM64` while
	 * `sys_pagefault_e` exists only on `x86`.
	 */

	return bpf_map_freeze(handle->m_bpf_map_fds[SCAP_FILLERS_TABLE]);
}

static int32_t populate_ia32_to_64_map(struct bpf_engine *handle)
{
	int j;
	int ret;

	for(j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		// Note: we will map all syscalls from the upper limit of the ia32 table
		// up to SYSCALL_TABLE_SIZE to 0 (because they are not set in the g_ia32_64_map).
		// 0 is read on x86_64; this is not a problem though because
		// we will never receive a 32bit syscall above the upper limit, since it won't be existent
		const int *x64_val = &g_ia32_64_map[j];
		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_IA32_64_MAP], &j, x64_val,
					      BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret,
					      "SCAP_FILLERS_TABLE bpf_map_update_elem ");
		}
	}
	return bpf_map_freeze(handle->m_bpf_map_fds[SCAP_IA32_64_MAP]);
}

static int enforce_sc_set(struct bpf_engine* handle)
{
	/* handle->capturing == false means that we want to disable the capture */
	bool* sc_set = handle->curr_sc_set.ppm_sc;
	bool empty_sc_set[PPM_SC_MAX] = {0};
	if(!handle->capturing)
	{
		/* empty set to erase all */
		sc_set = empty_sc_set;
	}

	int ret = 0;
	int syscall_id = 0;
	/* Special tracepoints, their attachment depends on interesting syscalls */
	bool sys_enter = false;
	bool sys_exit = false;
	bool sched_prog_fork_move_args = false;
	bool sched_prog_fork_missing_child = false;
	bool sched_prog_exec = false;

	/* Enforce interesting syscalls */
	for(int sc = 0; sc < PPM_SC_MAX; sc++)
	{
		syscall_id = scap_ppm_sc_to_native_id(sc);
		/* if `syscall_id` is -1 this is not a syscall */
		if(syscall_id == -1)
		{
			continue;
		}

		if(!sc_set[sc])
		{
			set_single_syscall_of_interest(handle, syscall_id, false);
		}
		else
		{
			sys_enter = true;
			sys_exit = true;
			sched_prog_fork_move_args = true;
			set_single_syscall_of_interest(handle, syscall_id, true);
		}
	}

	if(sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK] ||
	   sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3])
	{
		sched_prog_fork_missing_child = true;
	}

	if(sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		sched_prog_exec = true;
	}

	/* Enable desired tracepoints */
	if(sys_enter)
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SYS_ENTER]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SYS_ENTER]));

	if(sys_exit)
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SYS_EXIT]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SYS_EXIT]));

	if(sched_prog_fork_move_args)
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_FORK_MOVE_ARGS]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_FORK_MOVE_ARGS]));

	if(sched_prog_fork_missing_child)
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_FORK_MISSING_CHILD]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_FORK_MISSING_CHILD]));

	if(sched_prog_exec)
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_EXEC_MISSING_EXIT]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_EXEC_MISSING_EXIT]));

	if(sc_set[PPM_SC_SCHED_PROCESS_EXIT])
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_EXIT]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_PROC_EXIT]));

	if(sc_set[PPM_SC_SCHED_SWITCH])
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_SWITCH]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SCHED_SWITCH]));

	if(sc_set[PPM_SC_PAGE_FAULT_USER])
		ret = ret ?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_PAGE_FAULT_USER]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_PAGE_FAULT_USER]));

	if(sc_set[PPM_SC_PAGE_FAULT_KERNEL])
		ret = ret?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_PAGE_FAULT_KERNEL]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_PAGE_FAULT_KERNEL]));

	if(sc_set[PPM_SC_SIGNAL_DELIVER])
		ret = ret?: attach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SIGNAL_DELIVER]), handle->m_lasterr);
	else
		detach_bpf_prog(&(handle->m_attached_progs[BPF_PROG_SIGNAL_DELIVER]));

	return ret;
}

int32_t scap_bpf_start_capture(struct scap_engine_handle engine)
{
	struct bpf_engine* handle = engine.m_handle;
	int32_t rc = 0;
	/* Here we are covering the case in which some syscalls don't have an associated ppm_sc
	 * and so we cannot set them as (un)interesting. For this reason, we default them to 0.
	 * Please note this is an extra check since our ppm_sc should already cover all possible syscalls.
	 * Ideally we should do this only once, but right now in our code we don't have a "right" place to do it.
	 * We need to move it, if `scap_start_capture` will be called frequently in our flow, right now in live mode, it
	 * should be called only once...
	 */
	for(int i = 0; i < SYSCALL_TABLE_SIZE; i++)
	{
		rc = set_single_syscall_of_interest(handle, i, false);
		if(rc != SCAP_SUCCESS)
		{
			return rc;
		}
	}
	handle->capturing = true;
	return enforce_sc_set(handle);
}

int32_t scap_bpf_stop_capture(struct scap_engine_handle engine)
{
	struct bpf_engine* handle = engine.m_handle;
	handle->capturing = false;
	return enforce_sc_set(handle);
}

//
// This is needed to make sure that the driver can properly
// lookup sockets. We generate a fake socket system call
// at the beginning so the calibration will surely take place.
// For more info, read the corresponding filler in kernel space.
//
static int32_t calibrate_socket_file_ops(struct scap_engine_handle engine)
{
	/* We just need to enable the socket syscall for the socket calibration */
	engine.m_handle->curr_sc_set.ppm_sc[PPM_SC_SOCKET] = 1;
	if(scap_bpf_start_capture(engine) != SCAP_SUCCESS)
	{
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "unable to set the socket syscall for the calibration");
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "unable to create a socket for the calibration");
	}
	close(fd);

	/* We need to stop the capture */
	if(scap_bpf_stop_capture(engine) != SCAP_SUCCESS)
	{
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "unable to stop the capture after the calibration");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_snaplen(struct scap_engine_handle engine, uint32_t snaplen)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if(snaplen > SNAPLEN_MAX)
	{
		return scap_errprintf(handle->m_lasterr, 0, "snaplen can't exceed %d\n", SNAPLEN_MAX);
	}

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.snaplen = snaplen;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_fullcapture_port_range(struct scap_engine_handle engine, uint16_t range_start, uint16_t range_end)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.fullcapture_port_range_start = range_start;
	settings.fullcapture_port_range_end = range_end;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_statsd_port(struct scap_engine_handle engine, const uint16_t port)
{
	struct scap_bpf_settings settings = {};
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.statsd_port = port;

	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_disable_dynamic_snaplen(struct scap_engine_handle engine)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.do_dynamic_snaplen = false;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_start_dropping_mode(struct scap_engine_handle engine, uint32_t sampling_ratio)
{
	struct bpf_engine *handle = engine.m_handle;
	struct scap_bpf_settings settings;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.sampling_ratio = sampling_ratio;
	settings.dropping_mode = true;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_stop_dropping_mode(struct scap_engine_handle engine)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.sampling_ratio = 1;
	settings.dropping_mode = false;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_dynamic_snaplen(struct scap_engine_handle engine)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.do_dynamic_snaplen = true;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_close(struct scap_engine_handle engine)
{
	struct bpf_engine *handle = engine.m_handle;

	struct scap_device_set *devset = &handle->m_dev_set;

	devset_free(devset);

	/* Unload all tail called progs */
	for(int j = 0; j < BPF_PROGS_TAIL_CALLED_MAX; j++)
	{
		if(handle->m_tail_called_fds[j] != -1)
		{
			close(handle->m_tail_called_fds[j]);
		}
	}
	handle->m_tail_called_cnt = 0;


	for(int j = 0; j < BPF_PROG_ATTACHED_MAX; j++)
	{
		detach_bpf_prog(&handle->m_attached_progs[j]);
		unload_bpf_prog(&handle->m_attached_progs[j]);
	}

	handle->m_bpf_prog_array_map_idx = -1;

	if (handle->elf)
	{
		elf_end(handle->elf);
		handle->elf = NULL;
	}
	if (handle->m_stats)
	{
		free(handle->m_stats);
		handle->m_stats = NULL;
	}
	if (handle->program_fd > 0)
	{
		close(handle->program_fd);
		handle->program_fd = -1;
	}

	return SCAP_SUCCESS;
}

static int32_t set_runtime_params(struct bpf_engine *handle)
{
	struct rlimit rl;
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = rl.rlim_max;
	if(setrlimit(RLIMIT_MEMLOCK, &rl))
	{
		return scap_errprintf(handle->m_lasterr, errno, "setrlimit failed");
	}

	FILE *f = fopen("/proc/sys/net/core/bpf_jit_enable", "w");
	if(!f)
	{
		// snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_enable");
		// return SCAP_FAILURE;

		// Not every kernel has BPF_JIT enabled. Fix this after COS changes.
		return SCAP_SUCCESS;
	}

	if(fprintf(f, "1") != 1)
	{
		int err = errno;
		fclose(f);
		return scap_errprintf(handle->m_lasterr, err, "Can't write to /proc/sys/net/core/bpf_jit_enable");
	}

	fclose(f);

	f = fopen("/proc/sys/net/core/bpf_jit_harden", "w");
	if(!f)
	{
		return scap_errprintf(handle->m_lasterr, errno, "Can't open /proc/sys/net/core/bpf_jit_harden");
	}

	if(fprintf(f, "0") != 1)
	{
		int err = errno;
		fclose(f);
		return scap_errprintf(handle->m_lasterr, err, "Can't write to /proc/sys/net/core/bpf_jit_harden");
	}

	fclose(f);

	f = fopen("/proc/sys/net/core/bpf_jit_kallsyms", "w");
	if(!f)
	{
		return scap_errprintf(handle->m_lasterr, errno, "Can't open /proc/sys/net/core/bpf_jit_kallsyms");
	}

	if(fprintf(f, "1") != 1)
	{
		int err = errno;
		fclose(f);
		return scap_errprintf(handle->m_lasterr, err, "Can't write to /proc/sys/net/core/bpf_jit_kallsyms");
	}

	fclose(f);

	return SCAP_SUCCESS;
}

static int32_t set_default_settings(struct bpf_engine *handle)
{
	struct scap_bpf_settings settings;

	uint64_t boot_time = 0;
	if(scap_get_precise_boot_time(handle->m_lasterr, &boot_time) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	settings.boot_time = boot_time;
	settings.socket_file_ops = NULL;
	settings.snaplen = SNAPLEN;
	settings.sampling_ratio = 1;
	settings.do_dynamic_snaplen = false;
	settings.dropping_mode = false;
	settings.is_dropping = false;
	settings.drop_failed = false;
	settings.fullcapture_port_range_start = 0;
	settings.fullcapture_port_range_end = 0;
	settings.statsd_port = PPM_PORT_STATSD;

	int k = 0;
	int ret;

	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_load(
	struct bpf_engine *handle,
	const char *bpf_probe,
	scap_open_args *oargs)
{
	struct scap_bpf_engine_params* bpf_args = oargs->engine_params;

	if(set_runtime_params(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	handle->m_bpf_prog_array_map_idx = -1;

	if(!bpf_probe)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	snprintf(handle->m_filepath, PATH_MAX, "%s", bpf_probe);

	if(load_bpf_file(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	/* load all progs but don't attach anything */
	if(load_all_progs(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	/* allocate_scap_stats_v2 dynamically based on number of valid m_attached_progs,
	 * In the future, it may change when and how we perform the allocation.
	 */
	if(allocate_scap_stats_v2(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_syscall_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_event_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_fillers_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if (populate_ia32_to_64_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Open and initialize all the devices
	//
	struct scap_device_set *devset = &handle->m_dev_set;
	uint32_t online_idx = 0;
	// devset->m_ndevs = online CPUs in the system.
	// handle->m_ncpus = available CPUs in the system.
	for(uint32_t cpu_idx = 0; online_idx < devset->m_ndevs && cpu_idx < handle->m_ncpus; ++cpu_idx)
	{
		struct perf_event_attr attr = {
			.sample_type = PERF_SAMPLE_RAW,
			.type = PERF_TYPE_SOFTWARE,
			.config = PERF_COUNT_SW_BPF_OUTPUT,
		};
		int pmu_fd = 0;
		int ret = 0;

		/* We suppose that CPU 0 is always online, so we only check for cpu_idx > 0 */
		if(cpu_idx > 0)
		{
			char filename[SCAP_MAX_PATH_SIZE];
			FILE *fp;
			int online = 0;

			snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", cpu_idx);

			fp = fopen(filename, "r");
			if(fp == NULL)
			{
				// When missing NUMA properties, CPUs do not expose online information.
				// Fallback at considering them online if we can at least reach their folder.
				// This is useful for example for raspPi devices.
				// See: https://github.com/kubernetes/kubernetes/issues/95039
				snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/", cpu_idx);
				if (access(filename, F_OK) == 0)
				{
					online = 1;
				}
				// If we can't access the cpu, count it as offline.
				// Some VMs or hyperthreading systems export an high number of configured CPUs,
				// even if they are not existing. See https://github.com/falcosecurity/falco/issues/2843 for example.
				// Skip them.
			}
			else
			{
				if(fscanf(fp, "%d", &online) != 1)
				{
					int err = errno;
					fclose(fp);

					return scap_errprintf(handle->m_lasterr, err, "can't read %s", filename);
				}
				fclose(fp);
			}

			if(!online)
			{
				continue;
			}
		}

		pmu_fd = sys_perf_event_open(&attr, -1, cpu_idx, -1, 0);
		if(pmu_fd < 0)
		{
			return scap_errprintf(handle->m_lasterr, -pmu_fd, "unable to open the perf-buffer for cpu '%d'", cpu_idx);
		}

		struct scap_device *dev = &devset->m_devs[online_idx];
		dev->m_fd = pmu_fd;

		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_PERF_MAP], &cpu_idx, &pmu_fd, BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret, "unable to update the SCAP_PERF_MAP map for cpu '%d'", cpu_idx);
		}

		if(ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
		{
			return scap_errprintf(handle->m_lasterr, errno, "unable to call PERF_EVENT_IOC_ENABLE on the fd for cpu '%d'", cpu_idx);
		}

		//
		// Map the ring buffer
		//
		dev->m_buffer = perf_event_mmap(handle, pmu_fd, &dev->m_mmap_size, bpf_args->buffer_bytes_dim);
		dev->m_buffer_size = bpf_args->buffer_bytes_dim;
		if(dev->m_buffer == MAP_FAILED)
		{
			return scap_errprintf(handle->m_lasterr, errno, "unable to mmap the perf-buffer for cpu '%d'", cpu_idx);
		}
		online_idx++;
	}

	// Check that we parsed all online CPUs
	if(online_idx != devset->m_ndevs)
	{
		return scap_errprintf(handle->m_lasterr, 0, "mismatch, processors online after the 'for' loop: %d, '_SC_NPROCESSORS_ONLN' before the 'for' loop: %d", online_idx, devset->m_ndevs);
	}

	// Check that no CPUs were hotplugged during the for loop
	uint32_t final_ndevs = sysconf(_SC_NPROCESSORS_ONLN);
	if(final_ndevs == -1)
	{
		return scap_errprintf(handle->m_lasterr, errno, "cannot obtain the number of online CPUs from '_SC_NPROCESSORS_ONLN' to check against the previous value");
	}
	if (online_idx != final_ndevs)
	{
		return scap_errprintf(handle->m_lasterr, 0, "mismatch, processors online after the 'for' loop: %d, '_SC_NPROCESSORS_ONLN' after the 'for' loop: %d", online_idx, final_ndevs);
	}


	if(set_default_settings(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_get_stats(struct scap_engine_handle engine, OUT scap_stats* stats)
{
	struct bpf_engine *handle = engine.m_handle;
	int j;
	int ret;

	for(j = 0; j < handle->m_ncpus; j++)
	{
		struct scap_bpf_per_cpu_state v;
		if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_LOCAL_STATE_MAP], &j, &v)))
		{
			return scap_errprintf(handle->m_lasterr, -ret, "Error looking up local state %d", j);
		}

		stats->n_evts += v.n_evts;
		stats->n_drops_buffer += v.n_drops_buffer;
		stats->n_drops_buffer_clone_fork_enter += v.n_drops_buffer_clone_fork_enter;
		stats->n_drops_buffer_clone_fork_exit += v.n_drops_buffer_clone_fork_exit;
		stats->n_drops_buffer_execve_enter += v.n_drops_buffer_execve_enter;
		stats->n_drops_buffer_execve_exit += v.n_drops_buffer_execve_exit;
		stats->n_drops_buffer_connect_enter += v.n_drops_buffer_connect_enter;
		stats->n_drops_buffer_connect_exit += v.n_drops_buffer_connect_exit;
		stats->n_drops_buffer_open_enter += v.n_drops_buffer_open_enter;
		stats->n_drops_buffer_open_exit += v.n_drops_buffer_open_exit;
		stats->n_drops_buffer_dir_file_enter += v.n_drops_buffer_dir_file_enter;
		stats->n_drops_buffer_dir_file_exit += v.n_drops_buffer_dir_file_exit;
		stats->n_drops_buffer_other_interest_enter += v.n_drops_buffer_other_interest_enter;
		stats->n_drops_buffer_other_interest_exit += v.n_drops_buffer_other_interest_exit;
		stats->n_drops_buffer_close_exit += v.n_drops_buffer_close_exit;
		stats->n_drops_buffer_proc_exit += v.n_drops_buffer_proc_exit;
		stats->n_drops_scratch_map += v.n_drops_scratch_map;
		stats->n_drops_pf += v.n_drops_pf;
		stats->n_drops_bug += v.n_drops_bug;
		stats->n_drops += v.n_drops_buffer +
				  v.n_drops_scratch_map +
				  v.n_drops_pf +
				  v.n_drops_bug;
	}

	return SCAP_SUCCESS;
}

const struct scap_stats_v2* scap_bpf_get_stats_v2(struct scap_engine_handle engine, uint32_t flags, OUT uint32_t* nstats, OUT int32_t* rc)
{
	struct bpf_engine *handle = engine.m_handle;
	int ret;
	int fd;
	int offset = 0; // offset in stats buffer
	*nstats = 0;
	uint32_t nstats_allocated = handle->m_nstats;
	scap_stats_v2* stats = handle->m_stats;
	if (!stats)
	{
		*rc = SCAP_FAILURE;
		return NULL;
	}

	// we can't collect libbpf stats if bpf stats are not enabled
	if (!(handle->m_flags & ENGINE_FLAG_BPF_STATS_ENABLED))
	{
		flags &= ~PPM_SCAP_STATS_LIBBPF_STATS;
	}

	if ((flags & PPM_SCAP_STATS_KERNEL_COUNTERS) && (BPF_MAX_KERNEL_COUNTERS_STATS <= nstats_allocated))
	{
		/* KERNEL SIDE STATS COUNTERS */
		for(int stat = 0; stat < BPF_MAX_KERNEL_COUNTERS_STATS; stat++)
		{
			stats[stat].type = STATS_VALUE_TYPE_U64;
			stats[stat].flags = PPM_SCAP_STATS_KERNEL_COUNTERS;
			stats[stat].value.u64 = 0;
			strlcpy(stats[stat].name, bpf_kernel_counters_stats_names[stat], STATS_NAME_MAX);
		}

		for(int cpu = 0; cpu < handle->m_ncpus; cpu++)
		{
			struct scap_bpf_per_cpu_state v;
			if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_LOCAL_STATE_MAP], &cpu, &v)))
			{
				*rc = scap_errprintf(handle->m_lasterr, -ret, "Error looking up local state %d", cpu);
				return stats;
			}
			stats[BPF_N_EVTS].value.u64 += v.n_evts;
			stats[BPF_N_DROPS_BUFFER_TOTAL].value.u64 += v.n_drops_buffer;
			stats[BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER].value.u64 += v.n_drops_buffer_clone_fork_enter;
			stats[BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT].value.u64 += v.n_drops_buffer_clone_fork_exit;
			stats[BPF_N_DROPS_BUFFER_EXECVE_ENTER].value.u64 += v.n_drops_buffer_execve_enter;
			stats[BPF_N_DROPS_BUFFER_EXECVE_EXIT].value.u64 += v.n_drops_buffer_execve_exit;
			stats[BPF_N_DROPS_BUFFER_CONNECT_ENTER].value.u64 += v.n_drops_buffer_connect_enter;
			stats[BPF_N_DROPS_BUFFER_CONNECT_EXIT].value.u64 += v.n_drops_buffer_connect_exit;
			stats[BPF_N_DROPS_BUFFER_OPEN_ENTER].value.u64 += v.n_drops_buffer_open_enter;
			stats[BPF_N_DROPS_BUFFER_OPEN_EXIT].value.u64 += v.n_drops_buffer_open_exit;
			stats[BPF_N_DROPS_BUFFER_DIR_FILE_ENTER].value.u64 += v.n_drops_buffer_dir_file_enter;
			stats[BPF_N_DROPS_BUFFER_DIR_FILE_EXIT].value.u64 += v.n_drops_buffer_dir_file_exit;
			stats[BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER].value.u64 += v.n_drops_buffer_other_interest_enter;
			stats[BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT].value.u64 += v.n_drops_buffer_other_interest_exit;
			stats[BPF_N_DROPS_BUFFER_CLOSE_EXIT].value.u64 += v.n_drops_buffer_close_exit;
			stats[BPF_N_DROPS_BUFFER_PROC_EXIT].value.u64 += v.n_drops_buffer_proc_exit;
			stats[BPF_N_DROPS_SCRATCH_MAP].value.u64 += v.n_drops_scratch_map;
			stats[BPF_N_DROPS_PAGE_FAULTS].value.u64 += v.n_drops_pf;
			stats[BPF_N_DROPS_BUG].value.u64 += v.n_drops_bug;
			stats[BPF_N_DROPS].value.u64 += v.n_drops_buffer + \
				v.n_drops_scratch_map + \
				v.n_drops_pf + \
				v.n_drops_bug;
		}
		offset = BPF_MAX_KERNEL_COUNTERS_STATS;
	}

	/* LIBBPF STATS */

	/* At the time of writing (Apr 2, 2023) libbpf stats are only available on a per program granularity.
	 * This means we cannot measure the statistics for each filler / tail call individually.
	 * Hopefully someone upstreams such capabilities to libbpf one day :)
	 * Meanwhile, we can simulate perf comparisons between future LSM hooks and sys enter and exit tracepoints
	 * via leveraging syscall selection mechanisms `handle->curr_sc_set`.
	 *
	 * Please note that libbpf stats are available only on kernels >= 5.1, they could be backported but
	 * it's possible that in some of our supported kernels they won't be available.
	 */
	if ((flags & PPM_SCAP_STATS_LIBBPF_STATS))
	{
		for(int bpf_prog = 0; bpf_prog < BPF_PROG_ATTACHED_MAX; bpf_prog++)
		{
			fd = handle->m_attached_progs[bpf_prog].fd;
			if (fd < 0)
			{
				// we loop through each possible prog, landing here means prog was not attached
				continue;
			}
			struct bpf_prog_info info = {};
			__u32 len = sizeof(info);
			if((ret = bpf_obj_get_info_by_fd(fd, &info, &len)))
			{
				*rc = scap_errprintf(handle->m_lasterr, -ret, "Error getting bpf prog info for fd %d", fd);
				continue;
			}

			for(int stat = 0; stat < BPF_MAX_LIBBPF_STATS; stat++)
			{
				if (offset > nstats_allocated - 1)
				{
					break;
				}
				stats[offset].type = STATS_VALUE_TYPE_U64;
				stats[offset].flags = PPM_SCAP_STATS_LIBBPF_STATS;
				/* The possibility to specify a name for a BPF program was introduced in kernel 4.15
				 * https://github.com/torvalds/linux/commit/cb4d2b3f03d8eed90be3a194e5b54b734ec4bbe9
				 * So it's possible that in some of our supported kernels `info.name` will be "".
				 */
				if(strlen(info.name) == 0)
				{
					/* Fallback on the elf section name */
					strlcpy(stats[offset].name, handle->m_attached_progs[bpf_prog].name, STATS_NAME_MAX);
				}
				else
				{
					strlcpy(stats[offset].name, info.name, STATS_NAME_MAX);
				}
				switch(stat)
				{
				case RUN_CNT:
					strlcat(stats[offset].name, bpf_libbpf_stats_names[RUN_CNT], sizeof(stats[offset].name));
					stats[offset].value.u64 = info.run_cnt;
					break;
				case RUN_TIME_NS:
					strlcat(stats[offset].name, bpf_libbpf_stats_names[RUN_TIME_NS], sizeof(stats[offset].name));
					stats[offset].value.u64 = info.run_time_ns;
					break;
				case AVG_TIME_NS:
					strlcat(stats[offset].name, bpf_libbpf_stats_names[AVG_TIME_NS], sizeof(stats[offset].name));
					stats[offset].value.u64 = 0;
					if (info.run_cnt > 0)
					{
						stats[offset].value.u64 = info.run_time_ns / info.run_cnt;
					}
					break;
				default:
					break;
				}
				offset++;
			}
		}
	}
	*nstats = offset; // return true number of stats that were available as libbpf metrics are a function of attached progs
	*rc = SCAP_SUCCESS;
	return stats;
}

int32_t scap_bpf_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	struct bpf_engine *handle = engine.m_handle;
	int j;
	int sys_ret;

	for(j = 0; j < handle->m_ncpus; j++)
	{
		struct scap_bpf_per_cpu_state v;
		if((sys_ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_LOCAL_STATE_MAP], &j, &v)))
		{
			return scap_errprintf(handle->m_lasterr, -sys_ret, "Error looking up local state %d\n", j);
		}

		ret[j] = v.n_evts;
	}

	return SCAP_SUCCESS;
}

static int32_t next(struct scap_engine_handle engine, OUT scap_evt **pevent, OUT uint16_t *pdevid, OUT uint32_t *pflags)
{
	return ringbuffer_next(&engine.m_handle->m_dev_set, pevent, pdevid, pflags);
}

static int32_t unsupported_config(struct scap_engine_handle engine, const char* msg)
{
	struct bpf_engine* handle = engine.m_handle;

	strlcpy(handle->m_lasterr, msg, SCAP_LASTERR_SIZE);
	return SCAP_FAILURE;
}

static int32_t scap_bpf_handle_dropfailed(struct scap_engine_handle engine, bool drop_failed)
{
	struct bpf_engine *handle = engine.m_handle;
	struct scap_bpf_settings settings;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.drop_failed = drop_failed;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

static int32_t scap_bpf_handle_sc(struct scap_engine_handle engine, uint32_t op, uint32_t sc)
{
	struct bpf_engine* handle = engine.m_handle;
	handle->curr_sc_set.ppm_sc[sc] = op == SCAP_PPM_SC_MASK_SET;
	/* We update the system state only if the capture is started
	 * otherwise there is the risk to enable again tracepoints
	 */
	if(handle->capturing)
	{
		return enforce_sc_set(handle);
	}
	return SCAP_SUCCESS;
}

static int32_t configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	switch(setting)
	{
	case SCAP_SAMPLING_RATIO:
		if(arg2 == 0)
		{
			return scap_bpf_stop_dropping_mode(engine);
		}
		else
		{
			return scap_bpf_start_dropping_mode(engine, arg1);
		}
	case SCAP_SNAPLEN:
		return scap_bpf_set_snaplen(engine, arg1);
	case SCAP_PPM_SC_MASK:
		return scap_bpf_handle_sc(engine, arg1, arg2);
	case SCAP_DROP_FAILED:
		return scap_bpf_handle_dropfailed(engine, arg1);
	case SCAP_DYNAMIC_SNAPLEN:
		if(arg1 == 0)
		{
			return scap_bpf_disable_dynamic_snaplen(engine);
		}
		else
		{
			return scap_bpf_enable_dynamic_snaplen(engine);
		}
	case SCAP_FULLCAPTURE_PORT_RANGE:
		return scap_bpf_set_fullcapture_port_range(engine, arg1, arg2);
	case SCAP_STATSD_PORT:
		return scap_bpf_set_statsd_port(engine, arg1);
	default:
	{
		char msg[SCAP_LASTERR_SIZE];
		snprintf(msg, sizeof(msg), "Unsupported setting %d (args %lu, %lu)", setting, arg1, arg2);
		return unsupported_config(engine, msg);
	}
	}
}

static int32_t init(scap_t* handle, scap_open_args *oargs)
{
	int32_t rc = 0;
	char bpf_probe_buf[SCAP_MAX_PATH_SIZE] = {0};
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_bpf_engine_params *params = oargs->engine_params;
	strlcpy(bpf_probe_buf, params->bpf_probe, SCAP_MAX_PATH_SIZE);

	if(check_buffer_bytes_dim(engine.m_handle->m_lasterr, params->buffer_bytes_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Find out how many devices we have to open, which equals to the number of online CPUs
	//
	ssize_t num_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if(num_cpus == -1)
	{
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "cannot obtain the number of available CPUs from '_SC_NPROCESSORS_CONF'");
	}

	engine.m_handle->m_ncpus = num_cpus;

	ssize_t num_devs = sysconf(_SC_NPROCESSORS_ONLN);
	if(num_devs == -1)
	{
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "cannot obtain the number of online CPUs from '_SC_NPROCESSORS_ONLN'");
	}

	rc = devset_init(&engine.m_handle->m_dev_set, num_devs, engine.m_handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	/* Here we need to load maps and progs but we shouldn't attach tracepoints */
	rc = scap_bpf_load(engine.m_handle, bpf_probe_buf, oargs);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	/* Calibrate the socket at init time */
	rc = calibrate_socket_file_ops(engine);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	/* Store interesting sc codes */
	memcpy(&engine.m_handle->curr_sc_set, &oargs->ppm_sc_of_interest, sizeof(interesting_ppm_sc_set));

	engine.m_handle->m_flags = 0;
	if(scap_get_bpf_stats_enabled())
	{
		engine.m_handle->m_flags |= ENGINE_FLAG_BPF_STATS_ENABLED;
	}

	return SCAP_SUCCESS;
}

static uint64_t get_flags(struct scap_engine_handle engine)
{
	return engine.m_handle->m_flags;
}

static uint32_t get_n_devs(struct scap_engine_handle engine)
{
	return engine.m_handle->m_dev_set.m_ndevs;
}

static uint64_t get_max_buf_used(struct scap_engine_handle engine)
{
	uint64_t i;
	uint64_t max = 0;
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;

	for(i = 0; i < devset->m_ndevs; i++)
	{
		uint64_t size = buf_size_used(&devset->m_devs[i]);
		max = size > max ? size : max;
	}

	return max;
}

uint64_t scap_bpf_get_api_version(struct scap_engine_handle engine)
{
	return engine.m_handle->m_api_version;
}

uint64_t scap_bpf_get_schema_version(struct scap_engine_handle engine)
{
	return engine.m_handle->m_schema_version;
}

const struct scap_vtable scap_bpf_engine = {
	.name = BPF_ENGINE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = init,
	.get_flags = get_flags,
	.free_handle = free_handle,
	.close = scap_bpf_close,
	.next = next,
	.start_capture = scap_bpf_start_capture,
	.stop_capture = scap_bpf_stop_capture,
	.configure = configure,
	.get_stats = scap_bpf_get_stats,
	.get_stats_v2 = scap_bpf_get_stats_v2,
	.get_n_tracepoint_hit = scap_bpf_get_n_tracepoint_hit,
	.get_n_devs = get_n_devs,
	.get_max_buf_used = get_max_buf_used,
	.get_api_version = scap_bpf_get_api_version,
	.get_schema_version = scap_bpf_get_schema_version,
};
