/*
Copyright (C) 2021 The Falco Authors.

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
#ifndef MINIMAL_BUILD
#include <gelf.h>
#endif // MINIMAL_BUILD
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>

#define SCAP_HANDLE_T struct bpf_engine

#include "bpf.h"
#include "engine_handle.h"
#include "scap.h"
#include "scap-int.h"
#include "scap_bpf.h"
#include "scap_engine_util.h"
#include "driver_config.h"
#include "../../driver/bpf/types.h"
#include "../../driver/bpf/maps.h"
#include "compat/misc.h"
#include "compat/bpf.h"
#include "strlcpy.h"
#include "noop.h"
#include "strerror.h"

#ifndef MINIMAL_BUILD
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

#include "ringbuffer/ringbuffer.h"
#endif

static int32_t scap_bpf_handle_tp_mask(struct scap_engine_handle engine, uint32_t op, uint32_t tp);

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
	}
	return engine;
}

static void free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

# define UINT32_MAX (4294967295U)

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

static int bpf_raw_tracepoint_open(const char *name, int prog_fd)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.raw_tracepoint.name = (unsigned long) name;
	attr.raw_tracepoint.prog_fd = prog_fd;

	return sys_bpf(BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
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

static int32_t load_tracepoint(struct bpf_engine* handle, const char *event, struct bpf_insn *prog, int size)
{
	struct perf_event_attr attr = {};
	enum bpf_prog_type program_type;
	size_t insns_cnt;
	char buf[SCAP_MAX_PATH_SIZE];
	bool raw_tp;
	int efd;
	int err;
	int fd;
	int id;
	const char *prog_name = NULL;

	insns_cnt = size / sizeof(struct bpf_insn);

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

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
		return scap_errprintf(handle->m_lasterr, 0, "event name cannot be empty");
	}

	/* 'event' looks like "raw_tracepoint/raw_syscalls/sys_enter". Skip
	 * to the last word after '/', if possible.
	 */
	prog_name = strrchr(event, '/');
	if (prog_name != NULL) {
		prog_name++;
	} else {
		prog_name = event;
	}

	fd = bpf_load_program(prog, program_type, insns_cnt, error, BPF_LOG_SIZE, prog_name);
	if(fd < 0)
	{
		/* It is possible than some old kernels don't support the prog_name so in case
		 * of loading failure, we try again the loading without the name. See it in libbpf:
		 * https://github.com/torvalds/linux/blob/master/tools/lib/bpf/libbpf.c#L4926
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

	if (handle->m_bpf_prog_cnt + 1 >= BPF_PROGS_MAX) {
		return scap_errprintf(handle->m_lasterr, 0, "libscap: too many programs recorded: %d (limit is %d)", handle->m_bpf_prog_cnt + 1 ,BPF_PROGS_MAX);
	}

	handle->m_bpf_progs[handle->m_bpf_prog_cnt].fd = fd;
	strlcpy(handle->m_bpf_progs[handle->m_bpf_prog_cnt].name, full_event, NAME_MAX);
	handle->m_bpf_prog_cnt++;

	if(memcmp(event, "filler/", sizeof("filler/") - 1) == 0)
	{
		int prog_id;

		event += sizeof("filler/") - 1;
		if(*event == 0)
		{
			return scap_errprintf(handle->m_lasterr, 0, "filler name cannot be empty");
		}

		prog_id = lookup_filler_id(event);
		if(prog_id == -1)
		{
			return scap_errprintf(handle->m_lasterr, 0, "invalid filler name: %s", event);
		}
		else if (prog_id >= BPF_PROGS_MAX)
		{
			return scap_errprintf(handle->m_lasterr, 0, "program ID exceeds BPF_PROG_MAX limit (%d/%d)", prog_id, BPF_PROGS_MAX);
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

	if(raw_tp)
	{
		efd = bpf_raw_tracepoint_open(event, fd);
		if(efd < 0)
		{
			return scap_errprintf(handle->m_lasterr, -efd, "BPF_RAW_TRACEPOINT_OPEN: event %s", event);
		}
	}
	else
	{
		snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/id", event);

		efd = open(buf, O_RDONLY, 0);
		if(efd < 0)
		{
			if(strcmp(event, "exceptions/page_fault_user") == 0 ||
			strcmp(event, "exceptions/page_fault_kernel") == 0)
			{
				return SCAP_SUCCESS;
			}

			return scap_errprintf(handle->m_lasterr, errno, "failed to open event %s", event);
		}

		err = read(efd, buf, sizeof(buf));
		if(err < 0 || err >= sizeof(buf))
		{
			int err = errno;
			close(efd);
			return scap_errprintf(handle->m_lasterr, err, "read from '%s' failed", event);
		}

		close(efd);

		buf[err] = 0;
		id = atoi(buf);
		attr.config = id;

		efd = sys_perf_event_open(&attr, -1, 0, -1, 0);
		if(efd < 0)
		{
			return scap_errprintf(handle->m_lasterr, -efd, "event %d", id);
		}

		if(ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd))
		{
			int err = errno;
			close(efd);
			return scap_errprintf(handle->m_lasterr, err, "PERF_EVENT_IOC_SET_BPF");
		}
	}

	// by this point m_bpf_prog_cnt has already been checked for
	// being inbounds, so this is safe.
	handle->m_bpf_progs[handle->m_bpf_prog_cnt - 1].efd = efd;

	return SCAP_SUCCESS;
}

static bool is_tp_enabled(interesting_tp_set *tp_of_interest, const char *shname)
{
	tp_values val = tp_from_name(shname);
	if(!tp_of_interest || val == -1)
	{
		// Null tp set? Enable everything!
		// Not found? Enable it!
		return true;
	}
	return tp_of_interest->tp[val];
}

static int32_t load_bpf_file(
	struct bpf_engine *handle,
	uint64_t *api_version_p,
	uint64_t *schema_version_p)
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
				memcpy(api_version_p, data->d_buf, sizeof(*api_version_p));
			}
			else if(strcmp(shname, "schema_version") == 0)
			{
				got_schema_version = true;
				memcpy(schema_version_p, data->d_buf, sizeof(*schema_version_p));
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

static int load_tracepoints(struct bpf_engine *handle,
			    interesting_tp_set *tp_of_interest)
{
	int j;
	int32_t res = SCAP_FAILURE;
	GElf_Shdr shdr;
	Elf_Data *data;
	char *shname;

	for(j = 0; j < handle->ehdr.e_shnum; ++j)
	{
		if(get_elf_section(handle->elf, j, &handle->ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		if(memcmp(shname, "tracepoint/", sizeof("tracepoint/") - 1) == 0 ||
		   memcmp(shname, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
		{
			if(is_tp_enabled(tp_of_interest, shname))
			{
				bool already_attached = false;
				for (int i = 0; i < handle->m_bpf_prog_cnt && !already_attached; i++)
				{
					if (strcmp(handle->m_bpf_progs[i].name, shname) == 0)
					{
						already_attached = true;
					}
				}

				if (!already_attached)
				{
					if(load_tracepoint(handle, shname, data->d_buf, data->d_size) != SCAP_SUCCESS)
					{
						goto end;
					}
				}
			}
		}
	}
	res = SCAP_SUCCESS;
end:
	return res;
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

static int32_t set_single_syscall_of_interest(struct bpf_engine *handle, int ppm_sc, bool value)
{
	int ret;

	/* We can have more than one syscall corresponding to the same `ppm_sc` for this
	 * reason we need to check the entire table. As a future work every syscall
	 * must have is `PPM_SC_CODE`.
	 */
	for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if(g_syscall_table[syscall_nr].ppm_sc != ppm_sc)
		{
			continue;
		}

		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_INTERESTING_SYSCALLS_TABLE], &syscall_nr, &value, BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret, "SCAP_INTERESTING_SYSCALLS_TABLE unable to update syscall: %d", syscall_nr);
		}
	}
	return SCAP_SUCCESS;
}

static int32_t populate_interesting_syscalls_map(struct bpf_engine *handle, scap_open_args *oargs)
{
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(set_single_syscall_of_interest(handle, ppm_sc, oargs->ppm_sc_of_interest.ppm_sc[ppm_sc]) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
	}
	return SCAP_SUCCESS;
}

static int32_t update_interesting_syscalls_map(struct scap_engine_handle engine, uint32_t op, uint32_t ppm_sc)
{
	struct bpf_engine *handle = engine.m_handle;
	return set_single_syscall_of_interest(handle, ppm_sc, op == SCAP_PPM_SC_MASK_SET);
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

//
// This is needed to make sure that the driver can properly
// lookup sockets. We generate a fake socket system call
// at the beginning so the calibration will surely take place.
// For more info, read the corresponding filler in kernel space.
//
static int32_t calibrate_socket_file_ops()
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
		return SCAP_FAILURE;
	}

	close(fd);
	return SCAP_SUCCESS;
}

int32_t scap_bpf_start_capture(struct scap_engine_handle engine)
{
	struct bpf_engine* handle = engine.m_handle;

	/* Enable requested tracepoints */
	int ret = SCAP_SUCCESS;
	for (int i = 0; i < TP_VAL_MAX && ret == SCAP_SUCCESS; i++)
	{
		if (handle->open_tp_set.tp[i])
		{
			ret = scap_bpf_handle_tp_mask(engine, SCAP_TP_MASK_SET, i);
		}
	}
	if (ret != SCAP_SUCCESS)
	{
		return ret;
	}

	if(calibrate_socket_file_ops() != SCAP_SUCCESS)
	{
		ASSERT(false);
		// if we're here, errno should come from the failed socket() call in calibrate_socket_ops()
		return scap_errprintf(handle->m_lasterr, errno, "calibrate_socket_file_ops");
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_stop_capture(struct scap_engine_handle engine)
{
	/* Disable all tracepoints */
	int ret = SCAP_SUCCESS;
	for (int i = 0; i < TP_VAL_MAX && ret == SCAP_SUCCESS; i++)
	{
		ret = scap_bpf_handle_tp_mask(engine, SCAP_TP_MASK_UNSET, i);
	}
	return ret;
}

int32_t scap_bpf_set_snaplen(struct scap_engine_handle engine, uint32_t snaplen)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if(snaplen > RW_MAX_SNAPLEN)
	{
		return scap_errprintf(handle->m_lasterr, 0, "snaplen can't exceed %d\n", RW_MAX_SNAPLEN);
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
	switch(sampling_ratio)
	{
		case 1:
		case 2:
		case 4:
		case 8:
		case 16:
		case 32:
		case 64:
		case 128:
			break;
		default:
			return scap_errprintf(handle->m_lasterr, 0, "invalid sampling ratio size");
	}

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

int32_t scap_bpf_enable_tracers_capture(struct scap_engine_handle engine)
{
	struct scap_bpf_settings settings;
	struct bpf_engine *handle = engine.m_handle;
	int k = 0;
	int ret;

	if((ret = bpf_map_lookup_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_lookup_elem");
	}

	settings.tracers_enabled = true;
	if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_SETTINGS_MAP], &k, &settings, BPF_ANY)) != 0)
	{
		return scap_errprintf(handle->m_lasterr, -ret, "SCAP_SETTINGS_MAP bpf_map_update_elem");
	}

	return SCAP_SUCCESS;
}

static void close_prog(struct bpf_prog *prog)
{
	if(prog->efd > 0)
	{
		close(prog->efd);
	}
	if(prog->fd > 0)
	{
		close(prog->fd);
	}
	memset(prog, 0, sizeof(*prog));
}

int32_t scap_bpf_close(struct scap_engine_handle engine)
{
	struct bpf_engine *handle = engine.m_handle;
	int j;

	struct scap_device_set *devset = &handle->m_dev_set;

	devset_free(devset);

	for(j = 0; j < sizeof(handle->m_bpf_progs) / sizeof(handle->m_bpf_progs[0]); ++j)
	{
		close_prog(&handle->m_bpf_progs[j]);
	}

	for(j = 0; j < sizeof(handle->m_bpf_map_fds) / sizeof(handle->m_bpf_map_fds[0]); ++j)
	{
		if(handle->m_bpf_map_fds[j] > 0)
		{
			close(handle->m_bpf_map_fds[j]);
			handle->m_bpf_map_fds[j] = 0;
		}
	}

	handle->m_bpf_prog_cnt = 0;
	handle->m_bpf_prog_array_map_idx = -1;

	if (handle->elf)
	{
		elf_end(handle->elf);
		handle->elf = NULL;
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
	if(scap_get_boot_time(handle->m_lasterr, &boot_time) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	settings.boot_time = boot_time;
	settings.socket_file_ops = NULL;
	settings.snaplen = RW_SNAPLEN;
	settings.sampling_ratio = 1;
	settings.do_dynamic_snaplen = false;
	settings.dropping_mode = false;
	settings.is_dropping = false;
	settings.tracers_enabled = false;
	settings.fullcapture_port_range_start = 0;
	settings.fullcapture_port_range_end = 0;
	settings.statsd_port = 8125;

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
	uint64_t *api_version_p,
	uint64_t *schema_version_p,
	scap_open_args *oargs)
{
	int online_cpu;
	int j;
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

	if(load_bpf_file(handle, api_version_p, schema_version_p) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	/* Store interesting Tracepoints */
	memcpy(&handle->open_tp_set, &oargs->tp_of_interest, sizeof(interesting_tp_set));
	/* Start with all tracepoints disabled */
	interesting_tp_set initial_tp_set = {0};
	if (load_tracepoints(handle, &initial_tp_set) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_syscall_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_interesting_syscalls_map(handle, oargs) != SCAP_SUCCESS)
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

	//
	// Open and initialize all the devices
	//
	online_cpu = 0;
	for(j = 0; j < handle->m_ncpus; ++j)
	{
		struct perf_event_attr attr = {
			.sample_type = PERF_SAMPLE_RAW,
			.type = PERF_TYPE_SOFTWARE,
			.config = PERF_COUNT_SW_BPF_OUTPUT,
		};
		int pmu_fd;
		int ret;
		struct scap_device *dev;

		if(j > 0)
		{
			char filename[SCAP_MAX_PATH_SIZE];
			int online;
			FILE *fp;

			snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", j);

			fp = fopen(filename, "r");
			if(fp == NULL)
			{
				// When missing NUMA properties, CPUs do not expose online information.
				// Fallback at considering them online if we can at least reach their folder.
				// This is useful for example for raspPi devices.
				// See: https://github.com/kubernetes/kubernetes/issues/95039
				snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/", j);
				if (access(filename, F_OK) == 0)
				{
					online = 1;
				}
				else
				{
					return scap_errprintf(handle->m_lasterr, errno, "can't open %sonline", filename);
				}
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

		if(online_cpu >= handle->m_dev_set.m_ndevs)
		{
			return scap_errprintf(handle->m_lasterr, 0, "too many online processors: %d, expected: %d", online_cpu, handle->m_dev_set.m_ndevs);
		}

		dev = &handle->m_dev_set.m_devs[online_cpu];

		pmu_fd = sys_perf_event_open(&attr, -1, j, -1, 0);
		if(pmu_fd < 0)
		{
			return scap_errprintf(handle->m_lasterr, -pmu_fd, "pmu_fd");
		}

		dev->m_fd = pmu_fd;

		if((ret = bpf_map_update_elem(handle->m_bpf_map_fds[SCAP_PERF_MAP], &j, &pmu_fd, BPF_ANY)) != 0)
		{
			return scap_errprintf(handle->m_lasterr, -ret, "SCAP_PERF_MAP bpf_map_update_elem");
		}

		if(ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
		{
			return scap_errprintf(handle->m_lasterr, errno, "PERF_EVENT_IOC_ENABLE");
		}

		//
		// Map the ring buffer
		//
		dev->m_buffer = perf_event_mmap(handle, pmu_fd, &dev->m_mmap_size, bpf_args->buffer_bytes_dim);
		dev->m_buffer_size = bpf_args->buffer_bytes_dim;
		if(dev->m_buffer == MAP_FAILED)
		{
			return SCAP_FAILURE;
		}

		++online_cpu;
	}

	if(online_cpu != handle->m_dev_set.m_ndevs)
	{
		return scap_errprintf(handle->m_lasterr, 0, "processors online: %d, expected: %d", online_cpu, handle->m_dev_set.m_ndevs);
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

static int32_t next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	return ringbuffer_next(&engine.m_handle->m_dev_set, pevent, pcpuid);
}

static int32_t unsupported_config(struct scap_engine_handle engine, const char* msg)
{
	struct bpf_engine* handle = engine.m_handle;

	strlcpy(handle->m_lasterr, msg, SCAP_LASTERR_SIZE);
	return SCAP_FAILURE;
}

static int32_t scap_bpf_handle_tp_mask(struct scap_engine_handle engine, uint32_t op, uint32_t tp)
{
	struct bpf_engine *handle = engine.m_handle;

	int prg_idx = -1;
	for (int i = 0; i < handle->m_bpf_prog_cnt; i++)
	{
		const tp_values val = tp_from_name(handle->m_bpf_progs[i].name);
		if (val == tp)
		{
			prg_idx = i;
			break;
		}
	}

	// We want to unload a never loaded tracepoint
	if (prg_idx == -1 && op != SCAP_TP_MASK_SET)
	{
		return SCAP_SUCCESS;
	}
	// We want to load an already loaded tracepoint
	if (prg_idx >= 0 && op != SCAP_TP_MASK_UNSET)
	{
		return SCAP_SUCCESS;
	}

	if (op == SCAP_TP_MASK_UNSET)
	{
		// Algo:
		// Close the event and tracepoint fds,
		// reduce number of prog cnt
		// move left remaining array elements
		// reset last array element
		close_prog(&handle->m_bpf_progs[prg_idx]);
		handle->m_bpf_prog_cnt--;
		size_t byte_size = (handle->m_bpf_prog_cnt - prg_idx) * sizeof(handle->m_bpf_progs[prg_idx]);
		if (byte_size > 0)
		{
			memmove(&handle->m_bpf_progs[prg_idx], &handle->m_bpf_progs[prg_idx + 1], byte_size);
		}
		memset(&handle->m_bpf_progs[handle->m_bpf_prog_cnt], 0, sizeof(handle->m_bpf_progs[handle->m_bpf_prog_cnt]));
		return SCAP_SUCCESS;
	}

	interesting_tp_set new_tp_set = {0};
	new_tp_set.tp[tp] = 1;
	return load_tracepoints(handle, &new_tp_set);
}

static int32_t scap_bpf_handle_event_mask(struct scap_engine_handle engine, uint32_t op, uint32_t ppm_sc)
{
	int32_t ret = SCAP_SUCCESS;
	switch(op)
	{
	case SCAP_PPM_SC_MASK_SET:
	case SCAP_PPM_SC_MASK_UNSET:
		ret = update_interesting_syscalls_map(engine, op, ppm_sc);
		break;

	default:
		ret = SCAP_FAILURE;
		break;
	}
	return ret;
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
	case SCAP_TRACERS_CAPTURE:
		if(arg1 == 0)
		{
			return unsupported_config(engine, "Tracers cannot be disabled once enabled");
		}
		return scap_bpf_enable_tracers_capture(engine);
	case SCAP_SNAPLEN:
		return scap_bpf_set_snaplen(engine, arg1);
	case SCAP_PPM_SC_MASK:
		return scap_bpf_handle_event_mask(engine, arg1, arg2);
	case SCAP_TP_MASK:
		return scap_bpf_handle_tp_mask(engine, arg1, arg2);
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
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "_SC_NPROCESSORS_CONF");
	}

	engine.m_handle->m_ncpus = num_cpus;

	ssize_t num_devs = sysconf(_SC_NPROCESSORS_ONLN);
	if(num_devs == -1)
	{
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "_SC_NPROCESSORS_ONLN");
	}

	rc = devset_init(&engine.m_handle->m_dev_set, num_devs, engine.m_handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	rc = scap_bpf_load(engine.m_handle, bpf_probe_buf, &handle->m_api_version, &handle->m_schema_version, oargs);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	rc = check_api_compatibility(handle, handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	return SCAP_SUCCESS;
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


const struct scap_vtable scap_bpf_engine = {
	.name = BPF_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = free_handle,
	.close = scap_bpf_close,
	.next = next,
	.start_capture = scap_bpf_start_capture,
	.stop_capture = scap_bpf_stop_capture,
	.configure = configure,
	.get_stats = scap_bpf_get_stats,
	.get_n_tracepoint_hit = scap_bpf_get_n_tracepoint_hit,
	.get_n_devs = get_n_devs,
	.get_max_buf_used = get_max_buf_used,
	.get_threadlist = scap_procfs_get_threadlist,
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = scap_os_getpid_global,
};
