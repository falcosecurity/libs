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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <scap.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "strlcpy.h"

#define SYSCALL_NAME_MAX_LEN 40
#define UNKNOWN_ENGINE "unknown"

/* SCAP SOURCES */
#define KMOD_OPTION "--kmod"
#define BPF_OPTION "--bpf"
#define MODERN_BPF_OPTION "--modern_bpf"
#define SCAP_FILE_OPTION "--scap_file"

/* CONFIGURATIONS */
#define TP_OPTION "--tp"
#define PPM_SC_OPTION "--ppm_sc"
#define NUM_EVENTS_OPTION "--num_events"
#define EVENT_TYPE_OPTION "--evt_type"
#define BUFFER_OPTION "--buffer_dim"
#define SIMPLE_SET_OPTION "--simple_set"
#define CPUS_FOR_EACH_BUFFER_MODE "--cpus_for_buf"
#define ALL_AVAILABLE_CPUS_MODE "--available_cpus"

/* PRINT */
#define PRINT_SYSCALLS_OPTION "--print_syscalls"
#define PRINT_HELP_OPTION "--help"

extern const struct ppm_event_info g_event_info[PPM_EVENT_MAX];
extern const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];

static const struct ppm_syscall_desc *g_syscall_info_table;

/* Engine params */
static struct scap_bpf_engine_params bpf_params;
static struct scap_kmod_engine_params kmod_params;
static struct scap_modern_bpf_engine_params modern_bpf_params;
static struct scap_savefile_engine_params savefile_params;

/* Configuration variables set through CLI. */
static uint64_t num_events = UINT64_MAX; /* max number of events to catch. */
static int evt_type = -1;		  /* event type to print. */
static bool ppm_sc_is_set = 0;
static bool tp_is_set = 0;
static unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;

static int simple_set[] = {
	PPM_SC_ACCEPT,
	PPM_SC_ACCEPT4,
	PPM_SC_BIND,
	PPM_SC_BPF,
	PPM_SC_CAPSET,
	PPM_SC_CHDIR,
	PPM_SC_CHMOD,
	PPM_SC_CHROOT,
	PPM_SC_CLONE,
	PPM_SC_CLONE3,
	PPM_SC_CLOSE,
	PPM_SC_CONNECT,
	PPM_SC_COPY_FILE_RANGE,
	PPM_SC_CREAT,
	PPM_SC_DUP,
	PPM_SC_DUP2,
	PPM_SC_DUP3,
	PPM_SC_EVENTFD,
	PPM_SC_EVENTFD2,
	PPM_SC_EXECVE,
	PPM_SC_EXECVEAT,
	PPM_SC_FCHDIR,
	PPM_SC_FCHMOD,
	PPM_SC_FCHMODAT,
	PPM_SC_FCNTL,
	PPM_SC_FLOCK,
	PPM_SC_FORK,
	PPM_SC_INOTIFY_INIT,
	PPM_SC_INOTIFY_INIT1,
	PPM_SC_IOCTL,
	PPM_SC_KILL,
	PPM_SC_LINK,
	PPM_SC_LINKAT,
	PPM_SC_LISTEN,
	PPM_SC_MKDIR,
	PPM_SC_MKDIRAT,
	PPM_SC_MOUNT,
	PPM_SC_OPEN,
	PPM_SC_OPEN_BY_HANDLE_AT,
	PPM_SC_OPENAT,
	PPM_SC_OPENAT2,
	PPM_SC_PIPE,
	PPM_SC_PIPE2,
	PPM_SC_PRLIMIT64,
	PPM_SC_PTRACE,
	PPM_SC_QUOTACTL,
	PPM_SC_RECVFROM,
	PPM_SC_RECVMSG,
	PPM_SC_RENAME,
	PPM_SC_RENAMEAT,
	PPM_SC_RENAMEAT2,
	PPM_SC_RMDIR,
	PPM_SC_SECCOMP,
	PPM_SC_SENDMMSG,
	PPM_SC_SENDTO,
	PPM_SC_SETGID,
	PPM_SC_SETNS,
	PPM_SC_SETPGID,
	PPM_SC_SETRESGID,
	PPM_SC_SETRESUID,
	PPM_SC_SETRLIMIT,
	PPM_SC_SETSID,
	PPM_SC_SETSOCKOPT,
	PPM_SC_SETUID,
	PPM_SC_SHUTDOWN,
	PPM_SC_SIGNALFD,
	PPM_SC_SIGNALFD4,
	PPM_SC_SOCKET,
	PPM_SC_SOCKETPAIR,
	PPM_SC_SYMLINK,
	PPM_SC_SYMLINKAT,
	PPM_SC_TGKILL,
	PPM_SC_TIMERFD_CREATE,
	PPM_SC_TKILL,
	PPM_SC_UMOUNT,
	PPM_SC_UMOUNT2,
	PPM_SC_UNLINK,
	PPM_SC_UNLINKAT,
	PPM_SC_UNSHARE,
	PPM_SC_USERFAULTFD,
	PPM_SC_VFORK,
	-1
};

/* Generic global variables. */
static scap_open_args oargs = {.engine_name = UNKNOWN_ENGINE};			    /* scap oargs used in `scap_open`. */
static uint64_t g_nevts = 0;							    /* total number of events captured. */
static scap_t* g_h = NULL;							    /* global scap handler. */
static uint16_t* lens16 = NULL;						    /* pointer used to print the length of event params. */
static char* valptr = NULL; /* pointer used to print the value of event params. */ /* pointer used to print the value of event params. */
static struct timeval tval_start, tval_end, tval_result;
static unsigned long number_of_timeouts; /* Times in which there were no events in the buffer. */
static unsigned long number_of_scap_next; /* Times in which the 'scap-next' method is called. */

/*=============================== PRINT SUPPORTED SYSCALLS ===========================*/

void print_sorted_syscalls(char string_vector[SYSCALL_TABLE_SIZE][SYSCALL_NAME_MAX_LEN], int dim)
{
	char temp[SYSCALL_NAME_MAX_LEN];

	/* storing strings in the lexicographical order */
	for(int i = 0; i < dim; ++i)
	{
		for(int j = i + 1; j < dim; ++j)
		{
			/* swapping strings if they are not in the lexicographical order */
			if(strcmp(string_vector[i], string_vector[j]) > 0)
			{
				strlcpy(temp, string_vector[i], SYSCALL_NAME_MAX_LEN);
				strlcpy(string_vector[i], string_vector[j], SYSCALL_NAME_MAX_LEN);
				strlcpy(string_vector[j], temp, SYSCALL_NAME_MAX_LEN);
			}
		}
	}

	printf("\nSyscalls in the lexicographical order: \n");
	for(int i = 0; i < dim; i++)
	{
		printf("[%d] %s\n", i, string_vector[i]);
	}
	printf("Interesting syscalls: %d\n", dim);
}

void print_UF_NEVER_DROP_syscalls()
{
	char str[SYSCALL_TABLE_SIZE][SYSCALL_NAME_MAX_LEN];
	int interesting_syscall = 0;

	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
		{
			if(g_syscall_table[syscall_nr].ppm_sc != ppm_sc)
			{
				continue;
			}

			if(g_syscall_table[syscall_nr].flags & UF_NEVER_DROP)
			{
				strlcpy(str[interesting_syscall++], g_syscall_info_table[ppm_sc].name, SYSCALL_NAME_MAX_LEN);
			}
		}
	}

	printf("\n------- Print UF_NEVER_DROP syscalls: \n");
	print_sorted_syscalls(str, interesting_syscall);
}

void print_EF_MODIFIES_STATE_syscalls()
{
	char str[SYSCALL_TABLE_SIZE][SYSCALL_NAME_MAX_LEN];
	int interesting_syscall = 0;

	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
		{
			if(g_syscall_table[syscall_nr].ppm_sc != ppm_sc)
			{
				continue;
			}

			int enter_event = g_syscall_table[syscall_nr].enter_event_type;
			if(g_event_info[enter_event].flags & EF_MODIFIES_STATE)
			{
				strlcpy(str[interesting_syscall++], g_syscall_info_table[ppm_sc].name, SYSCALL_NAME_MAX_LEN);
			}
		}
	}

	printf("\n------- Print EF_MODIFIES_STATE syscalls: \n");
	print_sorted_syscalls(str, interesting_syscall);
}

void print_sinsp_modifies_state_syscalls()
{
	uint8_t ppm_scs[PPM_SC_MAX];
	char str[SYSCALL_TABLE_SIZE][SYSCALL_NAME_MAX_LEN];
	int interesting_syscall = 0;

	scap_get_modifies_state_ppm_sc(ppm_scs);

	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if (!ppm_scs[ppm_sc])
		{
			continue;
		}
		for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
		{
			if(g_syscall_table[syscall_nr].ppm_sc != ppm_sc)
			{
				continue;
			}
			strlcpy(str[interesting_syscall++], g_syscall_info_table[ppm_sc].name, SYSCALL_NAME_MAX_LEN);
		}
	}

	printf("\n------- Print 'scap_get_modifies_state_ppm_sc' syscalls: \n");
	print_sorted_syscalls(str, interesting_syscall);
}

void print_supported_syscalls()
{
	printf("\n------- Print supported syscalls: \n");

	for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if(g_syscall_table[syscall_nr].ppm_sc == PPM_SC_UNKNOWN)
		{
			continue;
		}
		int ppm_code = g_syscall_table[syscall_nr].ppm_sc;
		printf("- %-25s system_code: (%d) ppm_code: (%d)\n", g_syscall_info_table[ppm_code].name, syscall_nr, ppm_code);
	}
}

void print_supported_tracepoints()
{
	printf("\n------- Print supported tracepoints: \n");

	for(int j = 0; j < TP_VAL_MAX; j++)
	{
		printf("- %-25s tp_code: (%d)\n", tp_names[j], j);
	}
}


/*=============================== PRINT SUPPORTED SYSCALLS ===========================*/

/*=============================== SYSCALLS/TRACEPOINTS ===========================*/

void enable_single_tp(int tp)
{
	if(tp == -1)
	{
		/* In this case we won't have any tracepoint enabled. */
		tp_is_set = true;
		return;
	}

	if(tp < 0 || tp >= TP_VAL_MAX)
	{
		fprintf(stderr, "Unexistent tp code: %d. Wrong parameter?\n", tp);
		print_supported_tracepoints();
		exit(EXIT_FAILURE);
	}
	oargs.tp_of_interest.tp[tp] = true;
	tp_is_set = true;
}

void enable_single_ppm_sc(int ppm_sc_code)
{
	if(ppm_sc_code == -1)
	{
		/* In this case we won't have any syscall enabled. */
		ppm_sc_is_set = true;
		return;
	}

	if(ppm_sc_code < 0 || ppm_sc_code >= PPM_SC_MAX)
	{
		fprintf(stderr, "Unexistent ppm_sc code: %d. Wrong parameter?\n", ppm_sc_code);
		print_supported_syscalls();
		exit(EXIT_FAILURE);
	}
	oargs.ppm_sc_of_interest.ppm_sc[ppm_sc_code] = true;
	ppm_sc_is_set = true;
}

void enable_syscalls_and_print()
{
	printf("---------------------- INTERESTING SYSCALLS ----------------------\n");
	if(ppm_sc_is_set)
	{
		printf("* Syscalls enabled:\n");
		for(int j = 0; j < PPM_SC_MAX; j++)
		{
			if(oargs.ppm_sc_of_interest.ppm_sc[j])
			{
				printf("- %s\n", g_syscall_info_table[j].name);
			}
		}
	}
	else
	{
		printf("* All syscalls are enabled!\n");
		for(int j = 0; j < PPM_SC_MAX; j++)
		{
			oargs.ppm_sc_of_interest.ppm_sc[j] = true;
		}
	}
	printf("------------------------------------------------------------------\n\n");
}

void enable_tracepoints_and_print()
{
	printf("---------------------- ENABLED TRACEPOINTS ----------------------\n");
	if(tp_is_set)
	{
		printf("* Tracepoints enabled:\n");
		for(int j = 0; j < TP_VAL_MAX; j++)
		{
			if(oargs.tp_of_interest.tp[j])
			{
				printf("- %s\n", tp_names[j]);
			}
		}
	}
	else
	{
		printf("* All Tracepoints are enabled!\n");
		for(int j = 0; j < TP_VAL_MAX; j++)
		{
			oargs.tp_of_interest.tp[j] = true;
		}
	}
	printf("-----------------------------------------------------------------\n\n");
}

void enable_simple_set()
{
	/* Enable only sys_enter and sys_exit */
	oargs.tp_of_interest.tp[SYS_ENTER] = true;
	oargs.tp_of_interest.tp[SYS_EXIT] = true;

	int i = 0;
	for (i = 0; simple_set[i] != -1; i++)
	{
		oargs.ppm_sc_of_interest.ppm_sc[simple_set[i]] = true;
	}
	tp_is_set = true;
	ppm_sc_is_set = true;
}

/*=============================== SYSCALLS/TRACEPOINTS ===========================*/

/*=============================== PRINT EVENT PARAMS ===========================*/

void print_ipv4(int starting_index)
{
	char ipv4_string[50];
	uint8_t* ipv4 = (uint8_t*)(valptr + starting_index);
	snprintf(ipv4_string, sizeof(ipv4_string), "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
	printf("- ipv4: %s\n", ipv4_string);
}

void print_ipv6(int starting_index)
{
	uint32_t ipv6[4] = {0, 0, 0, 0};
	ipv6[0] = *(uint32_t*)(valptr + starting_index);
	ipv6[1] = *(uint32_t*)(valptr + starting_index + 4);
	ipv6[2] = *(uint32_t*)(valptr + starting_index + 8);
	ipv6[3] = *(uint32_t*)(valptr + starting_index + 12);

	char ipv6_string[150];
	inet_ntop(AF_INET6, ipv6, ipv6_string, 150);
	printf("- ipv6: %s\n", ipv6_string);
}

void print_unix_path(int starting_index)
{
	printf("- unix path: %s\n", (char*)(valptr + starting_index));
}

void print_port(int starting_index)
{
	printf("- port: %d\n", *(uint16_t*)(valptr + starting_index));
}

void print_parameter(int16_t num_param)
{
	int16_t param_type = g_event_info[evt_type].params[num_param].type;
	int16_t len = lens16[num_param];

	if(len == 0)
	{
		printf("PARAM %d: is empty\n", num_param);
		return;
	}

	switch(param_type)
	{

	case PT_FLAGS8:
		printf("PARAM %d: %X\n", num_param, *(uint8_t*)(valptr));
		break;

	case PT_FLAGS16:
		printf("PARAM %d: %X\n", num_param, *(uint16_t*)(valptr));
		break;

	case PT_FLAGS32:
		printf("PARAM %d: %X\n", num_param, *(uint32_t*)(valptr));
		break;

	case PT_INT8:
		printf("PARAM %d: %d\n", num_param, *(int8_t*)(valptr));
		break;

	case PT_INT16:
		printf("PARAM %d: %d\n", num_param, *(int16_t*)(valptr));
		break;

	case PT_INT32:
		printf("PARAM %d: %d\n", num_param, *(int32_t*)(valptr));
		break;

	case PT_INT64:
	case PT_ERRNO:
	case PT_PID:
		printf("PARAM %d: %ld\n", num_param, *(int64_t*)(valptr));
		break;

	case PT_UINT8:
	case PT_SIGTYPE:
	case PT_ENUMFLAGS8:
		printf("PARAM %d: %d\n", num_param, *(uint8_t*)(valptr));
		break;

	case PT_UINT16:
	case PT_SYSCALLID:
	case PT_ENUMFLAGS16:
		printf("PARAM %d: %d\n", num_param, *(uint16_t*)(valptr));
		break;

	case PT_UINT32:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
	case PT_MODE:
	case PT_ENUMFLAGS32:
		printf("PARAM %d: %d\n", num_param, *(uint32_t*)(valptr));
		break;

	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		printf("PARAM %d: %lu\n", num_param, *(uint64_t*)(valptr));
		break;

	case PT_FD:
		printf("PARAM %d: %d\n", num_param, *(int32_t*)(valptr));
		break;

	case PT_SOCKADDR:
	{
		printf("PARAM %d:\n", num_param);
		uint8_t sock_family = *(uint8_t*)(valptr);
		printf("- sock_family: %d\n", sock_family);
		switch(sock_family)
		{

		case PPM_AF_INET:
			/* ipv4 dest. */
			print_ipv4(1);

			/* port dest. */
			print_port(5);
			break;

		case PPM_AF_INET6:
			/* ipv6 dest. */
			print_ipv6(1);

			/* port dest. */
			print_port(17);
			break;

		case PPM_AF_UNIX:
			/* unix_path. */
			print_unix_path(1);
			break;

		default:
			printf("-  error\n");
			break;
		}
		break;
	}

	case PT_SOCKTUPLE:
	{
		printf("PARAM %d:\n", num_param);
		uint8_t sock_family = *(uint8_t*)(valptr);
		printf("- sock_family: %d\n", sock_family);
		switch(sock_family)
		{
		case PPM_AF_INET:
			/* ipv4 src. */
			print_ipv4(1);

			/* ipv4 dest. */
			print_ipv4(5);

			/* port src. */
			print_port(9);

			/* port dest. */
			print_port(11);
			break;

		case PPM_AF_INET6:
			/* ipv6 src. */
			print_ipv6(1);

			/* ipv6 dest. */
			print_ipv6(17);

			/* port src. */
			print_port(33);

			/* port dest. */
			print_port(35);
			break;

		case PPM_AF_UNIX:
			/* Here there are also some kernel pointers but right
			 * now we are not interested in catching them.
			 * 8 + 8 = 16 bytes
			 */

			/* unix_path. */
			print_unix_path(17);
			break;

		default:
			printf("-  error\n");
			break;
		}
		break;
	}

	case PT_CHARBUF:
	case PT_BYTEBUF:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_FSRELPATH:
		printf("PARAM %d: ", num_param);
		for(int j = 0; j < len; j++)
		{
			printf("%c", *(char*)(valptr + j));
		}
		printf("\n");
		break;

	default:
		printf("PARAM %d: TYPE NOT KNOWN\n", num_param);
		break;
	}
	valptr += len;
}

void print_event(scap_evt* ev)
{
	lens16 = (uint16_t*)((char*)ev + sizeof(struct ppm_evt_hdr));
	valptr = (char*)lens16 + ev->nparams * sizeof(uint16_t);
	printf("\n------------------ EVENT: %d TID:%lu\n", evt_type, ev->tid);

	printf("------ HEADER\n");
	printf("timestamp: %lu\n", ev->ts);
	printf("tid: %lu\n", ev->tid);
	printf("len: %d\n", ev->len);
	printf("type: %d\n", ev->type);
	printf("num params: %d\n", ev->nparams);
	printf("------\n");
	printf("------ PARAMS\n");

	for(int i = 0; i < ev->nparams; i++)
	{
		print_parameter(i);
	}
	if(ev->nparams == 0)
	{
		printf("- This event has no parameter\n");
	}

	printf("------\n");
	printf("------------------\n");
}

/*=============================== PRINT EVENT PARAMS ===========================*/

/*=============================== PRINT CAPTURE INFO ===========================*/

void print_help()
{
	printf("\n----------------------- MENU -----------------------\n");
	printf("------> SCAP SOURCES\n");
	printf("'%s': enable the kernel module.\n", KMOD_OPTION);
	printf("'%s <probe_path>': enable the BPF probe.\n", BPF_OPTION);
	printf("'%s': enable modern BPF probe.\n", MODERN_BPF_OPTION);
	printf("'%s <file.scap>': read events from scap file.\n", SCAP_FILE_OPTION);
	printf("\n------> CONFIGURATIONS OPTIONS\n");
	printf("'%s <tp_code>': enable only requested tracepoint (sys_enter, sys_exit, sched_process_exit, sched_switch, page_fault_user, page_fault_kernel, signal_deliver, sched_process_fork, sched_process_exec). Can be passed multiple times.\n", TP_OPTION);
	printf("'%s <ppm_sc_code>': enable only requested syscall (this is our internal ppm syscall code not the system syscall code). Can be passed multiple times.\n", PPM_SC_OPTION);
	printf("'%s <num_events>': number of events to catch before terminating. (default: UINT64_MAX)\n", NUM_EVENTS_OPTION);
	printf("'%s <event_type>': every event of this type will be printed to console. (default: -1, no print)\n", EVENT_TYPE_OPTION);
	printf("'%s <dim>': dimension in bytes of a single per CPU buffer.\n", BUFFER_OPTION);
	printf("[MODERN PROBE ONLY, EXPERIMENTAL]\n");
	printf("'%s <cpus_for_each_buffer>': allocate a ring buffer for every `cpus_for_each_buffer` CPUs.\n", CPUS_FOR_EACH_BUFFER_MODE);
	printf("'%s': allocate ring buffers for all available CPUs. Default: allocate ring buffers for online CPUs only.\n", ALL_AVAILABLE_CPUS_MODE);
	printf("\n------> PRINT OPTIONS\n");
	printf("'%s': print all supported syscalls with different sources and configurations.\n", PRINT_SYSCALLS_OPTION);
	printf("'%s': print this menu.\n", PRINT_HELP_OPTION);
	printf("-----------------------------------------------------\n");
}

void print_scap_source()
{
	printf("\n---------------------- SCAP SOURCE ----------------------\n");
	if(strcmp(oargs.engine_name, KMOD_ENGINE) == 0)
	{
		printf("* Kernel module.\n");
	}
	else if(strcmp(oargs.engine_name, BPF_ENGINE) == 0)
	{
		struct scap_bpf_engine_params* params = oargs.engine_params;
		printf("* BPF probe: '%s'\n", params->bpf_probe);
	}
	else if(strcmp(oargs.engine_name, MODERN_BPF_ENGINE) == 0)
	{
		struct scap_modern_bpf_engine_params* params = oargs.engine_params;
		printf("* Modern BPF probe, 1 ring buffer every %d CPUs\n", params->cpus_for_each_buffer);
	}
	else if(strcmp(oargs.engine_name, SAVEFILE_ENGINE) == 0)
	{
		struct scap_savefile_engine_params* params = oargs.engine_params;
		printf("* Scap file: '%s'.\n", params->fname);
	}
	else
	{
		printf("* Unknown scap source! Bye!\n");
		print_help();
		exit(EXIT_FAILURE);
	}
	printf("-----------------------------------------------------------\n\n");
}

void print_configurations()
{
	printf("--------------------- CONFIGURATIONS ----------------------\n");
	printf("* Print single event type: %d (`-1` means no event to print).\n", evt_type);
	printf("* Run until '%lu' events are catched.\n", num_events);
	printf("-----------------------------------------------------------\n\n");
}

void print_start_capture()
{
	if(strcmp(oargs.engine_name, KMOD_ENGINE) == 0)
	{
		printf("* OK! Kernel module correctly loaded.\n");
	}
	else if(strcmp(oargs.engine_name, BPF_ENGINE) == 0)
	{
		printf("* OK! BPF probe correctly loaded: NO VERIFIER ISSUES :)\n");
	}
	else if(strcmp(oargs.engine_name, MODERN_BPF_ENGINE) == 0)
	{
		printf("* OK! modern BPF probe correctly loaded: NO VERIFIER ISSUES :)\n");
	}
	else if(strcmp(oargs.engine_name, SAVEFILE_ENGINE) == 0)
	{
		printf("* OK! Ready to read from scap file.\n");
		printf("\n* Reading from scap file...\n");
		return;
	}
	else
	{
		printf("Cannot start the capture! Bye\n");
		exit(EXIT_FAILURE);
	}
	printf("* Live capture in progress...\n");
	printf("* Press CTRL+C to stop the capture\n");
}

void parse_CLI_options(int argc, char** argv)
{
	for(int i = 0; i < argc; i++)
	{
		/*=============================== SCAP SOURCES ===========================*/

		if(!strcmp(argv[i], KMOD_OPTION))
		{
			oargs.engine_name = KMOD_ENGINE;
			oargs.mode = SCAP_MODE_LIVE;
			kmod_params.buffer_bytes_dim = buffer_bytes_dim;
			oargs.engine_params = &kmod_params;
		}
		if(!strcmp(argv[i], BPF_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the BPF probe path! Bye!\n");
				exit(EXIT_FAILURE);
			}
			oargs.engine_name = BPF_ENGINE;
			oargs.mode = SCAP_MODE_LIVE;
			bpf_params.bpf_probe = argv[++i];
			bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			oargs.engine_params = &bpf_params;
		}
		if(!strcmp(argv[i], MODERN_BPF_OPTION))
		{
			oargs.engine_name = MODERN_BPF_ENGINE;
			oargs.mode = SCAP_MODE_LIVE;
			modern_bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			modern_bpf_params.cpus_for_each_buffer = DEFAULT_CPU_FOR_EACH_BUFFER;
			modern_bpf_params.allocate_online_only = true;
			modern_bpf_params.verbose = true;
			oargs.engine_params = &modern_bpf_params;
		}
		if(!strcmp(argv[i], SCAP_FILE_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the scap file path! Bye!\n");
				exit(EXIT_FAILURE);
			}
			oargs.engine_name = SAVEFILE_ENGINE;
			oargs.mode = SCAP_MODE_CAPTURE;
			savefile_params.fname = argv[++i];
			oargs.engine_params = &savefile_params;
		}

		/*=============================== SCAP SOURCES ===========================*/

		/*=============================== CONFIGURATIONS ===========================*/

		if(!strcmp(argv[i], BUFFER_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the dimension of buffer in bytes! Bye!\n");
				exit(EXIT_FAILURE);
			}
			buffer_bytes_dim = strtoul(argv[++i], NULL, 10);
			kmod_params.buffer_bytes_dim = buffer_bytes_dim;
			bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			modern_bpf_params.buffer_bytes_dim = buffer_bytes_dim;
		}
		if(!strcmp(argv[i], TP_OPTION))
		{
			if(!(i + 1 < argc))
			{
				print_supported_tracepoints();
				printf("\nYou need to specify also the number of the tracepoint you are interested in! Bye!\n");
				exit(EXIT_FAILURE);
			}
			enable_single_tp(atoi(argv[++i]));
		}
		if(!strcmp(argv[i], PPM_SC_OPTION))
		{
			if(!(i + 1 < argc))
			{
				print_supported_syscalls();
				printf("\nYou need to specify also the syscall ppm_sc code! Bye!\n");
				exit(EXIT_FAILURE);
			}
			enable_single_ppm_sc(atoi(argv[++i]));
		}
		if(!strcmp(argv[i], NUM_EVENTS_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the number of events to catch! Bye!\n");
				exit(EXIT_FAILURE);
			}
			num_events = strtoul(argv[++i], NULL, 10);
		}
		if(!strcmp(argv[i], EVENT_TYPE_OPTION))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the event type number! Bye!\n");
				exit(EXIT_FAILURE);
			}
			evt_type = strtoul(argv[++i], NULL, 10);
		}
		if(!strcmp(argv[i], SIMPLE_SET_OPTION))
		{
			enable_simple_set();
		}
		/* This should be used only with the modern probe */
		if(!strcmp(argv[i], CPUS_FOR_EACH_BUFFER_MODE))
		{
			if(!(i + 1 < argc))
			{
				printf("\nYou need to specify also the number of CPUs. Bye!\n");
				exit(EXIT_FAILURE);
			}
			modern_bpf_params.cpus_for_each_buffer = atoi(argv[++i]);
		}
		/* This should be used only with the modern probe */
		if(!strcmp(argv[i], ALL_AVAILABLE_CPUS_MODE))
		{
			modern_bpf_params.allocate_online_only = false;
		}


		/*=============================== CONFIGURATIONS ===========================*/

		/*=============================== PRINT ===========================*/

		if(!strcmp(argv[i], PRINT_SYSCALLS_OPTION))
		{
			print_UF_NEVER_DROP_syscalls();
			print_EF_MODIFIES_STATE_syscalls();
			print_sinsp_modifies_state_syscalls();
			print_supported_syscalls();
			print_supported_tracepoints();
			exit(EXIT_SUCCESS);
		}
		if(!strcmp(argv[i], PRINT_HELP_OPTION))
		{
			print_help();
			exit(EXIT_SUCCESS);
		}

		/*=============================== PRINT ===========================*/
	}

	if(strcmp(oargs.engine_name, UNKNOWN_ENGINE) == 0)
	{
		printf("\nSource not specified! Bye!\n");
		exit(EXIT_FAILURE);
	}
}

void print_stats()
{
	gettimeofday(&tval_end, NULL);
	timersub(&tval_end, &tval_start, &tval_result);

	scap_stats s;
	printf("\n---------------------- STATS -----------------------\n");
	printf("Events correctly captured (SCAP_SUCCESS): %" PRIu64 "\n", g_nevts);
	scap_get_stats(g_h, &s);
	printf("Seen by driver: %" PRIu64 "\n", s.n_evts);
	printf("Time elapsed: %ld s\n", tval_result.tv_sec);
	if(tval_result.tv_sec != 0)
	{
		printf("Number of events/per-second: %ld\n", g_nevts / tval_result.tv_sec);
	}
	printf("Number of dropped events: %" PRIu64 "\n", s.n_drops);
	printf("Number of timeouts: %ld\n", number_of_timeouts);
	printf("Number of 'next' calls: %ld\n", number_of_scap_next);
	printf("Number of dropped events caused by full buffer (total / all buffer drops - includes all categories below, likely higher than sum of syscall categories): %" PRIu64 "\n", s.n_drops_buffer);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_clone_fork_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_clone_fork_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_execve_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_execve_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_execve_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_execve_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_connect_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_connect_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_connect_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_connect_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_open_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_open_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_open_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_open_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_dir_file_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_dir_file_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_dir_file_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_dir_file_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_other_interest_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_other_interest_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_other_interest_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_other_interest_exit);
	printf("Number of dropped events caused by full scratch map: %" PRIu64 "\n", s.n_drops_scratch_map);
	printf("Number of dropped events caused by invalid memory access (page faults): %" PRIu64 "\n", s.n_drops_pf);
	printf("Number of dropped events caused by an invalid condition in the kernel instrumentation (bug): %" PRIu64 "\n", s.n_drops_bug);
	printf("Number of preemptions: %" PRIu64 "\n", s.n_preemptions);
	printf("Number of events skipped due to the tid being in a set of suppressed tids: %" PRIu64 "\n", s.n_suppressed);
	printf("Number of threads currently being suppressed: %" PRIu64 "\n", s.n_tids_suppressed);
	printf("-----------------------------------------------------\n");
	printf("\n[SCAP-OPEN]: Bye!\n");
}

/*=============================== PRINT CAPTURE INFO ===========================*/

static void signal_callback(int signal)
{
	print_stats();
	exit(EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
	char error[SCAP_LASTERR_SIZE] = {0};
	int32_t res = 0;
	scap_evt* ev = NULL;
	uint16_t cpuid = 0;

	printf("\n[SCAP-OPEN]: Hello!\n");
	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	g_syscall_info_table = scap_get_syscall_info_table();

	parse_CLI_options(argc, argv);

	print_scap_source();

	print_configurations();

	enable_syscalls_and_print();

	enable_tracepoints_and_print();

	g_h = scap_open(&oargs, error, &res);
	if(g_h == NULL || res != SCAP_SUCCESS)
	{
		fprintf(stderr, "%s (%d)\n", error, res);
		return EXIT_FAILURE;
	}

	print_start_capture();

	gettimeofday(&tval_start, NULL);

	scap_start_capture(g_h);

	while(g_nevts != num_events)
	{
		res = scap_next(g_h, &ev, &cpuid);
		number_of_scap_next++;
		if(res == SCAP_UNEXPECTED_BLOCK)
		{
			res = scap_restart_capture(g_h);
			if(res == SCAP_SUCCESS)
			{
				continue;
			}
		}
		if(res == SCAP_TIMEOUT || res == SCAP_FILTERED_EVENT)
		{
			number_of_timeouts++;
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			scap_close(g_h);
			fprintf(stderr, "%s (%d)\n", scap_getlasterr(g_h), res);
			return -1;
		}

		if(ev->type == evt_type)
		{
			print_event(ev);
		}
		g_nevts++;
	}

	scap_stop_capture(g_h);
	print_stats();
	scap_close(g_h);
	return EXIT_SUCCESS;
}
