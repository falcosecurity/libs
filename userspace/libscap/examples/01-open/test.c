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

uint64_t g_nevts = 0;
scap_t* g_h = NULL;

/* Configuration variables set through CLI. */
uint64_t num_events = UINT64_MAX;
bool bpf_probe = false;
bool simple_consumer = false;
uint16_t evt_type = -1;
uint16_t* lens16 = NULL;
char* valptr = NULL;

extern const struct ppm_syscall_desc g_syscall_info_table[PPM_SC_MAX];
extern const struct ppm_event_info g_event_info[PPM_EVENT_MAX];

void print_stats()
{
	scap_stats s;
	printf("\n---------------------- STATS -----------------------\n");
	printf("events captured: %" PRIu64 "\n", g_nevts);
	scap_get_stats(g_h, &s);
	printf("seen by driver: %" PRIu64 "\n", s.n_evts);
	printf("Number of dropped events: %" PRIu64 "\n", s.n_drops);
	printf("Number of dropped events caused by full buffer: %" PRIu64 "\n", s.n_drops_buffer);
	printf("Number of dropped events caused by full scratch map: %" PRIu64 "\n", s.n_drops_scratch_map);
	printf("Number of dropped events caused by invalid memory access: %" PRIu64 "\n", s.n_drops_pf);
	printf("Number of dropped events caused by an invalid condition in the kernel instrumentation: %" PRIu64 "\n", s.n_drops_bug);
	printf("Number of preemptions: %" PRIu64 "\n", s.n_preemptions);
	printf("Number of events skipped due to the tid being in a set of suppressed tids: %" PRIu64 "\n", s.n_suppressed);
	printf("Number of threads currently being suppressed: %" PRIu64 "\n", s.n_tids_suppressed);
	printf("-----------------------------------------------------\n");
}

static void signal_callback(int signal)
{
	print_stats();
	exit(EXIT_SUCCESS);
}

void print_help()
{
	printf("\n----------------------- MENU -----------------------\n");
	printf("'--bpf <probe_path>': enable the BPF probe instead of the kernel module. (default: disabled)\n");
	printf("'--simple_consumer': enable the simple consumer mode. (default: disabled)\n");
	printf("'--num_events <num_events>': number of events to catch before terminating. (default: UINT64_MAX)\n");
	printf("'--help': print this menu.\n");
	printf("-----------------------------------------------------\n");
}

void print_configuration()
{
	printf("\n---------------------- CONFIG ----------------------\n");
	if(bpf_probe)
	{
		printf("* DRIVER: BPF probe\n");
	}
	else
	{
		printf("* DRIVER: Kernel module\n");
	}

	if(simple_consumer)
	{
		printf("* MODE: Simple consumer\n");
	}

	if(evt_type != -1)
	{
		printf("* EVENT_TYPE: %d\n", evt_type);
	}

	if(num_events != UINT64_MAX)
	{
		printf("* EVENTS TO CATCH: %lu\n", num_events);
	}
	else
	{
		printf("* EVENTS TO CATCH: UINT64_MAX\n");
	}
	printf("-----------------------------------------------------\n");
}

void print_load_success()
{
	if(bpf_probe)
	{
		printf("\n * OK! BPF probe correctly loaded: NO VERIFIER ISSUES :)\n");
	}
	else
	{
		printf("\n * OK! Kernel module correctly loaded\n");
	}
}

void print_start_capture()
{
	printf("\n * Capture in progress...\n");
}

void print_ipv4(int starting_index)
{
	char ipv4_string[50];
	uint8_t* ipv4 = (uint8_t*)(valptr + starting_index);
	sprintf(ipv4_string, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
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

int main(int argc, char** argv)
{
	char error[SCAP_LASTERR_SIZE];
	int32_t res;
	scap_evt* ev;
	uint16_t cpuid;

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return -1;
	}

	scap_open_args args = {.mode = SCAP_MODE_LIVE};

	/* Base configuration without simple consumer. */
	for(int j = 0; j < PPM_SC_MAX; j++)
	{
		args.ppm_sc_of_interest.ppm_sc[j] = 1;
	}

	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], "--bpf") && ++i < argc)
		{
			args.bpf_probe = argv[i];
			bpf_probe = true;
		}
		if(!strcmp(argv[i], "--simple_consumer"))
		{
			args.ppm_sc_of_interest.ppm_sc[PPM_SC_UNKNOWN] = 0;

			/* Starting from '1' since we ignore all the unknown syscalls (PPM_SC_UNKNOWN). */
			for(int j = 1; j < PPM_SC_MAX; j++)
			{
				args.ppm_sc_of_interest.ppm_sc[j] = !(g_syscall_info_table[j].flags & EF_DROP_SIMPLE_CONS);
			}
			simple_consumer = true;
		}
		if(!strcmp(argv[i], "--num_events") && ++i < argc)
		{
			num_events = strtoul(argv[i], NULL, 10);
		}
		if(!strcmp(argv[i], "--evt_type") && ++i < argc)
		{
			evt_type = strtoul(argv[i], NULL, 10);
		}
		if(!strcmp(argv[i], "--help"))
		{
			print_help();
			return EXIT_SUCCESS;
		}
	}

	print_configuration();

	g_h = scap_open(args, error, &res);
	if(g_h == NULL)
	{
		fprintf(stderr, "%s (%d)\n", error, res);
		return EXIT_FAILURE;
	}

	print_load_success();

	print_start_capture();

	while(g_nevts != num_events)
	{
		res = scap_next(g_h, &ev, &cpuid);

		if(res > 0)
		{
			fprintf(stderr, "%s\n", scap_getlasterr(g_h));
			scap_close(g_h);
			return -1;
		}

		if(res != SCAP_TIMEOUT)
		{
			if(ev->type == evt_type)
			{
				lens16 = (uint16_t*)((char*)ev + sizeof(struct ppm_evt_hdr));
				valptr = (char*)lens16 + ev->nparams * sizeof(uint16_t);
				printf("\n------------------ EVENT: %d TID:%lu\n", evt_type, ev->tid);
				for(int i = 0; i < ev->nparams; i++)
				{
					print_parameter(i);
				}
				printf("------------------\n");
			}
			g_nevts++;
		}
	}

	print_stats();
	scap_close(g_h);
	return EXIT_SUCCESS;
}
