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
#include <signal.h>
#include <scap.h>

uint64_t g_nevts = 0;
scap_t* g_h = NULL;
bool premature_death = false;
bool bpf_probe = false;
bool simple_consumer = false;

extern const struct ppm_syscall_desc g_syscall_info_table[PPM_SC_MAX];

static void signal_callback(int signal)
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
	exit(0);
}

void print_help()
{
	printf("\n----------------------- MENU -----------------------\n");
	printf("'--bpf': enable the BPF probe instead of the kernel module.\n");
	printf("'--sc'(simple_consumer): enable the simple consumer mode.\n");
	printf("'--pd'(premature_death): load the driver and capture only one event.\n");
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

	if(premature_death)
	{
		printf("* MODE: Premature death\n");
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

void print_premature_death()
{
	printf("\n * OK! We correctly catched one event! Bye!\n");
}

void print_start_capture()
{
	printf("\n * Capture in progress...\n");
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
		if(!strcmp(argv[i], "--sc"))
		{
			args.ppm_sc_of_interest.ppm_sc[PPM_SC_UNKNOWN] = 0;

			/* Starting from '1' since we ignore all the unknown syscalls (PPM_SC_UNKNOWN). */
			for(int j = 1; j < PPM_SC_MAX; j++)
			{
				args.ppm_sc_of_interest.ppm_sc[j] = !(g_syscall_info_table[j].flags & EF_DROP_SIMPLE_CONS);
			}
			simple_consumer = true;
		}
		if(!strcmp(argv[i], "--pd"))
		{
			premature_death = true;
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

	if(premature_death)
	{
		while(scap_next(g_h, &ev, &cpuid) != 0)
			;
		print_premature_death();
		goto cleanup;
	}

	print_start_capture();

	while(1)
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
			g_nevts++;
		}
	}

cleanup:
	scap_close(g_h);
	return EXIT_SUCCESS;
}
