#include <iostream>
#include <string>
#include <scap.h>
#include <libpman.h>
#include <getopt.h>
#include <gtest/gtest.h>
#include "./event_class/event_class.h"

/* we supports only these modes */
/// TODO: share these options between all tests/scap-open/sinsp-example
#define KMOD_OPTION "kmod"
#define BPF_OPTION "bpf"
#define MODERN_BPF_OPTION "modern-bpf"
#define BUFFER_OPTION "buffer-dim"
#define BPF_PROBE_DEFAULT_PATH ""
#define KMOD_DEFAULT_PATH ""

static struct scap_bpf_engine_params bpf_params;
static struct scap_kmod_engine_params kmod_params;
static struct scap_modern_bpf_engine_params modern_bpf_params;

/* We need to simplify this logic */
scap_open_args parse_CLI_options(int argc, char** argv)
{
	static struct option long_options[] = {
		{BPF_OPTION, optional_argument, 0, 'b'},
		{MODERN_BPF_OPTION, no_argument, 0, 'm'},
		{KMOD_OPTION, optional_argument, 0, 'k'},
		{BUFFER_OPTION, required_argument, 0, 'd'},
		{0, 0, 0, 0}};

	scap_open_args oargs = {0};
	oargs.mode = SCAP_MODE_LIVE;
	int op;
	int long_index = 0;
	unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
	while((op = getopt_long(argc, argv,
				"b::mk::d:",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'b':
			oargs.engine_name = BPF_ENGINE;
			bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			/* When the argument is required it should be passed like this `b<path>`
			 * and not like `b <path>`, sot without the white space! This first `if`
			 * allow us to handle also the case with the whitespace
			 */
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				optarg = argv[optind++];
				bpf_params.bpf_probe = optarg;
			}
			/* This is the case in which we don't have the arg*/
			else if(optarg == NULL)
			{
				bpf_params.bpf_probe = BPF_PROBE_DEFAULT_PATH;
			}
			else
			{
				bpf_params.bpf_probe = optarg;
			}
			oargs.engine_params = &bpf_params;
			break;
		case 'm':
			oargs.engine_name = MODERN_BPF_ENGINE;
			modern_bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			oargs.engine_params = &modern_bpf_params;
			break;
		case 'k':
			oargs.engine_name = KMOD_ENGINE;
			kmod_params.buffer_bytes_dim = buffer_bytes_dim;
			/* When the argument is required it should be passed like this `b<path>`
			 * and not like `b <path>`, sot without the white space! This first `if`
			 * allow us to handle also the case with the whitespace
			 */
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				optarg = argv[optind++];
				/*we should insmod here.*/
			}
			/* This is the case in which we don't have the arg*/
			else if(optarg == NULL)
			{
				/*we should insmod here.*/
			}
			else
			{
				/*we should insmod here.*/
			}
			oargs.engine_params = &kmod_params;
			break;
		case 'd':
			buffer_bytes_dim = strtoul(optarg, NULL, 10);
			break;
		default:
			break;
		}
	}
	return oargs;
}

void print_setup_phase_message()
{
	std::cout << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << "-------------------- Setup phase --------------------" << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << std::endl;
}

void print_start_test_message()
{
	std::cout << "* BPF probe correctly configured!" << std::endl;
	std::cout << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << "------------------- Testing phase -------------------" << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << std::endl;
}

void print_teardown_test_message()
{
	std::cout << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << "------------------- Teardown phase ------------------" << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << std::endl;
}

scap_t* event_test::scap_handle = NULL;

int main(int argc, char** argv)
{
	print_setup_phase_message();

	::testing::InitGoogleTest(&argc, argv);

	/* Parse configs */
	int res = 0;
	scap_open_args oargs = parse_CLI_options(argc, argv);
	char error_buffer[SCAP_LASTERR_SIZE];

	/* This call the init method and start the capture so inject the tracepoints */
	scap_t* handle = scap_open(&oargs, error_buffer, &res);
	if(res != SCAP_SUCCESS)
	{
		std::cout << "Error in opening the scap handle: " << error_buffer << std::endl;
		exit(EXIT_FAILURE);
	}

	/* We need to detach all the tracepoints before starting tests. */
	res = scap_stop_capture(handle);
	if(res != SCAP_SUCCESS)
	{
		std::cout << "Error in stopping the capture: " << scap_getlasterr(handle) << std::endl;
		goto cleanup_tests;
	}

	/* We need to disable also all the interesting syscalls */
	res = scap_clear_eventmask(handle);
	if(res != SCAP_SUCCESS)
	{
		std::cout << "Error in clearing the syscalls of interests: " << scap_getlasterr(handle) << std::endl;
		goto cleanup_tests;
	}

	/* Now we need to pass this object as a static member of the class */
	event_test::set_scap_handle(handle);
	print_start_test_message();

	res = RUN_ALL_TESTS();

cleanup_tests:
	print_teardown_test_message();
	scap_close(handle);
	return res;
}
