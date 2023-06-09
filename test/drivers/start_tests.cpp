#include <iostream>
#include <string>
#include <scap.h>
#include <getopt.h>
#include <gtest/gtest.h>
#include "./event_class/event_class.h"
#include "strl.h"

#define UNKNOWN_ENGINE "unknown"

/* We support only these arguments */
#define HELP_OPTION "help"
#define KMOD_OPTION "kmod"
#define BPF_OPTION "bpf"
#define MODERN_BPF_OPTION "modern-bpf"
#define BUFFER_OPTION "buffer-dim"
#define BPF_PROBE_DEFAULT_PATH "/driver/bpf/probe.o"
#define KMOD_DEFAULT_PATH "/driver/scap.ko"
#define KMOD_NAME "scap"

scap_t* event_test::s_scap_handle = NULL;

int remove_kmod()
{
	if(syscall(__NR_delete_module, KMOD_NAME, O_NONBLOCK))
	{
		switch(errno)
		{
		case ENOENT:
			return EXIT_SUCCESS;

		/* If a module has a nonzero reference count with `O_NONBLOCK` flag
		 * the call returns immediately, with `EWOULDBLOCK` code. So in that
		 * case we wait until the module is detached.
		 */
		case EWOULDBLOCK:
			for(int i = 0; i < 4; i++)
			{
				int ret = syscall(__NR_delete_module, KMOD_NAME, O_NONBLOCK);
				if(ret == 0 || errno == ENOENT)
				{
					return EXIT_SUCCESS;
				}
				sleep(1);
			}
			return EXIT_FAILURE;

		case EBUSY:
		case EFAULT:
		case EPERM:
			std::cerr << "Unable to remove kernel module. Errno message: " << strerror(errno) << ", errno: " << errno << std::endl;
			return EXIT_FAILURE;

		default:
			std::cerr << "Unexpected error code. Errno message: " << strerror(errno) << ", errno: " << errno << std::endl;
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int insert_kmod(const std::string& kmod_path)
{
	/* Here we want to insert the module if we fail we need to abort the program. */
	int fd = open(kmod_path.c_str(), O_RDONLY);
	if(fd < 0)
	{
		std::cout << "Unable to open the kmod file. Errno message: " << strerror(errno) << ", errno: " << errno << std::endl;
		return EXIT_FAILURE;
	}

	if(syscall(__NR_finit_module, fd, "", 0))
	{
		std::cerr << "Unable to inject the kmod. Errno message: " << strerror(errno) << ", errno: " << errno << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void abort_if_already_configured(scap_open_args* oargs)
{
	if(strcmp(oargs->engine_name, UNKNOWN_ENGINE) != 0)
	{
		std::cerr << "* '" << oargs->engine_name << "' engine is already configured. Please specify just one engine!" << std::endl;
		exit(EXIT_FAILURE);
	}
}

void print_message(std::string msg)
{
	std::cout << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << "- " << msg << std::endl;
	std::cout << "-----------------------------------------------------" << std::endl;
	std::cout << std::endl;
}

void print_menu_and_exit()
{
	std::string usage = R"(Usage: drivers_test [options]

Overview: The goal of this binary is to run tests against one of our drivers.

Options:
  -k, --kmod <path>       Run tests against the kernel module. Default path is `./driver/scap.ko`.
  -m, --modern-bpf        Run tests against the modern bpf probe.
  -b, --bpf <path>        Run tests against the bpf probe. Default path is `./driver/bpf/probe.o`.
  -d, --buffer-dim <dim>  Change the dimension of shared buffers between userspace and kernel. You must specify the dimension in bytes.
  -h, --help              This page.
)";
	std::cout << usage << std::endl;
	exit(EXIT_SUCCESS);
}

int open_engine(int argc, char** argv)
{
	static struct option long_options[] = {
		{BPF_OPTION, optional_argument, 0, 'b'},
		{MODERN_BPF_OPTION, no_argument, 0, 'm'},
		{KMOD_OPTION, optional_argument, 0, 'k'},
		{BUFFER_OPTION, required_argument, 0, 'd'},
		{HELP_OPTION, no_argument, 0, 'h'},
		{0, 0, 0, 0}};

	int ret = 0;
	scap_open_args oargs = {0};
	struct scap_bpf_engine_params bpf_params = {0};
	struct scap_kmod_engine_params kmod_params = {0};
	struct scap_modern_bpf_engine_params modern_bpf_params = {0};
	oargs.engine_name = UNKNOWN_ENGINE;
	oargs.mode = SCAP_MODE_LIVE;
	unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
	std::string kmod_path;

	/* Remove kmod if injected, we remove it always even if we use another engine
	 * in this way we are sure the unique driver in the system is the one we will use.
	 */
	if(remove_kmod())
	{
		return EXIT_FAILURE;
	}

	/* Get current cwd as a base directory for the driver path */
	char driver_path[FILENAME_MAX];
	if(!getcwd(driver_path, FILENAME_MAX))
	{
		std::cerr << "Unable to get current dir" << std::endl;
		return EXIT_FAILURE;
	}

	/* Parse CLI options */
	int op = 0;
	int long_index = 0;
	while((op = getopt_long(argc, argv,
				"b::mk::d:h",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'b':
			abort_if_already_configured(&oargs);
			oargs.engine_name = BPF_ENGINE;
			bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			/* This should handle cases where we pass arguments with the space:
			 * `-b ./path/to/probe`. Without this `if` case we can accept arguments
			 * only in this format `-b./path/to/probe`
			 */
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				bpf_params.bpf_probe = argv[optind++];
			}
			else if(optarg == NULL)
			{
				strlcat(driver_path, BPF_PROBE_DEFAULT_PATH, FILENAME_MAX);
				bpf_params.bpf_probe = driver_path;
			}
			else
			{
				bpf_params.bpf_probe = optarg;
			}
			oargs.engine_params = &bpf_params;

			std::cout << "* Configure BPF probe tests! Probe path: " << bpf_params.bpf_probe << std::endl;
			break;

		case 'm':
			abort_if_already_configured(&oargs);
			oargs.engine_name = MODERN_BPF_ENGINE;
			modern_bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			oargs.engine_params = &modern_bpf_params;
			std::cout << "* Configure modern BPF probe tests!" << std::endl;
			break;

		case 'k':
			abort_if_already_configured(&oargs);
			oargs.engine_name = KMOD_ENGINE;
			kmod_params.buffer_bytes_dim = buffer_bytes_dim;
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				kmod_path = argv[optind++];
			}
			else if(optarg == NULL)
			{
				strlcat(driver_path, KMOD_DEFAULT_PATH, FILENAME_MAX);
				kmod_path = driver_path;
			}
			else
			{
				kmod_path = optarg;
			}
			oargs.engine_params = &kmod_params;
			if(insert_kmod(kmod_path))
			{
				return EXIT_FAILURE;
			}
			std::cout << "* Configure kernel module tests! Kernel module path: " << kmod_path << std::endl;
			;
			break;

		case 'd':
			buffer_bytes_dim = strtoul(optarg, NULL, 10);
			break;

		case 'h':
			print_menu_and_exit();
			break;

		default:
			break;
		}
	}
	std::cout << "* Using buffer dim: " << buffer_bytes_dim << std::endl;

	if(strcmp(oargs.engine_name, UNKNOWN_ENGINE) == 0)
	{
		std::cerr << "Unsupported engine! Choose between: m, b, k" << std::endl;
		return EXIT_FAILURE;
	}

	char error_buffer[FILENAME_MAX] = {0};
	event_test::s_scap_handle = scap_open(&oargs, error_buffer, &ret);
	if(!event_test::s_scap_handle)
	{
		std::cerr << "Unable to open the engine: " << error_buffer << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
	int res = EXIT_SUCCESS;

	print_message("Setup phase");

	::testing::InitGoogleTest(&argc, argv);

	/* Open the requested engine */
	if(open_engine(argc, argv))
	{
		return EXIT_FAILURE;
	}

	print_message("Testing phase");

	res = RUN_ALL_TESTS();

	print_message("Teardown phase");
	scap_close(event_test::s_scap_handle);
	remove_kmod();
	return res;
}
