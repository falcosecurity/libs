// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include "sys_call_test.h"
#include "libsinsp_test_var.h"

#include <cstdlib>
#include <filesystem>
#include <getopt.h>

#include <libscap/scap_engines.h>

#define HELP_OPTION "help"
#define VERBOSE_OPTION "verbose"
#define KMOD_OPTION "kmod"
#define BPF_OPTION "bpf"
#define MODERN_BPF_OPTION "modern-bpf"
#define BUFFER_OPTION "buffer-dim"

class EventListener : public ::testing::EmptyTestEventListener
{
public:
	EventListener(bool keep_capture_files) { m_keep_capture_files = keep_capture_files; }

	// Called before a test starts.
	virtual void OnTestStart(const ::testing::TestInfo& test_info) {}

	// Called after a failed assertion or a SUCCEED() invocation.
	virtual void OnTestPartResult(const ::testing::TestPartResult& test_part_result) {}

	// Called after a test ends.
	virtual void OnTestEnd(const ::testing::TestInfo& test_info)
	{
		if (!m_keep_capture_files && !test_info.result()->Failed())
		{
			std::string dump_filename = std::string(LIBSINSP_TEST_CAPTURES_PATH) + test_info.test_case_name() + "_	" +
			                       test_info.name() + ".scap";
			std::remove(dump_filename.c_str());
		}
	}

private:
	bool m_keep_capture_files;
};

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
	close(fd);
	return EXIT_SUCCESS;
}

int remove_kmod()
{
	if(syscall(__NR_delete_module, LIBSINSP_TEST_KERNEL_MODULE_NAME, O_NONBLOCK))
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
				int ret = syscall(__NR_delete_module, LIBSINSP_TEST_KERNEL_MODULE_NAME, O_NONBLOCK);
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

void print_menu_and_exit()
{
	std::string usage = R"(Usage: tests [options]

Overview: The goal of this binary is to run tests against libsinsp.

Options:
  -k, --kmod <path>       Run tests against the kernel module. Default path is `./driver/scap.ko`.
  -m, --modern-bpf        Run tests against the modern bpf probe.
  -b, --bpf <path>        Run tests against the bpf probe. Default path is `./driver/bpf/probe.o`.
  -d, --buffer-dim <dim>  Change the dimension of shared buffers between userspace and kernel. You must specify the dimension in bytes.
  -v, --verbose <level>   Print all available logs. Default level is WARNING (4).
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
		{VERBOSE_OPTION, required_argument, 0, 'v'},
		{0, 0, 0, 0}};

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
				"b::mk::d:hv:",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'b':
#ifdef HAS_ENGINE_BPF
			event_capture::set_engine(BPF_ENGINE, LIBSINSP_TEST_BPF_PROBE_PATH);
#else
			std::cerr << "BPF engine is not supported in this build" << std::endl;
			return EXIT_FAILURE;
#endif
			break;

		case 'm':
#ifdef HAS_ENGINE_MODERN_BPF
			event_capture::set_engine(MODERN_BPF_ENGINE, "");
#else
			std::cerr << "Modern BPF engine is not supported in this build" << std::endl;
			return EXIT_FAILURE;
#endif
			break;

		case 'k':
#ifdef HAS_ENGINE_KMOD
			insert_kmod(LIBSINSP_TEST_KERNEL_MODULE_PATH);
			event_capture::set_engine(KMOD_ENGINE, LIBSINSP_TEST_KERNEL_MODULE_PATH);
#else
			std::cerr << "Kernel module engine is not supported in this build" << std::endl;
			return EXIT_FAILURE;
#endif
			break;

		case 'd':
			event_capture::set_buffer_dim(strtoul(optarg, NULL, 10));
			break;

		case 'h':
			print_menu_and_exit();
			break;

		default:
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc, argv);

	std::string captures_dir = LIBSINSP_TEST_CAPTURES_PATH;

	if(!std::filesystem::exists(captures_dir))
	{
		if (!std::filesystem::create_directory(captures_dir)) {
			std::cerr << "Failed to create captures directory." << std::endl;;
			return EXIT_FAILURE;
		}
	}

	if(open_engine(argc, argv) == EXIT_FAILURE)
	{
		std::cerr << "Failed to open the engine." << std::endl;;
		return EXIT_FAILURE;
	}

	return RUN_ALL_TESTS();
}
