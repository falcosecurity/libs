#include <sys/resource.h>
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <libpman.h>
#include <scap.h>
#include <gtest/gtest.h>

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

int main(int argc, char** argv)
{
	int ret;
	bool libbpf_verbosity = false;
	unsigned long buffer_dim = 8 * 1024; /* Should be enough */

	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], "--verbose"))
		{
			libbpf_verbosity = true;
		}
		if(!strcmp(argv[i], "--buffer_dim"))
		{
			if(!(i + 1 < argc))
			{
				std::cout << "\nYou need to specify also the dimension of buffer in bytes! Bye!" << std::endl;
				exit(EXIT_FAILURE);
			}
			buffer_dim = strtoul(argv[++i], NULL, 10);;
		}
	}

	print_setup_phase_message();

	::testing::InitGoogleTest(&argc, argv);

	/* Configure and load BPF probe. */
	ret = pman_init_state(libbpf_verbosity, buffer_dim, DEFAULT_CPU_FOR_EACH_BUFFER, true);
	ret = ret ?: pman_open_probe();
	ret = ret ?: pman_prepare_ringbuf_array_before_loading();
	ret = ret ?: pman_prepare_maps_before_loading();
	ret = ret ?: pman_load_probe();
	ret = ret ?: pman_finalize_maps_after_loading();
	ret = ret ?: pman_finalize_ringbuf_array_after_loading();
	if(ret)
	{
		std::cout << "\n* Error in the bpf probe setup, TESTS not started!" << std::endl;
		goto cleanup_tests;
	}

	/* Ensure that nothing is running before starting tests. */
	pman_disable_capture();
	pman_clean_all_64bit_interesting_syscalls();

	print_start_test_message();

	ret = RUN_ALL_TESTS();

cleanup_tests:
	print_teardown_test_message();
	pman_close_probe();
	std::cout << "* BPF probe correctly detached! Bye!" << std::endl;
	return ret;
}
