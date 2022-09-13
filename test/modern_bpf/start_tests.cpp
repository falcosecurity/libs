#include <sys/resource.h>
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <libpman.h>
#include <gtest/gtest.h>

/* Dimension of every single ring buffer in these tests is 8 MB. */
#define RINGBUF_BYTES_DIMENSION 8 * 1024 * 1024

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

	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], "--verbose"))
		{
			libbpf_verbosity = true;
		}
	}

	print_setup_phase_message();

	::testing::InitGoogleTest(&argc, argv);

	/* Configure and load BPF probe. */
	ret = pman_init_state(libbpf_verbosity, RINGBUF_BYTES_DIMENSION);
	ret = ret ?: pman_open_probe();
	ret = ret ?: pman_prepare_ringbuf_array_before_loading();
	ret = ret ?: pman_prepare_maps_before_loading();
	ret = ret ?: pman_load_probe();
	ret = ret ?: pman_finalize_maps_after_loading();
	ret = ret ?: pman_finalize_ringbuf_array_after_loading();
	/* Syscall dispatchers are always attached.
	 * Generic tracepoints will be attached only in the dedicated test cases.
	 */
	ret = ret ?: pman_attach_syscall_enter_dispatcher();
	ret = ret ?: pman_attach_syscall_exit_dispatcher();
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
