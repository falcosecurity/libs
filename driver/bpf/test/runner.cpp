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

#include <gtest.h>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <future>
#include <chrono>
#include <getopt.h>

#include "filler_test.h"

char *g_probe_path;

void handle_bpf_tracing(std::future<void> future)
{
#ifdef BPF_TEST_DEBUG
	std::ifstream trace_pipe("/sys/kernel/debug/tracing/trace_pipe");
	if(!trace_pipe.good())
	{
		std::cerr << "[bpf_printk]: could not open '/sys/kernel/debug/tracing/trace_pipe', bpf_printk output will not be available" << std::endl;
		return;
	}
	std::cout << "[bpf_printk]: trace pipe output available for printk calls, make sure to compile the bpf probe with -DDEBUG if you want to see those while running the tests" << std::endl;
	std::string line;
	while(future.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout)
	{
		if(std::getline(trace_pipe, line))
		{
			std::cout << "[bpf_printk]: " << line << std::endl;
			continue;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
#endif
}

int main(int argc, char **argv)
{
	int ret;

	::testing::InitGoogleTest(&argc, argv);

	int c;
	std::string probe_path;
	while(true)
	{
		int option_index = 0;
		static struct option long_options[] = {
			{"probe", required_argument, 0, 'p'},
			{0, 0, 0, 0}};

		c = getopt_long(argc, argv, "p:",
				long_options, &option_index);
		if(c == -1)
			break;

		if(c == 'p')
		{
			probe_path = optarg;
		}
	}

	if(probe_path.length() == 0)
	{
		std::cerr << "You need to provide the probe path to execute this test suite" << std::endl;
		std::cerr << "\t --probe=<path>" << std::endl;
		return EXIT_FAILURE;
	}
	g_probe_path = (char *)probe_path.c_str();

	std::promise<void> exit_promise;
	std::future<void> future = exit_promise.get_future();
	std::thread bpf_trace_pipe_thread(&handle_bpf_tracing, std::move(future));

	ret = RUN_ALL_TESTS();

	exit_promise.set_value();
	bpf_trace_pipe_thread.join();
	return ret;
}