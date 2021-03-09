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

void handle_bpf_tracing(std::future<void> future)
{
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
}

int main(int argc, char **argv)
{
	int ret;
	std::promise<void> exit_promise;
	std::future<void> future = exit_promise.get_future();
	std::thread bpf_trace_pipe_thread(&handle_bpf_tracing, std::move(future));

	::testing::InitGoogleTest(&argc, argv);
	ret = RUN_ALL_TESTS();

	exit_promise.set_value();
	bpf_trace_pipe_thread.join();
	return ret;
}