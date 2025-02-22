#include <thread>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iostream>
#include <cstring>
#include <cstdint>

#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

// Utility function to calculate CPU usage
int get_cpu_usage_percent()
{

	constexpr uint64_t USECS_PER_SEC = 1000L * 1000;
	static uint64_t cpu_time_last_run_us = 0;
	static uint64_t time_last_run_us = 0;
	double cpu_usage = 0.0;

	// Get the current timestamp in usecs
	auto time_since_epoch = std::chrono::steady_clock::now().time_since_epoch();
	auto curr_time_us = std::chrono::duration_cast<std::chrono::microseconds>(time_since_epoch).count();

	// Get the current thread's CPU times
	struct rusage usage;
	if (getrusage(RUSAGE_THREAD, &usage) != 0) {
		return -1;
	}

	// Calculate the thread's CPU time (user + system) in usecs
	uint64_t curr_cpu_time_us = (usage.ru_utime.tv_sec * USECS_PER_SEC + usage.ru_utime.tv_usec) +
	                            (usage.ru_stime.tv_sec * USECS_PER_SEC + usage.ru_stime.tv_usec);

	if (time_last_run_us != 0) {
		// Calculate the CPU usage percentage since the last iteration
		uint64_t time_diff_us = (double)(curr_time_us - time_last_run_us);
		uint64_t cpu_diff_us = (double)(curr_cpu_time_us - cpu_time_last_run_us);
		cpu_usage = ((double)cpu_diff_us * 100.0) / time_diff_us;
	}

	cpu_time_last_run_us = curr_cpu_time_us;
	time_last_run_us = curr_time_us;
	return cpu_usage;
}