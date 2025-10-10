#pragma once

#include <sys/resource.h> /* to get rlimit_resource */
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#define MAX_PATH 4096
#define MAX_NUM_ARGS 16 /* we parse at most 16 arguments for the process like in BPF */

/* Params that we need to catch from proc. There are cases
 * in which we don't need them all.
 */
struct proc_info {
	uint32_t tty = 0;
	pid_t ppid = 0; /* The PID of the parent of this process. */
	pid_t pgid = 0; /* The process group ID of the process. */
	char raw_args[MAX_NUM_ARGS][MAX_PATH] = {};
	const char* args[MAX_NUM_ARGS] = {};
	uint32_t uid = 0;
	uint32_t gid = 0;
	uint32_t vpid = 0;
	uint32_t vtid = 0;
	struct rlimit file_rlimit = {0, 0};
	uint32_t loginuid = 0;
	char exepath[MAX_PATH] = {};
};

bool get_proc_info(pid_t pid, proc_info* info);
pid_t get_proc_max_pid();
