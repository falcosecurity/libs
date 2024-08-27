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
struct proc_info
{
	uint32_t tty;
	pid_t ppid; /* The PID of the parent of this process. */
	pid_t pgid; /* The process group ID of the process. */
	char raw_args[MAX_NUM_ARGS][MAX_PATH];
	const char* args[MAX_NUM_ARGS];
	uint32_t uid;
	uint32_t gid;
	uint32_t vpid;
	uint32_t vtid;
	struct rlimit file_rlimit;
	uint32_t loginuid;
	char exepath [MAX_PATH];
};

bool get_proc_info(pid_t pid, proc_info* info);
