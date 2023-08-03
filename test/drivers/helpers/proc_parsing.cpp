#include "proc_parsing.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <errno.h>

bool get_proc_info(pid_t pid, proc_info* info)
{
	char path_to_read[MAX_PATH];

	/*
	 * Read some info regarding the stats of the process from `/proc/[pid]/stat`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/stat", pid);
	FILE* stat = fopen(path_to_read, "r");
	if(stat == NULL)
	{
		std::cerr << "'fopen /proc/[pid]/stat' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		return false;
	}

	/* we could get the filename of the executable (`comm`) from proc, but it is returned
	 * in parentheses, so for example "(bpf_test)", so we prefer to use our macro `TEST_EXECUTABLE_NAME`
	 */
	if(fscanf(stat, "%*d %*s %*c %d %d %*d %d", &info->ppid, &info->pgid, &info->tty) < 0)
	{
		std::cerr << "'fscanf /proc/[pid]/stat' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		fclose(stat);
		return false;
	}
	fclose(stat);

	/*
	 * Read cmdline arguments from `/proc/[pid]/cmdline`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/cmdline", pid);
	FILE* cmdline = fopen(path_to_read, "r");
	if(cmdline == NULL)
	{
		std::cerr << "'fopen /proc/[pid]/cmdline' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		return false;
	}

	int c;
	int i = 0;
	int j = 0;
	while((c = fgetc(cmdline)) != EOF && i < MAX_NUM_ARGS)
	{
		info->raw_args[i][j] = (char)c;
		j++;

		if(c == '\0')
		{
			info->args[i] = info->raw_args[i];
			i++;
			j = 0;
		}
	}
	if(i < MAX_NUM_ARGS)
	{
		info->args[i] = NULL;
	}
	fclose(cmdline);

	/*
	 * Read some info regarding the status of the process from `/proc/[pid]/status`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/status", pid);
	FILE* status = fopen(path_to_read, "r");
	if(status == NULL)
	{
		std::cerr << "'fopen /proc/[pid]/status' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		return false;
	}

	char line[MAX_PATH];
	char prefix[MAX_PATH];

	uint32_t temp = 0;

	int found = 0;
	while(fgets(line, MAX_PATH, status) != NULL)
	{
		sscanf(line, "%s %d %*s\n", prefix, &temp);
		if(strncmp(prefix, "Uid:", 5) == 0)
		{
			info->uid = temp;
			found++;
		}

		if(strncmp(prefix, "Gid:", 5) == 0)
		{
			info->gid = temp;
			found++;
		}

		if(strncmp(prefix, "NStgid:", 8) == 0)
		{
			info->vpid = temp;
			found++;
		}

		if(strncmp(prefix, "NSpid:", 7) == 0)
		{
			info->vtid = temp;
			found++;
		}

		if(found == 4)
		{
			break;
		}
	}
	fclose(status);

	/*
	 * Get rlimit
	 */

	if(getrlimit(RLIMIT_NOFILE, &info->file_rlimit) == -1)
	{
		std::cerr << "'getrlimit' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		return false;
	}

	/*
	 * Read `loginuid` from `/proc/[pid]/loginuid`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/loginuid", pid);
	FILE* login = fopen(path_to_read, "r");
	if(login == NULL)
	{
		std::cerr << "'fopen /proc/[pid]/loginuid' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		return false;
	}
	if(fscanf(login, "%d", &info->loginuid) != 1)
	{
		std::cerr << "'fscanf /proc/[pid]/loginuid' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
		fclose(login);
		return false;
	}
	fclose(login);

	snprintf(path_to_read, sizeof(path_to_read), "/proc/%u/exe", ::getpid());

	/*
	 * Gather the executable full name	
	 */
	int res = readlink(path_to_read, info->exepath, sizeof(info->exepath) - 1);

	if(res <= 0)
	{
		std::cerr << "'unable to readlink /proc/pid/exe: (" << errno << "), " << strerror(errno) << std::endl;
		return false;
	}
	/* Null termination */
	info->exepath[res] = 0;

	return true;
}
