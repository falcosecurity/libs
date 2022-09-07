/*
Copyright (C) 2022 The Falco Authors.

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

#include <sinsp.h>

std::unordered_set<uint32_t> sinsp::simple_ppm_sc_set()
{
	return std::unordered_set<uint32_t>{
		PPM_SC_ACCEPT,
		PPM_SC_ACCEPT4,
		PPM_SC_BIND,
		PPM_SC_BPF,
		PPM_SC_CAPSET,
		PPM_SC_CHDIR,
		PPM_SC_CHMOD,
		PPM_SC_CHROOT,
		PPM_SC_CLONE,
		PPM_SC_CLONE3,
		PPM_SC_CLOSE,
		PPM_SC_CONNECT,
		PPM_SC_COPY_FILE_RANGE, // REMOVE?
		PPM_SC_CREAT,
		PPM_SC_DUP,
		PPM_SC_DUP2,
		PPM_SC_DUP3,
		PPM_SC_EVENTFD,
		PPM_SC_EVENTFD2,
		PPM_SC_EXECVE,
		PPM_SC_EXECVEAT,
		PPM_SC_FCHDIR,
		PPM_SC_FCHMOD,
		PPM_SC_FCHMODAT,
		PPM_SC_FCNTL, // 64 TOO?
		PPM_SC_FLOCK,
		PPM_SC_FORK,
		PPM_SC_GETSOCKOPT, // do we need this?
		PPM_SC_INOTIFY_INIT,
		PPM_SC_INOTIFY_INIT1,
		PPM_SC_IOCTL,
		PPM_SC_IO_URING_SETUP,
		PPM_SC_KILL,
		PPM_SC_LINK,
		PPM_SC_LINKAT,
		PPM_SC_LISTEN,
		PPM_SC_MKDIR,
		PPM_SC_MKDIRAT,
		PPM_SC_MOUNT,
		PPM_SC_OPEN,
		PPM_SC_OPEN_BY_HANDLE_AT,
		PPM_SC_OPENAT,
		PPM_SC_OPENAT2,
		PPM_SC_PIPE,
		PPM_SC_PIPE2,
		PPM_SC_PRLIMIT64,
		PPM_SC_PTRACE,
		PPM_SC_QUOTACTL,
		PPM_SC_RECVFROM,
		PPM_SC_RECVMSG,
		PPM_SC_RENAME,
		PPM_SC_RENAMEAT,
		PPM_SC_RENAMEAT2,
		PPM_SC_RMDIR,
		PPM_SC_SECCOMP,
		PPM_SC_SENDMSG,
		PPM_SC_SENDTO,
		PPM_SC_SETGID, // 32?
		PPM_SC_SETNS,
		PPM_SC_SETPGID,	  // 32?
		PPM_SC_SETRESGID, // 32?
		PPM_SC_SETRESUID, // 32?
		PPM_SC_SETRLIMIT,
		PPM_SC_SETSID,
		PPM_SC_SETUID,
		PPM_SC_SHUTDOWN,
		PPM_SC_SIGNALFD,
		PPM_SC_SIGNALFD4,
		PPM_SC_SOCKET,
		PPM_SC_SOCKETPAIR,
		PPM_SC_SYMLINK,
		PPM_SC_SYMLINKAT,
		PPM_SC_TGKILL,
		PPM_SC_TIMERFD_CREATE,
		PPM_SC_TKILL,
		PPM_SC_UMOUNT,
		PPM_SC_UMOUNT2,
		PPM_SC_UNLINK,
		PPM_SC_UNLINKAT,
		PPM_SC_UNSHARE,
		PPM_SC_USERFAULTFD,
		PPM_SC_VFORK,
	};
}

std::unordered_set<uint32_t> sinsp::io_ppm_sc_set()
{
	std::unordered_set<uint32_t> ppm_sc_set;
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_IO_READ ||
		   g_infotables.m_syscall_info_table[i].category == EC_IO_WRITE ||
		   g_infotables.m_syscall_info_table[i].category == EC_IO_OTHER ||
		   g_infotables.m_syscall_info_table[i].category == EC_FILE)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::net_ppm_sc_set()
{
	std::unordered_set<uint32_t> ppm_sc_set;
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_NET)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::proc_ppm_sc_set()
{
	std::unordered_set<uint32_t> ppm_sc_set;
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_PROCESS)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::sys_ppm_sc_set()
{
	std::unordered_set<uint32_t> ppm_sc_set;
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_SYSTEM ||
		   g_infotables.m_syscall_info_table[i].category == EC_MEMORY ||
		   g_infotables.m_syscall_info_table[i].category == EC_SIGNAL ||
		   g_infotables.m_syscall_info_table[i].category == EC_OTHER)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}